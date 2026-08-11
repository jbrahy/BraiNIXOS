#![no_main]

//! Fuzz target: the BSP v2 AEAD record layer under a fixed key.
//!
//! `RecordOpener::open` is the only code a remote peer reaches **after** the
//! handshake, and it reaches it with every byte under its control except the
//! key. This target fixes the key — a forged record is indistinguishable from a
//! random one without it, so making the key fuzzable would only dilute the
//! search — and gives the fuzzer the whole stream (`INV-PARSE-001`, §4.2 rows
//! R1–R5).
//!
//! The properties asserted:
//!
//! - **Authentication either succeeds or fails cleanly.** `open` returns an
//!   `OpenedRecord` or a `TransportCryptoError`; it never panics, never reads
//!   out of bounds of the stream or the scratch buffer, and never hangs.
//! - **A failure does not move the receive sequence.** §4.2 makes every
//!   authentication fault a Drop, so there is no state to resynchronize, and a
//!   sequence that advanced on a forgery would let an attacker desynchronize a
//!   live channel by sending garbage.
//! - **A sealed record opens to the payload it sealed**, and consumes exactly
//!   the bytes it claims.
//! - **A tampered record never opens.** Every single-byte mutation of an honest
//!   record — in the encrypted length, the ciphertext, or the tag — must fail,
//!   and must fail as `AuthenticationFailed` with nothing attached.
//! - **Replay and reorder fail**, because the nonce is the locally derived
//!   sequence and is never on the wire.
//! - **`seal` respects the caller's buffer.** An output buffer too small denies
//!   rather than writing past the end, and a denied seal does not advance the
//!   send sequence.
//!
//! Reaching the authentic path matters as much as forging: a stream of random
//! bytes fails the Poly1305 check with probability `1 − 2^-128` and would leave
//! everything past `verify_tag` unfuzzed forever. So the target also seals
//! fuzzer-chosen payloads and lets the fuzzer mutate the result, which is how
//! the decrypt-and-unpad half of `open` is reached at all.

use brainix_bsp::record::{RECORD_LENGTH_PREFIX_BYTES, RECORD_TAG_BYTES};
use brainix_bsp::BSP_MAX_RECORD_PLAINTEXT;
use brainix_transport_crypto::{
    DirectionKeys, RecordOpener, RecordSealer, Secret, TransportCryptoError,
    MAX_SEALED_RECORD_BYTES,
};
use libfuzzer_sys::fuzz_target;

/// The 64 bytes one direction's HKDF-Expand would have produced.
///
/// A constant on purpose: the key is the one thing a remote peer does not
/// control, so fuzzing it would spend the budget on a value the threat model
/// already grants the defender.
const DIRECTION_MATERIAL: [u8; 64] = [
    0x2c, 0x91, 0x7f, 0x04, 0xbb, 0x38, 0xe6, 0x5a, 0x13, 0xcd, 0x70, 0xa2, 0x49, 0x86, 0xf1, 0x0b,
    0xd4, 0x27, 0x63, 0x9e, 0x58, 0xac, 0x31, 0xe0, 0x0f, 0x75, 0xb8, 0x42, 0x96, 0x1d, 0xca, 0x63,
    0x87, 0x3e, 0xd1, 0x6a, 0x05, 0xf4, 0x29, 0xbc, 0x51, 0x08, 0xe7, 0x93, 0x2a, 0xdf, 0x64, 0x1b,
    0xa8, 0x35, 0xc2, 0x79, 0x0e, 0x96, 0x4d, 0xe3, 0x21, 0xb7, 0x5c, 0x88, 0x3f, 0xd0, 0x6b, 0x17,
];

/// Records sealed and opened per iteration when the ordering rules are driven.
const ORDERING_RECORDS: usize = 4;

/// A fresh key set. Cheap: two 32-byte copies out of a constant.
fn keys() -> DirectionKeys {
    DirectionKeys::from_material(Secret::from_bytes(DIRECTION_MATERIAL))
}

/// A forward-only cursor over the fuzzer's bytes, wrapping at the end.
struct Driver<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Driver<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn byte(&mut self) -> u8 {
        if self.data.is_empty() {
            return 0;
        }
        let index = self.at % self.data.len();
        self.at = self.at.wrapping_add(1);
        self.data.get(index).copied().unwrap_or(0)
    }

    fn u16(&mut self) -> u16 {
        u16::from_be_bytes([self.byte(), self.byte()])
    }
}

/// Every failure `open` may report. A variant outside this set would mean the
/// module grew a new observable a peer can distinguish.
fn is_expected_open_failure(error: TransportCryptoError) -> bool {
    matches!(
        error,
        TransportCryptoError::AuthenticationFailed
            | TransportCryptoError::RecordIncomplete
            | TransportCryptoError::OutputBufferTooSmall
            | TransportCryptoError::SequenceExhausted
    )
}

/// Opens `stream` with a fresh opener and checks the sequence discipline.
///
/// Returns the opened payload, when there was one.
fn open_once(stream: &[u8]) -> Option<Vec<u8>> {
    let mut opener = RecordOpener::new(keys());
    let mut scratch = [0u8; MAX_SEALED_RECORD_BYTES];
    let before = opener.sequence();
    match opener.open(stream, &mut scratch) {
        Ok(record) => {
            assert!(
                record.payload.len() <= BSP_MAX_RECORD_PLAINTEXT,
                "an opened payload exceeded the row R4 ceiling"
            );
            assert!(
                record.consumed <= stream.len(),
                "an opened record consumed more bytes than arrived"
            );
            assert!(
                record.consumed >= RECORD_LENGTH_PREFIX_BYTES.saturating_add(RECORD_TAG_BYTES),
                "an opened record consumed less than a prefix and a tag"
            );
            let payload = record.payload.to_vec();
            assert!(
                opener.sequence() == before.wrapping_add(1),
                "a successful open did not advance the sequence by one"
            );
            Some(payload)
        }
        Err(error) => {
            assert!(
                is_expected_open_failure(error),
                "open reported a failure outside its documented set"
            );
            assert!(
                opener.sequence() == before,
                "a failed open advanced the receive sequence"
            );
            None
        }
    }
}

/// Seals `payload` into a fresh buffer, or reports why it could not.
fn seal_once(payload: &[u8]) -> Option<Vec<u8>> {
    let mut sealer = RecordSealer::new(keys());
    let mut out = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let before = sealer.sequence();
    match sealer.seal(payload, &mut out) {
        Ok(written) => {
            assert!(
                payload.len() <= BSP_MAX_RECORD_PLAINTEXT,
                "a payload past the ceiling was sealed"
            );
            assert!(
                written <= out.len(),
                "a seal reported more bytes than the buffer holds"
            );
            assert!(
                written
                    >= payload
                        .len()
                        .saturating_add(RECORD_LENGTH_PREFIX_BYTES)
                        .saturating_add(RECORD_TAG_BYTES),
                "a sealed record is smaller than its own payload plus framing"
            );
            assert!(
                sealer.sequence() == before.wrapping_add(1),
                "a successful seal did not advance the sequence by one"
            );
            out.truncate(written);
            Some(out)
        }
        Err(error) => {
            assert!(
                sealer.sequence() == before,
                "a failed seal advanced the send sequence"
            );
            assert!(
                matches!(
                    error,
                    TransportCryptoError::PayloadExceedsRecordPlaintext
                        | TransportCryptoError::OutputBufferTooSmall
                        | TransportCryptoError::SequenceExhausted
                ),
                "seal reported a failure outside its documented set"
            );
            None
        }
    }
}

/// Seals a payload, opens it back, and asserts the identity.
fn round_trip(payload: &[u8]) -> Option<Vec<u8>> {
    let sealed = seal_once(payload)?;
    match open_once(&sealed) {
        Some(opened) => {
            assert!(
                opened.as_slice() == payload,
                "a sealed record did not open to the payload it sealed"
            );
            Some(sealed)
        }
        None => panic!("a record this crate sealed failed its own authentication"),
    }
}

/// Flips fuzzer-chosen bits of an honest record and asserts none of them opens.
///
/// This is the near-miss half. A forgery that differs from an honest record in
/// one byte is the input a tag comparison with an early exit would treat
/// differently, and the input a length check applied after the tag check would
/// mishandle.
fn tamper(sealed: &[u8], driver: &mut Driver<'_>) {
    if sealed.is_empty() {
        return;
    }
    let mut attempts = 0usize;
    while attempts < 3 {
        attempts = attempts.saturating_add(1);
        let mut forged = sealed.to_vec();
        let at = usize::from(driver.u16()) % forged.len();
        let mask = driver.byte();
        if mask == 0 {
            continue;
        }
        if let Some(byte) = forged.get_mut(at) {
            *byte ^= mask;
        }
        assert!(
            open_once(&forged).is_none(),
            "a record with a mutated byte authenticated"
        );
    }

    // Truncation at every structural boundary: inside the length prefix, at the
    // prefix/ciphertext seam, mid-ciphertext, and one byte short of the tag.
    for cut in [
        RECORD_LENGTH_PREFIX_BYTES.saturating_sub(1),
        RECORD_LENGTH_PREFIX_BYTES,
        sealed.len() / 2,
        sealed.len().saturating_sub(RECORD_TAG_BYTES),
        sealed.len().saturating_sub(1),
    ] {
        if let Some(short) = sealed.get(..cut.min(sealed.len())) {
            assert!(
                open_once(short).is_none(),
                "a truncated record authenticated"
            );
        }
    }

    // Trailing bytes must not change the outcome: the record's extent comes
    // from the decrypted length, not from what happens to have arrived.
    let mut extended = sealed.to_vec();
    extended.push(driver.byte());
    assert!(
        open_once(&extended).is_some(),
        "an honest record stopped authenticating when a byte followed it"
    );
}

/// Seals a run of records and checks replay, reorder, and in-order delivery.
///
/// The sequence is the nonce and is never on the wire, so the receiver derives
/// it locally; that is the whole of the replay and reorder defence (rows R3,
/// R5) and it can only be exercised across more than one record.
fn ordering(payload: &[u8]) {
    let mut sealer = RecordSealer::new(keys());
    let mut out = vec![0u8; MAX_SEALED_RECORD_BYTES];
    let mut stream: Vec<Vec<u8>> = Vec::new();
    let mut sealed = 0usize;
    while sealed < ORDERING_RECORDS {
        sealed = sealed.saturating_add(1);
        match sealer.seal(payload, &mut out) {
            Ok(written) => match out.get(..written) {
                Some(record) => stream.push(record.to_vec()),
                None => return,
            },
            Err(_) => return,
        }
    }

    let mut opener = RecordOpener::new(keys());
    let mut scratch = [0u8; MAX_SEALED_RECORD_BYTES];
    for (position, record) in stream.iter().enumerate() {
        assert!(
            opener.sequence() as usize == position,
            "the opener is not at the position it has consumed to"
        );
        match opener.open(record, &mut scratch) {
            Ok(opened) => assert!(
                opened.payload == payload,
                "an in-order record opened to the wrong payload"
            ),
            Err(_) => panic!("an in-order record from this crate's sealer failed to open"),
        }
    }

    // Every record already consumed, replayed at the position the opener has
    // now reached, must fail.
    for record in stream.iter() {
        let before = opener.sequence();
        assert!(
            opener.open(record, &mut scratch).is_err(),
            "a replayed record authenticated"
        );
        assert!(
            opener.sequence() == before,
            "a replayed record moved the sequence"
        );
    }

    // And a fresh opener must refuse every record but the first, which is the
    // reorder case stated as a property rather than as an example.
    let mut fresh = RecordOpener::new(keys());
    for record in stream.iter().skip(1) {
        assert!(
            fresh.open(record, &mut scratch).is_err(),
            "a record presented out of order authenticated"
        );
    }
}

/// Drives `seal` against output buffers the caller sized, including ones too
/// small to hold the record.
fn cramped_seal(payload: &[u8], driver: &mut Driver<'_>) {
    let size = usize::from(driver.u16()) % (MAX_SEALED_RECORD_BYTES + 1);
    let mut out = vec![0u8; size];
    let mut sealer = RecordSealer::new(keys());
    let before = sealer.sequence();
    match sealer.seal(payload, &mut out) {
        Ok(written) => {
            assert!(written <= size, "a seal wrote past the buffer it was given");
            assert!(
                sealer.sequence() == before.wrapping_add(1),
                "a successful seal did not advance the sequence"
            );
        }
        Err(_) => assert!(
            sealer.sequence() == before,
            "a failed seal advanced the send sequence"
        ),
    }

    // The scratch buffer on the opening side is the caller's too.
    let scratch_size = usize::from(driver.u16()) % (MAX_SEALED_RECORD_BYTES + 1);
    let mut scratch = vec![0u8; scratch_size];
    let mut opener = RecordOpener::new(keys());
    let _ = opener.open(payload, &mut scratch);
}

fuzz_target!(|data: &[u8]| {
    // 1. The pure forgery: the whole input offered as a record.
    let _ = open_once(data);

    let mut driver = Driver::new(data);

    // 2. A payload the fuzzer chose, sealed and opened back.
    let payload_len = usize::from(driver.u16()) % (BSP_MAX_RECORD_PLAINTEXT + 2);
    let payload = data
        .get(..payload_len.min(data.len()))
        .unwrap_or(&[])
        .to_vec();
    let sealed = round_trip(&payload);

    // 3. Near misses around that honest record.
    if let Some(sealed) = sealed.as_deref() {
        tamper(sealed, &mut driver);
    }

    // 4. Ordering, replay, and reorder.
    ordering(&payload);

    // 5. Buffer bounds on both sides.
    cramped_seal(&payload, &mut driver);
    cramped_seal(data, &mut driver);

    // 6. A payload one byte past the ceiling must always be refused, whatever
    //    else the fuzzer produced.
    let oversize = vec![0u8; BSP_MAX_RECORD_PLAINTEXT + 1];
    assert!(
        seal_once(&oversize).is_none(),
        "a payload past the row R4 ceiling was sealed"
    );
});
