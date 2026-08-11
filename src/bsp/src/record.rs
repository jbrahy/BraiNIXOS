//! The §4.2 data-record layer: framing, padding, and sequence.
//!
//! A data record on the wire is
//!
//! ```text
//! data_record := enc_length[4] || ciphertext[packet_length] || tag[16]
//! ```
//!
//! and its plaintext is `padding_length[1] || payload || padding`.
//!
//! # The seam with the crypto
//!
//! `enc_length` is encrypted under the separate length key `K_1`, so a passive
//! observer learns record boundaries only by inference. This crate therefore
//! **cannot read it from the wire**: [`PacketLength::decode`] takes the four
//! *already decrypted* bytes. Likewise, the Poly1305 tag covers the encrypted
//! length and the ciphertext, so length forgery is an authentication failure
//! rather than a parsing problem (row R2) — and that authentication is P2-T2's,
//! not this crate's.
//!
//! What is this crate's is every bound around them, and the **order** matters:
//! §4.2 makes the `packet_length` range check normative *before any buffer is
//! touched*, and [`PacketLength::decode`] takes no buffer at all, so there is
//! no buffer it could touch first.
//!
//! # Sequence
//!
//! Sequence numbers are the per-direction AEAD nonces and are **never on the
//! wire**: the receiver derives the expected value locally, which is what
//! closes replay and reorder (§5.6c). [`SequenceCounter`] is the whole of that
//! rule plus row R5.

use crate::error::BspError;
use crate::raw::ResponseWriter;
use crate::{BSP_MAX_RECORD_PLAINTEXT, MAX_RECORD_SEQ};

/// Bytes in the encrypted length prefix (§4.2).
pub const RECORD_LENGTH_PREFIX_BYTES: usize = 4;

/// Bytes in the Poly1305 tag (§4.2).
pub const RECORD_TAG_BYTES: usize = 16;

/// Row R1 — the absolute lower bound on a decrypted `packet_length`.
pub const MIN_PACKET_LENGTH: u32 = 2;

/// Row R1 — the absolute upper bound on a decrypted `packet_length`.
///
/// Client-independent by construction: it is a `const`, so no client input
/// participates in it.
pub const MAX_PACKET_LENGTH: u32 = 35000;

/// The block the record plaintext is padded to (§4.2).
pub const RECORD_PLAINTEXT_BLOCK: usize = 8;

/// The minimum number of padding bytes (§4.2).
pub const MIN_RECORD_PADDING: usize = 4;

/// Bytes in the `padding_length` field that opens a record plaintext.
const PADDING_LENGTH_FIELD: usize = 1;

/// A validated `packet_length`: the ciphertext byte count of one data record.
///
/// Construction is the validation. Holding one of these means row R1's bound
/// passed, and it passed before any buffer was consulted, because this type's
/// constructor takes no buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketLength(u32);

impl PacketLength {
    /// Applies row R1 to the four decrypted length bytes.
    ///
    /// Enforces `INV-SERVE-002`: the decoded value is compared against two
    /// `const`s and is never used to size, grow, or index a pool. Its only
    /// later use is to *split* a buffer that already exists.
    ///
    /// Verified by: `tests::adversarial::a_packet_length_of_zero_and_of_the_maximum`
    pub fn decode(field: [u8; RECORD_LENGTH_PREFIX_BYTES]) -> Result<Self, BspError> {
        let value = u32::from_be_bytes(field);
        if value < MIN_PACKET_LENGTH {
            return Err(BspError::PacketLengthBelowMinimum);
        }
        if value > MAX_PACKET_LENGTH {
            return Err(BspError::PacketLengthAboveMaximum);
        }
        Ok(Self(value))
    }

    /// The validated ciphertext byte count.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.0
    }

    /// The record's total wire extent: prefix, ciphertext, and tag.
    pub fn record_length(self) -> Result<usize, BspError> {
        let ciphertext = usize::try_from(self.0).map_err(|_| BspError::OffsetOverflow)?;
        let with_prefix = ciphertext
            .checked_add(RECORD_LENGTH_PREFIX_BYTES)
            .ok_or(BspError::OffsetOverflow)?;
        with_prefix
            .checked_add(RECORD_TAG_BYTES)
            .ok_or(BspError::OffsetOverflow)
    }
}

/// One complete data record located at the front of a byte stream.
///
/// The parts are **borrowed**, never copied. Nothing here is authenticated:
/// [`DataRecord::ciphertext`] is exactly the bytes P2-T2 opens under `K_2`, and
/// a record that fails its tag check never reaches the message decoder
/// (row R2).
#[derive(Debug, Clone, Copy)]
pub struct DataRecord<'a> {
    /// The `packet_length` ciphertext bytes.
    pub ciphertext: &'a [u8],
    /// The 16-byte Poly1305 tag.
    pub tag: &'a [u8],
    /// Bytes this record consumed from the stream.
    pub total_length: usize,
}

/// Splits one complete data record off the front of `stream`.
///
/// `packet_length` has already passed row R1, so the only remaining question is
/// whether the record it names has fully arrived. A prefix that names more
/// bytes than arrived denies with [`BspError::RecordExceedsAvailableBytes`] —
/// it never reads short, never zero-fills, and never sizes a buffer to fit.
pub fn split_data_record(
    stream: &[u8],
    packet_length: PacketLength,
) -> Result<DataRecord<'_>, BspError> {
    let total_length = packet_length.record_length()?;
    let ciphertext_end = split_point(packet_length)?;
    let ciphertext = stream
        .get(RECORD_LENGTH_PREFIX_BYTES..ciphertext_end)
        .ok_or(BspError::RecordExceedsAvailableBytes)?;
    let tag = stream
        .get(ciphertext_end..total_length)
        .ok_or(BspError::RecordExceedsAvailableBytes)?;
    Ok(DataRecord {
        ciphertext,
        tag,
        total_length,
    })
}

/// The offset at which the ciphertext ends and the tag begins.
fn split_point(packet_length: PacketLength) -> Result<usize, BspError> {
    let ciphertext =
        usize::try_from(packet_length.value()).map_err(|_| BspError::OffsetOverflow)?;
    RECORD_LENGTH_PREFIX_BYTES
        .checked_add(ciphertext)
        .ok_or(BspError::OffsetOverflow)
}

/// Recovers the BSP message payload from a decrypted record plaintext.
///
/// The plaintext is `padding_length[1] || payload || padding`. The checks run
/// in this order, and the order is the point:
///
/// 1. the plaintext length equals the `packet_length` the prefix declared —
///    otherwise the two framings disagree and nothing below means anything;
/// 2. the plaintext is a whole number of 8-byte blocks (§4.2);
/// 3. `padding_length + 1 ≤ packet_length` — the `open_packet` containment
///    rule, which is what stops the payload length underflowing;
/// 4. the padding is at least [`MIN_RECORD_PADDING`] bytes (§4.2);
/// 5. the recovered payload fits
///    [`BSP_MAX_RECORD_PLAINTEXT`](crate::BSP_MAX_RECORD_PLAINTEXT) — row R4.
///
/// Checks 2 and 4 are this crate's fail-closed reading of a rule §4.2 states as
/// a property of the sender; see [`BspError::PaddingBelowMinimum`].
pub fn decode_record_plaintext(
    plaintext: &[u8],
    packet_length: PacketLength,
) -> Result<&[u8], BspError> {
    check_plaintext_shape(plaintext, packet_length)?;
    let padding_length = usize::from(*plaintext.first().ok_or(BspError::EmptyMessage)?);
    let payload_end = payload_end_offset(plaintext.len(), padding_length)?;
    let payload = plaintext
        .get(PADDING_LENGTH_FIELD..payload_end)
        .ok_or(BspError::PaddingLengthExceedsPacket)?;
    check_payload_bound(payload.len())?;
    Ok(payload)
}

/// Checks 1 and 2: the plaintext is the declared length and is block-aligned.
fn check_plaintext_shape(plaintext: &[u8], packet_length: PacketLength) -> Result<(), BspError> {
    let declared = usize::try_from(packet_length.value()).map_err(|_| BspError::OffsetOverflow)?;
    if plaintext.len() != declared {
        return Err(BspError::RecordPlaintextLengthMismatch);
    }
    if !plaintext.len().is_multiple_of(RECORD_PLAINTEXT_BLOCK) {
        return Err(BspError::RecordPlaintextNotBlockAligned);
    }
    Ok(())
}

/// Checks 3 and 4, and returns where the payload ends.
fn payload_end_offset(plaintext_length: usize, padding_length: usize) -> Result<usize, BspError> {
    let consumed = padding_length
        .checked_add(PADDING_LENGTH_FIELD)
        .ok_or(BspError::OffsetOverflow)?;
    if consumed > plaintext_length {
        return Err(BspError::PaddingLengthExceedsPacket);
    }
    if padding_length < MIN_RECORD_PADDING {
        return Err(BspError::PaddingBelowMinimum);
    }
    plaintext_length
        .checked_sub(padding_length)
        .ok_or(BspError::PaddingLengthExceedsPacket)
}

/// Check 5 — row R4.
fn check_payload_bound(payload_length: usize) -> Result<(), BspError> {
    if payload_length > BSP_MAX_RECORD_PLAINTEXT {
        return Err(BspError::PayloadExceedsRecordPlaintext);
    }
    Ok(())
}

/// Frames a BSP message payload as a record plaintext, ready to be sealed.
///
/// Writes `padding_length[1] || payload || padding` into a caller-supplied
/// buffer and returns the byte count, which is always a multiple of
/// [`RECORD_PLAINTEXT_BLOCK`] with at least [`MIN_RECORD_PADDING`] padding
/// bytes. The padding bytes are written as zero: this crate holds no CSPRNG,
/// and §4.2 requires padding to exist, not to be unpredictable — the length is
/// already hidden by `K_1`.
pub fn encode_record_plaintext(payload: &[u8], out: &mut [u8]) -> Result<usize, BspError> {
    check_payload_bound(payload.len())?;
    let padding_length = padding_for(payload.len())?;
    let mut writer = ResponseWriter::new(out);
    writer.push_u8(u8::try_from(padding_length).map_err(|_| BspError::OffsetOverflow)?)?;
    writer.push_bytes(payload)?;
    write_padding(&mut writer, padding_length)?;
    Ok(writer.finish())
}

/// The smallest padding that reaches [`MIN_RECORD_PADDING`] and lands the whole
/// plaintext on a [`RECORD_PLAINTEXT_BLOCK`] boundary.
fn padding_for(payload_length: usize) -> Result<usize, BspError> {
    let minimum = payload_length
        .checked_add(PADDING_LENGTH_FIELD)
        .ok_or(BspError::OffsetOverflow)?
        .checked_add(MIN_RECORD_PADDING)
        .ok_or(BspError::OffsetOverflow)?;
    let blocks = minimum
        .checked_add(RECORD_PLAINTEXT_BLOCK)
        .ok_or(BspError::OffsetOverflow)?
        .checked_sub(1)
        .ok_or(BspError::OffsetOverflow)?
        / RECORD_PLAINTEXT_BLOCK;
    padding_from_block_count(blocks, payload_length)
}

/// Turns a block count back into the padding byte count it implies.
fn padding_from_block_count(blocks: usize, payload_length: usize) -> Result<usize, BspError> {
    let total = blocks
        .checked_mul(RECORD_PLAINTEXT_BLOCK)
        .ok_or(BspError::OffsetOverflow)?;
    total
        .checked_sub(payload_length)
        .ok_or(BspError::OffsetOverflow)?
        .checked_sub(PADDING_LENGTH_FIELD)
        .ok_or(BspError::OffsetOverflow)
}

/// Appends `count` zero padding bytes, one at a time and bounds-checked.
fn write_padding(writer: &mut ResponseWriter<'_>, count: usize) -> Result<(), BspError> {
    let mut written = 0usize;
    while written < count {
        writer.push_u8(0)?;
        written = written.checked_add(1).ok_or(BspError::OffsetOverflow)?;
    }
    Ok(())
}

/// A per-direction record sequence, which is also the AEAD nonce (§4.2).
///
/// Each direction starts at `0` at its first data record and increments by
/// exactly `1` per record. The value is **never on the wire**; the receiver
/// derives it locally, so a replayed or reordered record fails to authenticate
/// at the expected sequence and drops (row R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SequenceCounter {
    value: u32,
}

impl SequenceCounter {
    /// A counter at sequence `0` — the state of a direction that has sent or
    /// received no data record.
    #[must_use]
    pub const fn new() -> Self {
        Self { value: 0 }
    }

    /// A counter at a known position.
    ///
    /// Exists so the boundary of [`SequenceCounter::advance`] is reachable
    /// without 2^32 advances — a guard nobody can test at its boundary is a
    /// guard nobody has tested. It is safe to expose because this type carries
    /// no authority: it holds a counter, not a key, and every position is
    /// equally guarded.
    #[must_use]
    pub const fn at(value: u32) -> Self {
        Self { value }
    }

    /// The current sequence.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }

    /// The 64-bit big-endian AEAD nonce whose low 32 bits are the sequence.
    ///
    /// The high 32 bits are zero and stay zero: the counter cannot reach a
    /// value that would set them, because [`SequenceCounter::advance`] denies
    /// first.
    #[must_use]
    pub const fn nonce(self) -> [u8; 8] {
        (self.value as u64).to_be_bytes()
    }

    /// Advances by exactly one, or denies — row R5.
    ///
    /// **The sequence never wraps.** A counter already at
    /// [`MAX_RECORD_SEQ`](crate::MAX_RECORD_SEQ) denies with
    /// [`BspError::SequenceExhausted`] and the session is torn down (§9.4),
    /// rather than reusing a nonce — which would be catastrophic for a stream
    /// cipher, not merely a protocol fault.
    ///
    /// **Spec reading.** §4.2 says the session is torn down "on reaching
    /// `MAX_RECORD_SEQ`" while row R5 says the fault is a sequence that "would
    /// exceed" it. This crate takes the reading that satisfies both: the record
    /// at `MAX_RECORD_SEQ` is legal, and the advance past it is the denial.
    ///
    /// Verified by: `tests::adversarial::a_sequence_counter_never_wraps`
    ///
    /// The comparison is `>=` and not `==`, and the lint that objects is
    /// silenced rather than obeyed: §8 states that the *values* in its table
    /// are tunable and only the presence of a hard bound is not. `>=` stays
    /// correct if `MAX_RECORD_SEQ` is ever tuned below `u32::MAX`; `==` would
    /// silently stop guarding at the moment it was.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn advance(&mut self) -> Result<(), BspError> {
        if self.value >= MAX_RECORD_SEQ {
            return Err(BspError::SequenceExhausted);
        }
        self.value = self
            .value
            .checked_add(1)
            .ok_or(BspError::SequenceExhausted)?;
        Ok(())
    }

    /// Whether the next [`SequenceCounter::advance`] will deny.
    ///
    /// Lets `servd` tear down at the boundary rather than discovering it when a
    /// record is already half-processed.
    ///
    /// `>=` for the reason [`SequenceCounter::advance`] gives.
    #[allow(clippy::absurd_extreme_comparisons)]
    #[must_use]
    pub const fn is_exhausted(self) -> bool {
        self.value >= MAX_RECORD_SEQ
    }
}
