//! §4.2's data-record layer: `chacha20-poly1305@openssh.com` with the sequence
//! number as the nonce.
//!
//! ```text
//! data_record := enc_length[4] || ciphertext[packet_length] || tag[16]
//! ```
//!
//! The construction is retained verbatim from v1, which took it verbatim from
//! `src/kernel/src/ssh/transport.rs`. §4.2 keeps it **for its properties, not
//! for interoperability** — there is none:
//!
//! - the length field is encrypted under a separate key `K_1`, so a passive
//!   observer learns record boundaries only by inference;
//! - the Poly1305 tag covers the encrypted length *and* the ciphertext, so
//!   length forgery is an authentication failure rather than a parsing problem;
//! - the tag comparison is constant-time.
//!
//! One function from v1 does **not** survive the move, exactly as §4.2 says:
//! `derive_direction_keys` was the SSH exchange-hash KDF and there is no SSH
//! exchange hash in v2. Directional keys come from HKDF-Expand ([`crate::schedule`]).
//!
//! # Structure is P2-T3's; this module never re-parses
//!
//! [`brainix_bsp::PacketLength::decode`] applies row R1, `split_data_record`
//! splits the ciphertext from the tag, `decode_record_plaintext` applies the
//! padding rules, and `encode_record_plaintext` produces a plaintext that
//! satisfies them. This module supplies exactly what the decoder cannot: the
//! key, the keystream, and the tag.
//!
//! # Zero allocation, and no large scratch either
//!
//! Sealing writes the plaintext directly into the caller's output buffer and
//! encrypts it in place; opening decrypts into a caller-supplied scratch
//! buffer. Neither path holds a multi-kilobyte array of its own, so neither
//! puts one on a kernel stack.

use brainix_bsp::record::{
    decode_record_plaintext, encode_record_plaintext, split_data_record,
    RECORD_LENGTH_PREFIX_BYTES, RECORD_TAG_BYTES,
};
use brainix_bsp::{PacketLength, SequenceCounter, BSP_MAX_RECORD_PLAINTEXT, LEN_DIR_KEYS};
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20Legacy;

use crate::error::TransportCryptoError;
use crate::poly1305::{Poly1305, POLY1305_KEY_BYTES, POLY1305_TAG_BYTES};
use crate::secret::{constant_time_eq, Secret};

/// Bytes in one ChaCha20 key.
pub const LEN_CIPHER_KEY: usize = 32;

/// The largest record plaintext this crate will seal or open, in bytes.
///
/// **This const resolves an inconsistency in §4.2, and the resolution is
/// fail-closed.** §4.2 requires `BSP_MAX_RECORD_PLAINTEXT ≤` the internal
/// plaintext buffer and says that buffer is 4096 today — but the record
/// plaintext is `padding_length[1] || payload || padding`, so a
/// `BSP_MAX_RECORD_PLAINTEXT`-byte payload does not fit in 4096 bytes once
/// framed. The two statements cannot both hold.
///
/// The reading taken: the buffer is sized to the **framed** form, and the
/// figure is derived rather than chosen —
/// `BSP_MAX_RECORD_PLAINTEXT + 1 + 255`, where 255 is the largest
/// `padding_length` a one-byte field can express. Any `packet_length` above it
/// necessarily decodes to a payload above `BSP_MAX_RECORD_PLAINTEXT`, so
/// rejecting it early is exactly row R4 applied sooner, never a bound §4.2
/// does not have. §4.2 requires this buffer to be "a shared named `const`", and
/// this is it.
pub const RECORD_PLAINTEXT_CAPACITY: usize = BSP_MAX_RECORD_PLAINTEXT + 1 + 255;

/// The output buffer size that always suffices for [`RecordSealer::seal`], and
/// the scratch size that always suffices for [`RecordOpener::open`].
pub const MAX_SEALED_RECORD_BYTES: usize =
    RECORD_LENGTH_PREFIX_BYTES + RECORD_PLAINTEXT_CAPACITY + RECORD_TAG_BYTES;

/// One direction's keys: `K_2` (payload) and `K_1` (length).
///
/// §5.4: "Each 64-byte directional output splits exactly as the record layer
/// expects: bytes `0..32` are the payload key `K_2`, bytes `32..64` are the
/// length key `K_1`."
pub struct DirectionKeys {
    /// `K_2` — encrypts the record plaintext and keys the Poly1305 one-time MAC.
    payload_key: Secret<LEN_CIPHER_KEY>,
    /// `K_1` — encrypts the four-byte length prefix, and nothing else.
    length_key: Secret<LEN_CIPHER_KEY>,
}

impl DirectionKeys {
    /// Splits one 64-byte HKDF-Expand output into the two record keys.
    ///
    /// The 64-byte input is consumed by value so the caller cannot retain it,
    /// and it is zeroized when this function's binding drops.
    #[must_use]
    pub fn from_material(material: Secret<LEN_DIR_KEYS>) -> Self {
        let mut payload_key = Secret::<LEN_CIPHER_KEY>::zero();
        let mut length_key = Secret::<LEN_CIPHER_KEY>::zero();
        copy_half(payload_key.expose_mut(), material.expose(), 0);
        copy_half(length_key.expose_mut(), material.expose(), LEN_CIPHER_KEY);
        Self {
            payload_key,
            length_key,
        }
    }

    /// Destroys both keys — §9.4's teardown obligation, callable before the
    /// value itself goes out of scope.
    pub fn zeroize(&mut self) {
        self.payload_key.zeroize();
        self.length_key.zeroize();
    }
}

/// Copies 32 bytes out of the 64-byte material at `offset`.
fn copy_half(destination: &mut [u8; LEN_CIPHER_KEY], material: &[u8; LEN_DIR_KEYS], offset: usize) {
    let end = offset.saturating_add(LEN_CIPHER_KEY);
    if let Some(source) = material.get(offset..end) {
        destination.copy_from_slice(source);
    }
}

/// The sending half of one direction: keys plus the send sequence.
///
/// The sequence is the nonce and is **never on the wire** (§4.2). It starts at
/// `0` at the first data record and increments by exactly one per record.
pub struct RecordSealer {
    keys: DirectionKeys,
    sequence: SequenceCounter,
}

/// The receiving half of one direction: keys plus the expected receive
/// sequence.
///
/// The receiver derives the expected sequence locally, which is what closes
/// replay and reorder: a record presented at any other position fails to
/// authenticate (row R3) and is indistinguishable from a forgery (row R2).
pub struct RecordOpener {
    keys: DirectionKeys,
    sequence: SequenceCounter,
}

/// One successfully opened record.
///
/// `Debug` prints the decrypted payload, which is decoded protocol data and
/// never key material — the same exposure P2-T3's decoded message types carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenedRecord<'a> {
    /// The BSP message payload, borrowed from the caller's scratch buffer.
    pub payload: &'a [u8],
    /// Bytes this record consumed from the stream.
    pub consumed: usize,
}

impl RecordSealer {
    /// A sealer at sequence `0`.
    #[must_use]
    pub fn new(keys: DirectionKeys) -> Self {
        Self {
            keys,
            sequence: SequenceCounter::new(),
        }
    }

    /// The sequence the next record will be sealed at.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence.value()
    }

    /// Seals `payload` as one data record and advances the sequence.
    ///
    /// The plaintext is framed by [`encode_record_plaintext`], which is what
    /// satisfies §4.2's two sender obligations — `1 + payload + padding` is a
    /// multiple of 8, and there are at least 4 padding bytes — the same rules
    /// P2-T3 enforces on receipt.
    ///
    /// Returns the number of bytes written to `out`.
    pub fn seal(&mut self, payload: &[u8], out: &mut [u8]) -> Result<usize, TransportCryptoError> {
        if payload.len() > BSP_MAX_RECORD_PLAINTEXT {
            return Err(TransportCryptoError::PayloadExceedsRecordPlaintext);
        }
        if self.sequence.is_exhausted() {
            // COVERAGE-EXEMPT: same as the opener's: 2^32 records on a single channel is not reachable in a test, and the guard is what prevents nonce reuse.
            return Err(TransportCryptoError::SequenceExhausted);
        }
        let plaintext_length = frame_plaintext(payload, out)?;
        let total = seal_in_place(&self.keys, self.sequence.nonce(), plaintext_length, out)?;
        self.sequence
            .advance()
            .map_err(|_| TransportCryptoError::SequenceExhausted)?;
        Ok(total)
    }

    /// Destroys the direction's keys (§9.4).
    pub fn zeroize(&mut self) {
        self.keys.zeroize();
    }
}

/// Writes `padding_length || payload || padding` into `out[4..]`, reserving the
/// tag's 16 bytes, and returns the framed plaintext length.
fn frame_plaintext(payload: &[u8], out: &mut [u8]) -> Result<usize, TransportCryptoError> {
    let tag_start_limit = out
        .len()
        .checked_sub(RECORD_TAG_BYTES)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    let body = out
        .get_mut(RECORD_LENGTH_PREFIX_BYTES..tag_start_limit)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    encode_record_plaintext(payload, body).map_err(|_| TransportCryptoError::OutputBufferTooSmall)
}

/// Encrypts the length under `K_1`, the plaintext under `K_2` from block 1, and
/// appends the Poly1305 tag over `enc_length || ciphertext`.
fn seal_in_place(
    keys: &DirectionKeys,
    nonce: [u8; 8],
    plaintext_length: usize,
    out: &mut [u8],
) -> Result<usize, TransportCryptoError> {
    write_encrypted_length(keys, nonce, plaintext_length, out)?;
    let mac_key = encrypt_body(keys, nonce, plaintext_length, out)?;
    append_tag(&mac_key, plaintext_length, out)
}

/// Encrypts the four-byte `packet_length` prefix under `K_1`.
fn write_encrypted_length(
    keys: &DirectionKeys,
    nonce: [u8; 8],
    plaintext_length: usize,
    out: &mut [u8],
) -> Result<(), TransportCryptoError> {
    let declared =
        u32::try_from(plaintext_length).map_err(|_| TransportCryptoError::OutputBufferTooSmall)?;
    let prefix = out
        .get_mut(..RECORD_LENGTH_PREFIX_BYTES)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    prefix.copy_from_slice(&declared.to_be_bytes());
    length_cipher(keys, nonce).apply_keystream(prefix);
    Ok(())
}

/// Encrypts the record body under `K_2` starting at keystream block 1, and
/// returns the one-time Poly1305 key taken from block 0.
fn encrypt_body(
    keys: &DirectionKeys,
    nonce: [u8; 8],
    plaintext_length: usize,
    out: &mut [u8],
) -> Result<Secret<POLY1305_KEY_BYTES>, TransportCryptoError> {
    let mut cipher = payload_cipher(keys, nonce);
    let mac_key = take_mac_key(&mut cipher);
    let end = RECORD_LENGTH_PREFIX_BYTES.saturating_add(plaintext_length);
    let body = out
        .get_mut(RECORD_LENGTH_PREFIX_BYTES..end)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    cipher.apply_keystream(body);
    Ok(mac_key)
}

/// Appends the tag over `enc_length || ciphertext` and returns the record's
/// total length.
fn append_tag(
    mac_key: &Secret<POLY1305_KEY_BYTES>,
    plaintext_length: usize,
    out: &mut [u8],
) -> Result<usize, TransportCryptoError> {
    let authenticated_end = RECORD_LENGTH_PREFIX_BYTES.saturating_add(plaintext_length);
    let total = authenticated_end.saturating_add(RECORD_TAG_BYTES);
    let authenticated = out
        .get(..authenticated_end)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    let tag = compute_tag(mac_key, authenticated);
    let destination = out
        .get_mut(authenticated_end..total)
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    destination.copy_from_slice(&tag);
    Ok(total)
}

impl RecordOpener {
    /// An opener expecting sequence `0`.
    #[must_use]
    pub fn new(keys: DirectionKeys) -> Self {
        Self {
            keys,
            sequence: SequenceCounter::new(),
        }
    }

    /// The sequence the next record is expected at.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence.value()
    }

    /// Opens one data record from the front of `stream`, decrypting into
    /// `scratch`, and advances the expected sequence on success.
    ///
    /// Every failure other than [`TransportCryptoError::RecordIncomplete`] and
    /// [`TransportCryptoError::OutputBufferTooSmall`] is
    /// [`TransportCryptoError::AuthenticationFailed`] — a forged tag, a
    /// replayed or reordered record, a `packet_length` out of range, and a
    /// padding field the sender could not have produced are one variant with no
    /// payload, so no caller can tell them apart or log which occurred.
    ///
    /// The sequence is **not** advanced on failure: §12's action for every one
    /// of those rows is Drop, so there is no state to resynchronize.
    pub fn open<'a>(
        &mut self,
        stream: &[u8],
        scratch: &'a mut [u8],
    ) -> Result<OpenedRecord<'a>, TransportCryptoError> {
        if self.sequence.is_exhausted() {
            // COVERAGE-EXEMPT: exhausting a u32 sequence needs 2^32 records sealed on one channel, which no test can drive in bounded time. The guard is what stops nonce reuse after wrap, so it stays.
            return Err(TransportCryptoError::SequenceExhausted);
        }
        let nonce = self.sequence.nonce();
        let packet_length = self.decrypt_length(stream, nonce)?;
        let opened = open_body(&self.keys, nonce, stream, packet_length, scratch)?;
        self.sequence
            .advance()
            .map_err(|_| TransportCryptoError::SequenceExhausted)?;
        Ok(opened)
    }

    /// Destroys the direction's keys (§9.4).
    pub fn zeroize(&mut self) {
        self.keys.zeroize();
    }

    /// Decrypts the four-byte prefix under `K_1` and applies row R1 and the
    /// [`RECORD_PLAINTEXT_CAPACITY`] ceiling.
    fn decrypt_length(
        &self,
        stream: &[u8],
        nonce: [u8; 8],
    ) -> Result<PacketLength, TransportCryptoError> {
        let mut field = [0u8; RECORD_LENGTH_PREFIX_BYTES];
        let prefix = stream
            .get(..RECORD_LENGTH_PREFIX_BYTES)
            .ok_or(TransportCryptoError::RecordIncomplete)?;
        field.copy_from_slice(prefix);
        length_cipher(&self.keys, nonce).apply_keystream(&mut field);
        let packet_length =
            PacketLength::decode(field).map_err(|_| TransportCryptoError::AuthenticationFailed)?;
        check_capacity(packet_length)?;
        Ok(packet_length)
    }
}

/// Rejects a `packet_length` that could not decode to a payload within
/// [`BSP_MAX_RECORD_PLAINTEXT`] — row R4, applied before any buffer is touched.
fn check_capacity(packet_length: PacketLength) -> Result<(), TransportCryptoError> {
    let declared = usize::try_from(packet_length.value())
        .map_err(|_| TransportCryptoError::AuthenticationFailed)?;
    if declared > RECORD_PLAINTEXT_CAPACITY {
        return Err(TransportCryptoError::AuthenticationFailed);
    }
    Ok(())
}

/// Verifies the tag, then decrypts the body into `scratch` and recovers the
/// payload.
fn open_body<'a>(
    keys: &DirectionKeys,
    nonce: [u8; 8],
    stream: &[u8],
    packet_length: PacketLength,
    scratch: &'a mut [u8],
) -> Result<OpenedRecord<'a>, TransportCryptoError> {
    let record = split_data_record(stream, packet_length)
        .map_err(|_| TransportCryptoError::RecordIncomplete)?;
    let mut cipher = payload_cipher(keys, nonce);
    let mac_key = take_mac_key(&mut cipher);
    verify_tag(&mac_key, stream, &record)?;
    let plaintext = decrypt_into(&mut cipher, record.ciphertext, scratch)?;
    let payload = decode_record_plaintext(plaintext, packet_length)
        .map_err(|_| TransportCryptoError::AuthenticationFailed)?;
    Ok(OpenedRecord {
        payload,
        consumed: record.total_length,
    })
}

/// Row R2 — the constant-time tag comparison.
///
/// The comparison is [`crate::secret::constant_time_eq`], which is
/// `subtle::ConstantTimeEq`; a mismatch is
/// [`TransportCryptoError::AuthenticationFailed`] with nothing attached.
fn verify_tag(
    mac_key: &Secret<POLY1305_KEY_BYTES>,
    stream: &[u8],
    record: &brainix_bsp::DataRecord<'_>,
) -> Result<(), TransportCryptoError> {
    let authenticated_end = RECORD_LENGTH_PREFIX_BYTES.saturating_add(record.ciphertext.len());
    let authenticated = stream
        .get(..authenticated_end)
        .ok_or(TransportCryptoError::AuthenticationFailed)?;
    let computed = compute_tag(mac_key, authenticated);
    let mut received = [0u8; POLY1305_TAG_BYTES];
    if record.tag.len() != POLY1305_TAG_BYTES {
        // COVERAGE-EXEMPT: the BSP decoder that produced this DataRecord already fixed the tag at POLY1305_TAG_BYTES, so the length check cannot fail here. Kept so this function is total for any DataRecord, including one a future decoder builds differently.
        return Err(TransportCryptoError::AuthenticationFailed);
    }
    received.copy_from_slice(record.tag);
    if !constant_time_eq(&computed, &received) {
        return Err(TransportCryptoError::AuthenticationFailed);
    }
    Ok(())
}

/// Decrypts `ciphertext` into `scratch` and returns the plaintext slice.
fn decrypt_into<'a>(
    cipher: &mut ChaCha20Legacy,
    ciphertext: &[u8],
    scratch: &'a mut [u8],
) -> Result<&'a [u8], TransportCryptoError> {
    let plaintext = scratch
        .get_mut(..ciphertext.len())
        .ok_or(TransportCryptoError::OutputBufferTooSmall)?;
    plaintext.copy_from_slice(ciphertext);
    cipher.apply_keystream(plaintext);
    Ok(plaintext)
}

/// The Poly1305 tag over the already-encrypted `enc_length || ciphertext`.
fn compute_tag(
    mac_key: &Secret<POLY1305_KEY_BYTES>,
    authenticated: &[u8],
) -> [u8; POLY1305_TAG_BYTES] {
    let mut state = Poly1305::new(mac_key.expose());
    state.update(authenticated);
    state.finalize()
}

/// The one-time Poly1305 key: keystream block 0 under `K_2`.
///
/// Consuming a whole 64-byte block leaves the cipher positioned at block 1,
/// which is where the record body is encrypted from.
fn take_mac_key(cipher: &mut ChaCha20Legacy) -> Secret<POLY1305_KEY_BYTES> {
    let mut block = Secret::<64>::zero();
    cipher.apply_keystream(block.expose_mut());
    let mut mac_key = Secret::<POLY1305_KEY_BYTES>::zero();
    if let Some(source) = block.expose().get(..POLY1305_KEY_BYTES) {
        mac_key.expose_mut().copy_from_slice(source);
    }
    mac_key
}

/// A ChaCha20 instance over `K_1` at the record's nonce.
fn length_cipher(keys: &DirectionKeys, nonce: [u8; 8]) -> ChaCha20Legacy {
    ChaCha20Legacy::new(keys.length_key.expose().into(), (&nonce).into())
}

/// A ChaCha20 instance over `K_2` at the record's nonce.
fn payload_cipher(keys: &DirectionKeys, nonce: [u8; 8]) -> ChaCha20Legacy {
    ChaCha20Legacy::new(keys.payload_key.expose().into(), (&nonce).into())
}
