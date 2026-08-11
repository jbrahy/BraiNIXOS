//! The three §5.1 handshake messages.
//!
//! Every field is a fixed scalar or a fixed array; there is **no var-bytes
//! field anywhere in the handshake**. That is what makes these three decoders
//! total and trivially provable: each message's length is a compile-time
//! constant, and any deviation from it is a single REJECT (rows H1 and H4).
//! It also matters cryptographically — the §5.4 transcript hashes are taken
//! over inputs whose length is a `const`, so there is no canonicalization
//! ambiguity to argue about.
//!
//! # What these decoders cannot check
//!
//! `key_selector`, `server_confirm`, and `client_confirm` are decoded as opaque
//! fixed arrays and handed to the caller. Matching a selector against the
//! credential table (§5.3) and comparing a confirmation value in constant time
//! (§5.4, rows H5 and H6) need key material this crate does not hold and must
//! not hold. `chain_counter` is likewise decoded and not bounded: §6.3's
//! comparison is against persisted state (rows K3 and K4), and a decoder that
//! guessed at it would be inventing a bound.

use crate::error::BspError;
use crate::raw::{require_exact_length, FieldReader, ResponseWriter};
use crate::{
    BSP_MAGIC, BSP_RESERVED, BSP_VERSION_MAJOR, BSP_VERSION_MINOR, LEN_CLIENT_AUTH,
    LEN_CLIENT_HELLO, LEN_CONFIRM, LEN_NONCE, LEN_SELECTOR, LEN_SERVER_HELLO,
};

/// The client's first message (§5.1), exactly
/// [`LEN_CLIENT_HELLO`](crate::LEN_CLIENT_HELLO) bytes.
///
/// Field layout, offsets normative:
///
/// | Off | Len | Field |
/// |--:|--:|---|
/// | 0 | 4 | `magic` — MUST equal `"BSP2"` |
/// | 4 | 1 | `version_major` — MUST equal 2 |
/// | 5 | 1 | `version_minor` — MUST equal 0 |
/// | 6 | 2 | `reserved` — MUST equal `0x0000` |
/// | 8 | 8 | `chain_counter` |
/// | 16 | 32 | `client_nonce` |
/// | 48 | 16 | `key_selector` |
///
/// The three checked fields are absent from this type on purpose: a decoded
/// `ClientHello` is one that already matched them, so there is no accessor
/// through which a caller could re-derive a different answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    /// The chain position the client declares it derived from (§6.3).
    ///
    /// Decoded, never bounded here. Rows K3 and K4 compare it against the
    /// server's persisted position, which this crate cannot see.
    pub chain_counter: u64,

    /// 32 fresh random bytes: the selector salt and the client's freshness
    /// contribution.
    pub client_nonce: [u8; LEN_NONCE],

    /// The per-connection blinded credential selector (§5.3).
    ///
    /// Opaque here. The constant-work scan over all
    /// [`MAX_ENROLLED_KEYS`](crate::MAX_ENROLLED_KEYS) slots, its constant-time
    /// comparison, and the break-glass refusal of row K5 are P2-T2's.
    pub key_selector: [u8; LEN_SELECTOR],
}

impl ClientHello {
    /// Decodes a `ClientHello` from exactly
    /// [`LEN_CLIENT_HELLO`](crate::LEN_CLIENT_HELLO) bytes.
    ///
    /// Enforces rows H1 and H2 in that order: the length is checked first,
    /// because a short buffer makes every field check meaningless, and the
    /// three exact-match fields are checked before any opaque field is read.
    ///
    /// Verified by: `tests::adversarial::a_client_hello_of_any_other_length_denies`
    pub fn decode(bytes: &[u8]) -> Result<Self, BspError> {
        require_exact_length(
            bytes.len(),
            LEN_CLIENT_HELLO,
            BspError::ClientHelloLengthMismatch,
        )?;
        let mut reader = FieldReader::new(bytes);
        check_preamble(&mut reader)?;
        Self::decode_body(&mut reader)
    }

    /// Reads the four fields that follow the checked preamble.
    fn decode_body(reader: &mut FieldReader<'_>) -> Result<Self, BspError> {
        let chain_counter = reader.take_u64()?;
        let client_nonce = reader.take_array()?;
        let key_selector = reader.take_array()?;
        Ok(Self {
            chain_counter,
            client_nonce,
            key_selector,
        })
    }
}

/// Checks `magic`, both version bytes, and `reserved` — the whole of row H2.
///
/// One shot, no negotiation: `version_minor` and `reserved` are exact-match
/// fields rather than extension points, which is why downgrade is impossible
/// (§5.6g). The cost — no in-band way to evolve the protocol — is §5.5's and is
/// stated there.
fn check_preamble(reader: &mut FieldReader<'_>) -> Result<(), BspError> {
    check_magic(reader)?;
    check_versions(reader)?;
    check_reserved(reader)
}

/// Row H2 — `magic` MUST equal ASCII `"BSP2"`.
fn check_magic(reader: &mut FieldReader<'_>) -> Result<(), BspError> {
    let magic: [u8; 4] = reader.take_array()?;
    if magic != BSP_MAGIC {
        return Err(BspError::BadMagic);
    }
    Ok(())
}

/// Row H2 — both version bytes are exact matches.
fn check_versions(reader: &mut FieldReader<'_>) -> Result<(), BspError> {
    if reader.take_u8()? != BSP_VERSION_MAJOR {
        return Err(BspError::UnsupportedVersionMajor);
    }
    if reader.take_u8()? != BSP_VERSION_MINOR {
        return Err(BspError::UnsupportedVersionMinor);
    }
    Ok(())
}

/// Row H2 — `reserved` MUST equal `0x0000`.
fn check_reserved(reader: &mut FieldReader<'_>) -> Result<(), BspError> {
    if reader.take_u16()? != BSP_RESERVED {
        return Err(BspError::ReservedFieldNonZero);
    }
    Ok(())
}

/// The server's reply (§5.1), exactly
/// [`LEN_SERVER_HELLO`](crate::LEN_SERVER_HELLO) bytes.
///
/// | Off | Len | Field |
/// |--:|--:|---|
/// | 0 | 32 | `server_nonce` |
/// | 32 | 32 | `server_confirm` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    /// 32 fresh random bytes from the kernel CSPRNG (`INV-BOOT-005`).
    ///
    /// §5.6c: **freshness here is the one assumption replay resistance rests
    /// on.** A serving path that cannot prove entropy is available MUST refuse
    /// connections rather than emit a weak nonce. Producing this value is the
    /// caller's; this crate only places it.
    pub server_nonce: [u8; LEN_NONCE],

    /// The server's proof of possession over `TH_1` (§5.4). Opaque here.
    pub server_confirm: [u8; LEN_CONFIRM],
}

impl ServerHello {
    /// Decodes a `ServerHello` — the client-side mirror of row H1.
    pub fn decode(bytes: &[u8]) -> Result<Self, BspError> {
        require_exact_length(
            bytes.len(),
            LEN_SERVER_HELLO,
            BspError::ServerHelloLengthMismatch,
        )?;
        let mut reader = FieldReader::new(bytes);
        let server_nonce = reader.take_array()?;
        let server_confirm = reader.take_array()?;
        Ok(Self {
            server_nonce,
            server_confirm,
        })
    }

    /// Encodes into a caller-supplied buffer and returns the bytes written.
    ///
    /// Always [`LEN_SERVER_HELLO`](crate::LEN_SERVER_HELLO) on success. There
    /// is no length prefix on the wire (§4.1): the receiver knows the count
    /// from its state.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, BspError> {
        let mut writer = ResponseWriter::new(out);
        writer.push_bytes(&self.server_nonce)?;
        writer.push_bytes(&self.server_confirm)?;
        Ok(writer.finish())
    }
}

/// The client's third message (§5.1), exactly
/// [`LEN_CLIENT_AUTH`](crate::LEN_CLIENT_AUTH) bytes.
///
/// A **plaintext handshake block, not an AEAD record** (§5.1). v1 sealed its
/// third message to obtain key confirmation as a side effect; v2 does not,
/// because `client_confirm` derives from the same `PRK_session` as the
/// directional keys. Removing the AEAD wrapper removes the last
/// pre-`ESTABLISHED` path through the record decoder and leaves the handshake
/// decoder reading nothing but three constant byte counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAuth {
    /// The client's proof of possession over `TH_2` (§5.4).
    ///
    /// Opaque here. The constant-time comparison of row H5 is P2-T2's, and its
    /// failure is a Drop that commits no chain advance (§6.2).
    pub client_confirm: [u8; LEN_CONFIRM],
}

impl ClientAuth {
    /// Decodes a `ClientAuth` from exactly
    /// [`LEN_CLIENT_AUTH`](crate::LEN_CLIENT_AUTH) bytes — row H4.
    pub fn decode(bytes: &[u8]) -> Result<Self, BspError> {
        require_exact_length(
            bytes.len(),
            LEN_CLIENT_AUTH,
            BspError::ClientAuthLengthMismatch,
        )?;
        let mut reader = FieldReader::new(bytes);
        let client_confirm = reader.take_array()?;
        Ok(Self { client_confirm })
    }
}
