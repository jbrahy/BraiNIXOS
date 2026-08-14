#![no_std]
#![deny(unsafe_code)]

//! The client half of BSP v2 (P2-T11).
//!
//! `brainix-bsp` is the **server's** view of the wire: it decodes what a client
//! sends and encodes what a server sends. Nothing in the tree spoke the other
//! half, so every test of that decoder fed it a byte array written by hand from
//! the specification's field tables — which tests the decoder against
//! somebody's reading of the spec, twice, in the same head.
//!
//! This crate is the other end. Its encoders are written from the same
//! normative field tables, and the tests round-trip them through the server's
//! decoder: two implementations, written to one specification, required to
//! agree. A field-offset mistake in either now shows up as a disagreement
//! rather than as a hand-written array that happens to match the mistake.
//!
//! # What it is not
//!
//! No socket, no key schedule, no session. A `ClientHello` here is bytes in the
//! right order, not a handshake: the nonce, the selector and the confirmation
//! value are the caller's, because computing them is `brainix-transport-crypto`'s
//! and pretending otherwise would put a second key schedule in the tree. The
//! driver that opens a connection and runs a session is P3-T9a, and it needs a
//! server to talk to.

use brainix_bsp::{
    BspError, ClientAuth, ClientHello, BSP_MAGIC, BSP_RESERVED, BSP_VERSION_MAJOR,
    BSP_VERSION_MINOR, LEN_CLIENT_AUTH, LEN_CLIENT_HELLO,
};

/// Writes the eight-byte preamble every client message opens with.
///
/// `magic`, both version bytes and `reserved` are **exact-match** fields on the
/// server side rather than negotiation, which is what makes downgrade
/// impossible (§5.6g). An encoder that treated any of them as a parameter would
/// be offering the caller a downgrade this protocol does not have.
fn write_preamble(out: &mut [u8]) -> Result<usize, BspError> {
    let magic = out.get_mut(0..4).ok_or(BspError::OutputBufferTooSmall)?;
    magic.copy_from_slice(&BSP_MAGIC);
    *out.get_mut(4).ok_or(BspError::OutputBufferTooSmall)? = BSP_VERSION_MAJOR;
    *out.get_mut(5).ok_or(BspError::OutputBufferTooSmall)? = BSP_VERSION_MINOR;
    let reserved = out.get_mut(6..8).ok_or(BspError::OutputBufferTooSmall)?;
    reserved.copy_from_slice(&BSP_RESERVED.to_be_bytes());
    Ok(8)
}

/// Encodes a `ClientHello` into exactly
/// [`LEN_CLIENT_HELLO`](brainix_bsp::LEN_CLIENT_HELLO) bytes.
///
/// Offsets are §5.1's: preamble at 0, `chain_counter` at 8, `client_nonce` at
/// 16, `key_selector` at 48.
///
/// # Errors
///
/// [`BspError::OutputBufferTooSmall`] if `out` is smaller than a `ClientHello`.
pub fn encode_client_hello(hello: &ClientHello, out: &mut [u8]) -> Result<usize, BspError> {
    if out.len() < LEN_CLIENT_HELLO {
        return Err(BspError::OutputBufferTooSmall);
    }
    let written = write_preamble(out)?;
    debug_assert_eq!(written, 8);

    let counter = out.get_mut(8..16).ok_or(BspError::OutputBufferTooSmall)?;
    counter.copy_from_slice(&hello.chain_counter.to_be_bytes());
    let nonce = out.get_mut(16..48).ok_or(BspError::OutputBufferTooSmall)?;
    nonce.copy_from_slice(&hello.client_nonce);
    let selector = out
        .get_mut(48..LEN_CLIENT_HELLO)
        .ok_or(BspError::OutputBufferTooSmall)?;
    selector.copy_from_slice(&hello.key_selector);
    Ok(LEN_CLIENT_HELLO)
}

/// Encodes a `ClientAuth` into exactly
/// [`LEN_CLIENT_AUTH`](brainix_bsp::LEN_CLIENT_AUTH) bytes.
///
/// No preamble: §5.4's `ClientAuth` is the confirmation value and nothing else,
/// because the session is already bound to `TH_2` by the time it is sent.
///
/// # Errors
///
/// [`BspError::OutputBufferTooSmall`] if `out` is smaller than a `ClientAuth`.
pub fn encode_client_auth(auth: &ClientAuth, out: &mut [u8]) -> Result<usize, BspError> {
    let field = out
        .get_mut(0..LEN_CLIENT_AUTH)
        .ok_or(BspError::OutputBufferTooSmall)?;
    field.copy_from_slice(&auth.client_confirm);
    Ok(LEN_CLIENT_AUTH)
}
