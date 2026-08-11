//! Fixtures, built programmatically from the specification's tables.
//!
//! Nothing here calls the crate's own decoders or encoders to build an input.
//! Every fixture is assembled byte by byte from §5.1, §10.2, §10.4, and §4.2,
//! so a test that passes proves the decoder agrees with the specification
//! rather than with itself. The one exception is
//! [`ServerHello::encode`](brainix_bsp::ServerHello::encode), which the
//! round-trip test deliberately checks against a hand-built image.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::useless_vec
)]

use brainix_bsp::{Session, SessionType};

// ---------------------------------------------------------------------------
// §5.1 handshake messages
// ---------------------------------------------------------------------------

/// A distinguishable 32-byte nonce.
pub fn nonce(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed ^ (index as u8);
    }
    out
}

/// A distinguishable 16-byte selector or handle.
pub fn sixteen(seed: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    out
}

/// The §5.1 `ClientHello` image: 4+1+1+2+8+32+16 = 64 bytes.
pub fn client_hello(chain_counter: u64, client_nonce: [u8; 32], selector: [u8; 16]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"BSP2");
    out.extend_from_slice(&[2, 0]);
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&chain_counter.to_be_bytes());
    out.extend_from_slice(&client_nonce);
    out.extend_from_slice(&selector);
    assert_eq!(out.len(), 64, "spec §8 LEN_CLIENT_HELLO");
    out
}

/// A `ClientHello` with default field values.
pub fn valid_client_hello() -> Vec<u8> {
    client_hello(7, nonce(0xa1), sixteen(0x30))
}

/// The §5.1 `ServerHello` image: 32+32 = 64 bytes.
pub fn server_hello(server_nonce: [u8; 32], server_confirm: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&server_nonce);
    out.extend_from_slice(&server_confirm);
    assert_eq!(out.len(), 64, "spec §8 LEN_SERVER_HELLO");
    out
}

/// The §5.1 `ClientAuth` image: 32 bytes.
pub fn client_auth(client_confirm: [u8; 32]) -> Vec<u8> {
    let out = client_confirm.to_vec();
    assert_eq!(out.len(), 32, "spec §8 LEN_CLIENT_AUTH");
    out
}

/// A `ClientAuth` with a default confirmation value.
pub fn valid_client_auth() -> Vec<u8> {
    client_auth(nonce(0xc3))
}

// ---------------------------------------------------------------------------
// §10.2 client-session messages
// ---------------------------------------------------------------------------

/// `0x01` — `request_id[4]`, `max_tokens[4]`, `temperature[2]`, `top_p[2]`,
/// `prompt_total_len[4]`.
pub fn infer_begin(
    request_id: u32,
    max_tokens: u32,
    temperature: u16,
    top_p: u16,
    prompt_total_length: u32,
) -> Vec<u8> {
    let mut out = vec![0x01];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&max_tokens.to_be_bytes());
    out.extend_from_slice(&temperature.to_be_bytes());
    out.extend_from_slice(&top_p.to_be_bytes());
    out.extend_from_slice(&prompt_total_length.to_be_bytes());
    assert_eq!(out.len(), 17, "tag + 16 body bytes");
    out
}

/// `0x02` — `request_id[4]`, `chunk[u16 len]`.
pub fn prompt_chunk(request_id: u32, chunk: &[u8]) -> Vec<u8> {
    prompt_chunk_with_declared_length(request_id, chunk, chunk.len() as u16)
}

/// A `PromptChunk` whose declared var-bytes length may disagree with the bytes
/// that follow it.
pub fn prompt_chunk_with_declared_length(request_id: u32, chunk: &[u8], declared: u16) -> Vec<u8> {
    let mut out = vec![0x02];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&declared.to_be_bytes());
    out.extend_from_slice(chunk);
    out
}

/// `0x03` — `request_id[4]`.
pub fn infer_commit(request_id: u32) -> Vec<u8> {
    tagged_request_id(0x03, request_id)
}

/// `0x04` — `request_id[4]`.
pub fn cancel(request_id: u32) -> Vec<u8> {
    tagged_request_id(0x04, request_id)
}

/// `0x05` — empty body.
pub fn close() -> Vec<u8> {
    vec![0x05]
}

/// Any `tag[1] || request_id[4]` message.
pub fn tagged_request_id(tag: u8, request_id: u32) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&request_id.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// §10.4 admin verbs
// ---------------------------------------------------------------------------

/// `0x11` — `request_id[4]`, `role[1]`, `key_material[32]`.
pub fn enroll_key(request_id: u32, role: u8, key_material: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x11];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.push(role);
    out.extend_from_slice(&key_material);
    assert_eq!(out.len(), 38, "tag + 37 body bytes");
    out
}

/// `0x12` — `request_id[4]`, `handle[16]`.
pub fn revoke_key(request_id: u32, handle: [u8; 16]) -> Vec<u8> {
    let mut out = vec![0x12];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&handle);
    assert_eq!(out.len(), 21, "tag + 20 body bytes");
    out
}

/// `0x13` — `request_id[4]`, `weights_digest[32]`.
pub fn load_weights(request_id: u32, digest: [u8; 32]) -> Vec<u8> {
    let mut out = vec![0x13];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&digest);
    assert_eq!(out.len(), 37, "tag + 36 body bytes");
    out
}

/// `0x14` — `request_id[4]`, `cursor[8]`, `max_records[2]`.
pub fn read_audit_log(request_id: u32, cursor: u64, max_records: u16) -> Vec<u8> {
    let mut out = vec![0x14];
    out.extend_from_slice(&request_id.to_be_bytes());
    out.extend_from_slice(&cursor.to_be_bytes());
    out.extend_from_slice(&max_records.to_be_bytes());
    assert_eq!(out.len(), 15, "tag + 14 body bytes");
    out
}

/// `0x15` — `request_id[4]`, `target[1]`.
pub fn restart_server(request_id: u32, target: u8) -> Vec<u8> {
    let mut out = tagged_request_id(0x15, request_id);
    out.push(target);
    assert_eq!(out.len(), 6, "tag + 5 body bytes");
    out
}

/// `0x16` — `request_id[4]`.
pub fn reboot(request_id: u32) -> Vec<u8> {
    tagged_request_id(0x16, request_id)
}

/// Every well-formed admin verb, for the sweeps that must cover all six.
pub fn all_six_verbs() -> Vec<Vec<u8>> {
    vec![
        enroll_key(1, 0x01, nonce(0x11)),
        revoke_key(2, sixteen(0x22)),
        load_weights(3, nonce(0x33)),
        read_audit_log(4, 0xdead_beef_0000_0001, 64),
        restart_server(5, 0x02),
        reboot(6),
    ]
}

// ---------------------------------------------------------------------------
// §4.2 record plaintext
// ---------------------------------------------------------------------------

/// Builds `padding_length[1] || payload || padding` by hand, padding to a
/// multiple of 8 with at least 4 padding bytes.
pub fn record_plaintext(payload: &[u8]) -> Vec<u8> {
    let mut padding = 4;
    while !(1 + payload.len() + padding).is_multiple_of(8) {
        padding += 1;
    }
    let mut out = vec![padding as u8];
    out.extend_from_slice(payload);
    out.extend(core::iter::repeat_n(0u8, padding));
    out
}

/// One complete data record's wire image, given already-sealed ciphertext.
///
/// The "ciphertext" here is opaque filler: this crate never decrypts, so the
/// framing tests care only about the byte counts.
pub fn data_record(packet_length: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&packet_length.to_be_bytes());
    out.extend(core::iter::repeat_n(0xabu8, packet_length as usize));
    out.extend(core::iter::repeat_n(0xcdu8, 16));
    out
}

// ---------------------------------------------------------------------------
// Session drivers
// ---------------------------------------------------------------------------

/// A session driven to `ESTABLISHED` with the given granted capability.
pub fn established(session_type: SessionType) -> Session {
    let mut session = Session::new();
    session.accept_client_hello(&valid_client_hello()).unwrap();
    session.accept_client_auth(&valid_client_auth()).unwrap();
    session.establish(session_type).unwrap();
    session
}

/// An established client session with an open request collecting `declared`
/// prompt bytes.
pub fn collecting(request_id: u32, declared: u32) -> Session {
    let mut session = established(SessionType::Client);
    let begin = infer_begin(request_id, 128, 700, 900, declared);
    session.accept_message(&begin).unwrap();
    session
}

/// An established client session that is streaming `request_id`.
pub fn streaming(request_id: u32) -> Session {
    let mut session = collecting(request_id, 4);
    session
        .accept_message(&prompt_chunk(request_id, b"abcd"))
        .unwrap();
    session.accept_message(&infer_commit(request_id)).unwrap();
    session
}
