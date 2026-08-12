//! chacha20-poly1305@openssh.com transport encryption (post-NEWKEYS).
//!
//! Key derivation per RFC 4253 §7.2; the AEAD construction per OpenSSH's
//! PROTOCOL.chacha20poly1305: a 512-bit key splits into K_2 (payload, first 256
//! bits) and K_1 (length, second 256 bits). The packet length is encrypted with
//! K_1; the payload with K_2 starting at block 1; Poly1305 (key = K_2 keystream
//! block 0) authenticates length||ciphertext. The nonce is the packet sequence
//! number as a big-endian u64.

use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20Legacy;
use sha2::{Digest, Sha256};

use crate::ssh::crypto::write_mpint;
use crate::ssh::poly1305::poly1305_mac;

/// chacha20-poly1305 key material length (two 256-bit keys).
const CIPHER_KEY_LENGTH: usize = 64;
const POLY1305_TAG_LENGTH: usize = 16;
const PACKET_LENGTH_FIELD: usize = 4;
const AEAD_BLOCK_SIZE: usize = 8;
const MINIMUM_PADDING: usize = 4;

/// One direction's chacha20-poly1305 keys: K_2 (payload) and K_1 (length).
#[derive(Clone)]
pub struct DirectionKeys {
    payload_key: [u8; 32],
    length_key: [u8; 32],
}

/// Derives the 64-byte key for direction letter `X` ('C' = client->server,
/// 'D' = server->client) from the shared secret `K`, exchange hash `H`, and
/// `session_id` (= H for the first key exchange). RFC 4253 §7.2.
pub fn derive_direction_keys(
    shared_secret: &[u8; 32],
    exchange_hash: &[u8; 32],
    session_id: &[u8; 32],
    direction_letter: u8,
) -> DirectionKeys {
    let mut k_mpint = [0u8; 36];
    let k_mpint_length = write_mpint(&mut k_mpint, 0, shared_secret);

    // K1 = HASH(K || H || letter || session_id)
    let mut hasher = Sha256::new();
    hasher.update(&k_mpint[..k_mpint_length]);
    hasher.update(exchange_hash);
    hasher.update([direction_letter]);
    hasher.update(session_id);
    let k1 = hasher.finalize();

    // K2 = HASH(K || H || K1)
    let mut hasher = Sha256::new();
    hasher.update(&k_mpint[..k_mpint_length]);
    hasher.update(exchange_hash);
    hasher.update(k1);
    let k2 = hasher.finalize();

    // key = (K1 || K2)[..64]; first 32 -> K_2 (payload), next 32 -> K_1 (length).
    let mut key = [0u8; CIPHER_KEY_LENGTH];
    key[0..32].copy_from_slice(&k1);
    key[32..64].copy_from_slice(&k2);
    let mut payload_key = [0u8; 32];
    let mut length_key = [0u8; 32];
    payload_key.copy_from_slice(&key[0..32]);
    length_key.copy_from_slice(&key[32..64]);
    DirectionKeys {
        payload_key,
        length_key,
    }
}

fn nonce_for_sequence(sequence_number: u32) -> [u8; 8] {
    // 64-bit big-endian nonce; the high 32 bits stay zero for our packet counts.
    let mut nonce = [0u8; 8];
    nonce[4..8].copy_from_slice(&sequence_number.to_be_bytes());
    nonce
}

/// Encrypts `payload` as an SSH binary packet at `sequence_number`, writing
/// encrypted-length(4) || ciphertext || tag(16) to `out`. Returns the length.
pub fn seal_packet(
    keys: &DirectionKeys,
    sequence_number: u32,
    payload: &[u8],
    padding_source: &[u8],
    out: &mut [u8],
) -> usize {
    // padding so that (1 + payload + padding) is a multiple of 8, padding >= 4.
    let unpadded = 1 + payload.len();
    let mut padding_length = AEAD_BLOCK_SIZE - (unpadded % AEAD_BLOCK_SIZE);
    if padding_length < MINIMUM_PADDING {
        padding_length += AEAD_BLOCK_SIZE;
    }
    let packet_length = 1 + payload.len() + padding_length;

    // Plaintext payload region: padding_length || payload || padding.
    let mut plaintext = [0u8; 4096];
    plaintext[0] = padding_length as u8;
    plaintext[1..1 + payload.len()].copy_from_slice(payload);
    for index in 0..padding_length {
        plaintext[1 + payload.len() + index] = padding_source.get(index).copied().unwrap_or(0);
    }
    let plaintext_length = packet_length;

    let nonce = nonce_for_sequence(sequence_number);

    // Encrypt the length with K_1.
    out[0..4].copy_from_slice(&(packet_length as u32).to_be_bytes());
    let mut length_cipher = ChaCha20Legacy::new((&keys.length_key).into(), (&nonce).into());
    length_cipher.apply_keystream(&mut out[0..4]);

    // Poly1305 key = K_2 keystream block 0; payload encrypted from block 1.
    let mut payload_cipher = ChaCha20Legacy::new((&keys.payload_key).into(), (&nonce).into());
    let mut poly_block = [0u8; 64];
    payload_cipher.apply_keystream(&mut poly_block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_block[0..32]);
    payload_cipher.apply_keystream(&mut plaintext[..plaintext_length]);
    out[4..4 + plaintext_length].copy_from_slice(&plaintext[..plaintext_length]);

    // Tag over encrypted length || ciphertext.
    let tag = poly1305_mac(&poly_key, &out[..4 + plaintext_length]);
    out[4 + plaintext_length..4 + plaintext_length + POLY1305_TAG_LENGTH].copy_from_slice(&tag);
    4 + plaintext_length + POLY1305_TAG_LENGTH
}

/// Result of opening one encrypted packet.
pub struct OpenedPacket {
    /// Decrypted SSH payload bytes (without padding) written to the caller buffer.
    pub payload_length: usize,
    /// Total encrypted bytes consumed from the input.
    pub consumed: usize,
}

/// Attempts to decrypt and authenticate one packet at `sequence_number` from the
/// start of `input`, writing the plaintext payload to `payload_out`. Returns
/// None if `input` lacks a full packet; Err semantics (auth failure) also yield
/// None (fail closed).
pub fn open_packet(
    keys: &DirectionKeys,
    sequence_number: u32,
    input: &[u8],
    payload_out: &mut [u8],
) -> Option<OpenedPacket> {
    if input.len() < PACKET_LENGTH_FIELD {
        return None;
    }
    let nonce = nonce_for_sequence(sequence_number);

    // Decrypt the length with K_1.
    let mut length_bytes = [0u8; 4];
    length_bytes.copy_from_slice(&input[0..4]);
    let mut length_cipher = ChaCha20Legacy::new((&keys.length_key).into(), (&nonce).into());
    length_cipher.apply_keystream(&mut length_bytes);
    let packet_length = u32::from_be_bytes(length_bytes) as usize;
    if packet_length < 2 || packet_length > 35000 {
        return None;
    }
    let total = PACKET_LENGTH_FIELD + packet_length + POLY1305_TAG_LENGTH;
    if input.len() < total {
        return None;
    }

    // Verify the tag over encrypted length || ciphertext.
    let mut payload_cipher = ChaCha20Legacy::new((&keys.payload_key).into(), (&nonce).into());
    let mut poly_block = [0u8; 64];
    payload_cipher.apply_keystream(&mut poly_block);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&poly_block[0..32]);
    let tag = poly1305_mac(&poly_key, &input[..PACKET_LENGTH_FIELD + packet_length]);
    let received_tag = &input[PACKET_LENGTH_FIELD + packet_length..total];
    if !constant_time_equal(&tag, received_tag) {
        return None;
    }

    // Decrypt the ciphertext (padding_length || payload || padding).
    let mut plaintext = [0u8; 4096];
    plaintext[..packet_length]
        .copy_from_slice(&input[PACKET_LENGTH_FIELD..PACKET_LENGTH_FIELD + packet_length]);
    payload_cipher.apply_keystream(&mut plaintext[..packet_length]);

    let padding_length = plaintext[0] as usize;
    if padding_length + 1 > packet_length {
        return None;
    }
    let payload_length = packet_length - padding_length - 1;
    if payload_length > payload_out.len() {
        return None;
    }
    payload_out[..payload_length].copy_from_slice(&plaintext[1..1 + payload_length]);
    Some(OpenedPacket {
        payload_length,
        consumed: total,
    })
}

fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for index in 0..a.len() {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{derive_direction_keys, open_packet, seal_packet};

    #[test]
    fn test_seal_open_round_trip() {
        let keys = derive_direction_keys(&[9u8; 32], &[3u8; 32], &[3u8; 32], b'D');
        let payload = b"\x05hello-encrypted-ssh-payload";
        let padding = [0xABu8; 64];
        let mut sealed = [0u8; 256];
        let sealed_length = seal_packet(&keys, 3, payload, &padding, &mut sealed);

        let mut recovered = [0u8; 256];
        let opened =
            open_packet(&keys, 3, &sealed[..sealed_length], &mut recovered).expect("opens");
        assert_eq!(&recovered[..opened.payload_length], payload);
        assert_eq!(opened.consumed, sealed_length);
    }

    #[test]
    fn test_wrong_sequence_fails_auth() {
        let keys = derive_direction_keys(&[9u8; 32], &[3u8; 32], &[3u8; 32], b'D');
        let mut sealed = [0u8; 256];
        let sealed_length = seal_packet(&keys, 3, b"data", &[0u8; 64], &mut sealed);
        let mut recovered = [0u8; 256];
        // Opening at the wrong sequence number must fail the Poly1305 check.
        assert!(open_packet(&keys, 4, &sealed[..sealed_length], &mut recovered).is_none());
    }

    #[test]
    fn test_directions_differ() {
        let server = derive_direction_keys(&[1u8; 32], &[2u8; 32], &[2u8; 32], b'D');
        let client = derive_direction_keys(&[1u8; 32], &[2u8; 32], &[2u8; 32], b'C');
        assert_ne!(server.payload_key, client.payload_key);
    }
}
