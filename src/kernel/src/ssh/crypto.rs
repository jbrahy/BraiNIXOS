//! SSH key-exchange cryptography: X25519 ECDH, the RFC 4253/5656 exchange hash,
//! the ed25519 host key, and SSH wire encodings (string, mpint).
//!
//! Uses the vendored curve25519-dalek (X25519) and ed25519-dalek (host key
//! signature) with sha2 for the exchange hash.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// SSH host-key / signature algorithm name.
pub const HOST_KEY_ALGORITHM_NAME: &[u8] = b"ssh-ed25519";

/// Development host key seed (a fixed ed25519 secret). A persistent,
/// disk-stored key replaces this; clients use StrictHostKeyChecking=no for now.
const HOST_KEY_SEED: [u8; 32] = [
    0xb7, 0xa1, 0x4d, 0x15, 0x42, 0x72, 0x61, 0x69, 0x4e, 0x49, 0x58, 0x2d, 0x73, 0x73, 0x68, 0x2d,
    0x68, 0x6f, 0x73, 0x74, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x30, 0x31, 0x00, 0x11, 0x22, 0x33, 0x44,
];

/// Derives the X25519 public key (Q) from a 32-byte private scalar.
pub fn x25519_public_key(private_scalar: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*private_scalar).0
}

/// Computes the X25519 shared secret from our private scalar and the peer's
/// public key.
pub fn x25519_shared_secret(private_scalar: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint(*peer_public).mul_clamped(*private_scalar).0
}

/// The ed25519 host public key (32 bytes).
pub fn host_public_key() -> [u8; 32] {
    SigningKey::from_bytes(&HOST_KEY_SEED)
        .verifying_key()
        .to_bytes()
}

/// Signs `message` with the ed25519 host key, returning the 64-byte signature.
pub fn host_sign(message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&HOST_KEY_SEED)
        .sign(message)
        .to_bytes()
}

/// Writes an SSH `string` (uint32 length prefix + bytes) at `offset`.
pub fn write_string(out: &mut [u8], offset: usize, data: &[u8]) -> usize {
    out[offset..offset + 4].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out[offset + 4..offset + 4 + data.len()].copy_from_slice(data);
    offset + 4 + data.len()
}

/// Number of bytes an SSH mpint encoding of `value` (big-endian) occupies.
fn mpint_body(value: &[u8; 32], body: &mut [u8; 33]) -> usize {
    // Strip leading zero bytes.
    let mut start = 0;
    while start < 32 && value[start] == 0 {
        start += 1;
    }
    if start == 32 {
        return 0; // value is zero -> empty mpint
    }
    let mut length = 32 - start;
    let mut write_index = 0;
    if value[start] & 0x80 != 0 {
        body[0] = 0x00; // keep positive
        write_index = 1;
        length += 1;
    }
    body[write_index..write_index + (32 - start)].copy_from_slice(&value[start..]);
    length
}

/// Writes an SSH `mpint` (length-prefixed, minimal, positive) at `offset`.
pub fn write_mpint(out: &mut [u8], offset: usize, value: &[u8; 32]) -> usize {
    let mut body = [0u8; 33];
    let length = mpint_body(value, &mut body);
    out[offset..offset + 4].copy_from_slice(&(length as u32).to_be_bytes());
    out[offset + 4..offset + 4 + length].copy_from_slice(&body[..length]);
    offset + 4 + length
}

/// Builds the ssh-ed25519 host key blob: string("ssh-ed25519") string(pubkey).
pub fn build_host_key_blob(out: &mut [u8]) -> usize {
    let mut offset = write_string(out, 0, HOST_KEY_ALGORITHM_NAME);
    offset = write_string(out, offset, &host_public_key());
    offset
}

/// Builds the ssh-ed25519 signature blob: string("ssh-ed25519") string(sig).
pub fn build_signature_blob(signature: &[u8; 64], out: &mut [u8]) -> usize {
    let mut offset = write_string(out, 0, HOST_KEY_ALGORITHM_NAME);
    offset = write_string(out, offset, signature);
    offset
}

/// Verifies that `signature` is a valid ssh-ed25519 signature by the ed25519
/// public key `verifying_public_key` over `message`. Returns false on any
/// malformed key or signature (never panics). Used by the SSH client to verify
/// a remote server's host-key signature over the exchange hash.
pub fn host_signature_is_valid(
    verifying_public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    let verifying_key = match VerifyingKey::from_bytes(verifying_public_key) {
        Ok(verifying_key) => verifying_key,
        Err(_) => return false,
    };
    verifying_key
        .verify(message, &Signature::from_bytes(signature))
        .is_ok()
}

/// Reads an SSH `string` (uint32 length + bytes) at `offset`; returns the body
/// and the offset just past it, or None if the blob is truncated.
fn read_ssh_string(blob: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let length_end = offset.checked_add(4)?;
    let length_bytes = blob.get(offset..length_end)?;
    let length = u32::from_be_bytes([
        length_bytes[0],
        length_bytes[1],
        length_bytes[2],
        length_bytes[3],
    ]) as usize;
    let body_end = length_end.checked_add(length)?;
    let body = blob.get(length_end..body_end)?;
    Some((body, body_end))
}

/// Parses an ssh-ed25519 key blob (string("ssh-ed25519") string(key)) to the
/// 32-byte ed25519 public key. None on algorithm mismatch or short input.
/// Inverse of [`build_host_key_blob`].
pub fn parse_ed25519_key_blob(blob: &[u8]) -> Option<[u8; 32]> {
    let (algorithm, offset) = read_ssh_string(blob, 0)?;
    if algorithm != HOST_KEY_ALGORITHM_NAME {
        return None;
    }
    let (key, _) = read_ssh_string(blob, offset)?;
    key.try_into().ok()
}

/// Parses an ssh-ed25519 signature blob (string("ssh-ed25519") string(sig)) to
/// the 64-byte signature. None on algorithm mismatch or short input. Inverse of
/// [`build_signature_blob`].
pub fn parse_ed25519_signature_blob(blob: &[u8]) -> Option<[u8; 64]> {
    let (algorithm, offset) = read_ssh_string(blob, 0)?;
    if algorithm != HOST_KEY_ALGORITHM_NAME {
        return None;
    }
    let (signature, _) = read_ssh_string(blob, offset)?;
    signature.try_into().ok()
}

/// Computes the SSH exchange hash H (curve25519-sha256):
/// H = SHA256(string(V_C) string(V_S) string(I_C) string(I_S) string(K_S)
///            string(Q_C) string(Q_S) mpint(K)).
#[allow(clippy::too_many_arguments)]
pub fn compute_exchange_hash(
    client_version: &[u8],
    server_version: &[u8],
    client_kexinit: &[u8],
    server_kexinit: &[u8],
    host_key_blob: &[u8],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
    shared_secret: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_string(&mut hasher, client_version);
    hash_string(&mut hasher, server_version);
    hash_string(&mut hasher, client_kexinit);
    hash_string(&mut hasher, server_kexinit);
    hash_string(&mut hasher, host_key_blob);
    hash_string(&mut hasher, client_public);
    hash_string(&mut hasher, server_public);
    hash_mpint(&mut hasher, shared_secret);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn hash_string(hasher: &mut Sha256, data: &[u8]) {
    hasher.update((data.len() as u32).to_be_bytes());
    hasher.update(data);
}

fn hash_mpint(hasher: &mut Sha256, value: &[u8; 32]) {
    let mut body = [0u8; 33];
    let length = mpint_body(value, &mut body);
    hasher.update((length as u32).to_be_bytes());
    hasher.update(&body[..length]);
}

#[cfg(test)]
mod tests {
    use super::{
        build_host_key_blob, compute_exchange_hash, host_public_key, host_sign, write_mpint,
        x25519_public_key, x25519_shared_secret, HOST_KEY_ALGORITHM_NAME,
    };
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn test_x25519_shared_secret_agrees() {
        let alice_private = [7u8; 32];
        let bob_private = [9u8; 32];
        let alice_public = x25519_public_key(&alice_private);
        let bob_public = x25519_public_key(&bob_private);
        let alice_shared = x25519_shared_secret(&alice_private, &bob_public);
        let bob_shared = x25519_shared_secret(&bob_private, &alice_public);
        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_host_signature_verifies() {
        let message = b"exchange-hash-stand-in";
        let signature = host_sign(message);
        let verifying = VerifyingKey::from_bytes(&host_public_key()).unwrap();
        assert!(verifying
            .verify(message, &Signature::from_bytes(&signature))
            .is_ok());
    }

    #[test]
    fn test_host_key_blob_format() {
        let mut blob = [0u8; 128];
        let length = build_host_key_blob(&mut blob);
        // string("ssh-ed25519") then string(32-byte pubkey).
        let name_len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
        assert_eq!(&blob[4..4 + name_len], HOST_KEY_ALGORITHM_NAME);
        let key_len_off = 4 + name_len;
        let key_len = u32::from_be_bytes([
            blob[key_len_off],
            blob[key_len_off + 1],
            blob[key_len_off + 2],
            blob[key_len_off + 3],
        ]) as usize;
        assert_eq!(key_len, 32);
        assert_eq!(length, key_len_off + 4 + 32);
    }

    #[test]
    fn test_mpint_high_bit_gets_leading_zero() {
        let mut value = [0u8; 32];
        value[0] = 0x80; // high bit set -> needs a leading 0x00
        let mut out = [0u8; 64];
        let end = write_mpint(&mut out, 0, &value);
        let length = u32::from_be_bytes([out[0], out[1], out[2], out[3]]) as usize;
        assert_eq!(length, 33); // 32 + leading zero
        assert_eq!(out[4], 0x00);
        assert_eq!(end, 4 + 33);
    }

    #[test]
    fn test_host_signature_is_valid_round_trip() {
        use super::host_signature_is_valid;
        let message = b"exchange-hash-stand-in";
        let signature = host_sign(message);
        assert!(host_signature_is_valid(
            &host_public_key(),
            message,
            &signature
        ));
    }

    #[test]
    fn test_host_signature_is_valid_rejects_tampered_message() {
        use super::host_signature_is_valid;
        let signature = host_sign(b"original");
        assert!(!host_signature_is_valid(
            &host_public_key(),
            b"tampered",
            &signature
        ));
    }

    #[test]
    fn test_host_signature_is_valid_rejects_wrong_key() {
        use super::host_signature_is_valid;
        let message = b"msg";
        let signature = host_sign(message);
        let wrong_key = [0x01u8; 32];
        assert!(!host_signature_is_valid(&wrong_key, message, &signature));
    }

    #[test]
    fn test_parse_ed25519_key_blob_inverts_build() {
        use super::parse_ed25519_key_blob;
        let mut blob = [0u8; 128];
        let length = build_host_key_blob(&mut blob);
        assert_eq!(
            parse_ed25519_key_blob(&blob[..length]),
            Some(host_public_key())
        );
    }

    #[test]
    fn test_parse_ed25519_signature_blob_inverts_build() {
        use super::{build_signature_blob, parse_ed25519_signature_blob};
        let signature = host_sign(b"data");
        let mut blob = [0u8; 128];
        let length = build_signature_blob(&signature, &mut blob);
        assert_eq!(
            parse_ed25519_signature_blob(&blob[..length]),
            Some(signature)
        );
    }

    #[test]
    fn test_parse_rejects_wrong_algorithm() {
        use super::{parse_ed25519_key_blob, write_string};
        let mut blob = [0u8; 64];
        let mut offset = write_string(&mut blob, 0, b"ssh-rsa");
        offset = write_string(&mut blob, offset, &[0u8; 32]);
        assert_eq!(parse_ed25519_key_blob(&blob[..offset]), None);
    }

    #[test]
    fn test_parse_rejects_truncated_blob() {
        use super::parse_ed25519_key_blob;
        assert_eq!(parse_ed25519_key_blob(&[0, 0, 0, 11, b's']), None);
    }

    #[test]
    fn test_exchange_hash_is_deterministic() {
        let q = [3u8; 32];
        let k = [4u8; 32];
        let mut blob = [0u8; 128];
        let blob_len = build_host_key_blob(&mut blob);
        let h1 = compute_exchange_hash(
            b"V_C",
            b"V_S",
            b"I_C",
            b"I_S",
            &blob[..blob_len],
            &q,
            &q,
            &k,
        );
        let h2 = compute_exchange_hash(
            b"V_C",
            b"V_S",
            b"I_C",
            b"I_S",
            &blob[..blob_len],
            &q,
            &q,
            &k,
        );
        assert_eq!(h1, h2);
    }
}
