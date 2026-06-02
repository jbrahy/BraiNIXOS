//! SSH *client* identity and the pinned remote host-key allowlist.
//!
//! Distinct from `crypto.rs`, which holds *our server's* host key. This module
//! holds:
//!   * the client's ed25519 signing key (a kernel-TCB secret used for
//!     public-key user authentication) — exposed only as
//!     [`client_public_key`] and [`client_sign`]; the raw seed never leaves the
//!     module (no getter), mirroring how the CSPRNG exposes only random bytes;
//!   * a strict, compile-time **allowlist** of remote server host keys
//!     ([`pinned_host_key`]). Outbound SSH uses fail-closed pinning — a server
//!     whose offered host key does not byte-match the pin for its IP is
//!     rejected. There is no trust-on-first-use.
//!
//! No alloc, no unsafe, no panics; ≤6 executable lines per function.

use ed25519_dalek::{Signer, SigningKey};

/// Client ed25519 signing seed (kernel-TCB secret, distinct from the server's
/// `HOST_KEY_SEED`). v1 is a fixed dev seed; a persisted, CSPRNG-generated key
/// stored MAC-protected on disk replaces it later. Never exposed via any getter.
const CLIENT_KEY_SEED: [u8; 32] = [
    0xc1, 0xe7, 0x2d, 0x15, 0x42, 0x72, 0x61, 0x69, 0x4e, 0x49, 0x58, 0x2d, 0x73, 0x73, 0x68, 0x2d,
    0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x6b, 0x65, 0x79, 0x2d, 0x76, 0x30, 0x31, 0xaa, 0xbb, 0xcc,
];

/// One pinned remote host: its IPv4 literal bound to its ed25519 host public key.
struct PinnedHost {
    ipv4: [u8; 4],
    host_public_key: [u8; 32],
}

/// Compile-time allowlist of accepted remote SSH servers (strict pinning,
/// no TOFU). The entry for the dev verification sshd at 10.0.2.2 is a
/// placeholder until Stage B bakes in that server's real ed25519 host key.
const PINNED_HOSTS: &[PinnedHost] = &[PinnedHost {
    ipv4: [10, 0, 2, 2],
    // PLACEHOLDER — replaced in Stage B3 with the dev sshd's real ed25519 pubkey.
    host_public_key: [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ],
}];

/// The client's ed25519 public key (32 bytes), for the publickey userauth blob.
pub fn client_public_key() -> [u8; 32] {
    SigningKey::from_bytes(&CLIENT_KEY_SEED)
        .verifying_key()
        .to_bytes()
}

/// Signs `message` with the client ed25519 key, returning the 64-byte signature.
pub fn client_sign(message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(&CLIENT_KEY_SEED)
        .sign(message)
        .to_bytes()
}

/// Returns the pinned ed25519 host key for `ipv4`, or None if not allowlisted.
pub fn pinned_host_key(ipv4: [u8; 4]) -> Option<[u8; 32]> {
    PINNED_HOSTS
        .iter()
        .find(|host| host.ipv4 == ipv4)
        .map(|host| host.host_public_key)
}

/// Constant-time byte-slice equality (length-checked). Used to compare an
/// offered host key against its pin without leaking a timing signal.
pub fn constant_time_equals(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference: u8 = 0;
    for index in 0..left.len() {
        difference |= left[index] ^ right[index];
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    #[test]
    fn test_client_signature_verifies_under_client_public_key() {
        let message = b"userauth-signing-blob";
        let signature = client_sign(message);
        let verifying = VerifyingKey::from_bytes(&client_public_key()).unwrap();
        assert!(verifying
            .verify(message, &Signature::from_bytes(&signature))
            .is_ok());
    }

    #[test]
    fn test_pinned_host_key_returns_entry_for_known_ip() {
        assert!(pinned_host_key([10, 0, 2, 2]).is_some());
    }

    #[test]
    fn test_pinned_host_key_returns_none_for_unknown_ip() {
        assert_eq!(pinned_host_key([8, 8, 8, 8]), None);
    }

    #[test]
    fn test_constant_time_equals_matches_and_mismatches() {
        assert!(constant_time_equals(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_equals(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_equals(&[1, 2, 3], &[1, 2]));
    }
}
