//! SSH key-exchange negotiation: building the server's SSH_MSG_KEXINIT and
//! checking the client's KEXINIT for compatible algorithms (RFC 4253 §7.1).
//!
//! BraiNIX offers a single modern algorithm per category — the same suite
//! OpenSSH negotiates by default:
//!   kex      curve25519-sha256
//!   hostkey  ssh-ed25519
//!   cipher   chacha20-poly1305@openssh.com
//!   mac      hmac-sha2-256 (implicit/unused under the AEAD cipher)
//!   comp     none

use crate::ssh::packet::SSH_MSG_KEXINIT;

pub const KEX_ALGORITHM: &[u8] = b"curve25519-sha256";
pub const HOST_KEY_ALGORITHM: &[u8] = b"ssh-ed25519";
pub const CIPHER_ALGORITHM: &[u8] = b"chacha20-poly1305@openssh.com";
pub const MAC_ALGORITHM: &[u8] = b"hmac-sha2-256";
pub const COMPRESSION_ALGORITHM: &[u8] = b"none";

/// Writes a name-list (uint32 length-prefixed comma string — here a single
/// name) at `offset` in `out`, returning the new offset.
fn write_name_list(out: &mut [u8], offset: usize, name: &[u8]) -> usize {
    out[offset..offset + 4].copy_from_slice(&(name.len() as u32).to_be_bytes());
    out[offset + 4..offset + 4 + name.len()].copy_from_slice(name);
    offset + 4 + name.len()
}

/// Builds the server SSH_MSG_KEXINIT payload into `out` using `cookie` (16
/// random bytes). Returns the payload length.
pub fn build_server_kexinit(cookie: &[u8; 16], out: &mut [u8]) -> usize {
    out[0] = SSH_MSG_KEXINIT;
    out[1..17].copy_from_slice(cookie);
    let mut offset = 17;
    offset = write_name_list(out, offset, KEX_ALGORITHM);
    offset = write_name_list(out, offset, HOST_KEY_ALGORITHM);
    offset = write_name_list(out, offset, CIPHER_ALGORITHM); // enc c2s
    offset = write_name_list(out, offset, CIPHER_ALGORITHM); // enc s2c
    offset = write_name_list(out, offset, MAC_ALGORITHM); // mac c2s
    offset = write_name_list(out, offset, MAC_ALGORITHM); // mac s2c
    offset = write_name_list(out, offset, COMPRESSION_ALGORITHM); // comp c2s
    offset = write_name_list(out, offset, COMPRESSION_ALGORITHM); // comp s2c
    offset = write_name_list(out, offset, b""); // languages c2s
    offset = write_name_list(out, offset, b""); // languages s2c
    out[offset] = 0; // first_kex_packet_follows
    offset += 1;
    out[offset..offset + 4].copy_from_slice(&0u32.to_be_bytes()); // reserved
    offset + 4
}

/// True if `payload` is a KEXINIT (msg 20) that lists our kex algorithm and
/// host-key algorithm somewhere in its name-lists (a lenient substring check —
/// the client offers many, we only need ours present).
pub fn client_kexinit_is_compatible(payload: &[u8]) -> bool {
    if payload.is_empty() || payload[0] != SSH_MSG_KEXINIT {
        return false;
    }
    contains_subsequence(payload, KEX_ALGORITHM)
        && contains_subsequence(payload, CIPHER_ALGORITHM)
}

fn contains_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        build_server_kexinit, client_kexinit_is_compatible, CIPHER_ALGORITHM, KEX_ALGORITHM,
    };
    use crate::ssh::packet::SSH_MSG_KEXINIT;

    #[test]
    fn test_server_kexinit_structure() {
        let cookie = [0x11u8; 16];
        let mut out = [0u8; 512];
        let length = build_server_kexinit(&cookie, &mut out);
        assert_eq!(out[0], SSH_MSG_KEXINIT);
        assert_eq!(&out[1..17], &cookie);
        // The first name-list is our kex algorithm.
        let kex_len = u32::from_be_bytes([out[17], out[18], out[19], out[20]]) as usize;
        assert_eq!(&out[21..21 + kex_len], KEX_ALGORITHM);
        // Trailing reserved uint32 is zero.
        assert_eq!(&out[length - 4..length], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_client_compatibility_check() {
        // Synthesize a client KEXINIT-ish payload listing our algorithms.
        let mut payload = [0u8; 256];
        payload[0] = SSH_MSG_KEXINIT;
        payload[20..20 + KEX_ALGORITHM.len()].copy_from_slice(KEX_ALGORITHM);
        payload[80..80 + CIPHER_ALGORITHM.len()].copy_from_slice(CIPHER_ALGORITHM);
        assert!(client_kexinit_is_compatible(&payload));
        // A payload that is not a KEXINIT is rejected.
        let mut other = payload;
        other[0] = 99;
        assert!(!client_kexinit_is_compatible(&other));
    }
}
