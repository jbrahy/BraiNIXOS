//! BraiNIX SSH server — an SSH-2.0 implementation integrated into the OS,
//! served over the kernel TCP stack.
//!
//! Layered build-out (RFC 4251-4254):
//!   1. version exchange                                   — DONE
//!   2. binary packet protocol + KEXINIT negotiation       — DONE
//!   3. X25519 key exchange + ed25519 host key + hash      — next
//!   4. ChaCha20-Poly1305 transport + NEWKEYS
//!   5. userauth (password, via the kernel credential store)
//!   6. session channel -> interactive shell
//!
//! The session is a pure state machine over byte buffers (no hardware), driven
//! by the kernel network service loop which owns the TCP connection.

pub mod crypto;
pub mod kex;
pub mod packet;
pub mod version;

use kex::{build_server_kexinit, client_kexinit_is_compatible};
use packet::{parse_packet, write_packet, SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT};
use version::{client_version_is_supported, SERVER_IDENTIFICATION};

const RECEIVE_BUFFER_SIZE: usize = 8192;

/// Phases of the SSH connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SshPhase {
    AwaitingClientVersion,
    AwaitingClientKexInit,
    AwaitingKexEcdhInit,
    /// KEXINIT exchanged and KEX_ECDH_INIT received — ready for the ECDH reply
    /// (the cryptographic key exchange, next milestone).
    KexNegotiated,
    Rejected,
}

/// One SSH connection's state.
pub struct SshSession {
    phase: SshPhase,
    receive_buffer: [u8; RECEIVE_BUFFER_SIZE],
    receive_length: usize,
    client_identification: [u8; 256],
    client_identification_length: usize,
    cookie: [u8; 16],
    server_kexinit_sent: bool,
    /// Our X25519 ephemeral private scalar (fresh CSPRNG per connection).
    ephemeral_private: [u8; 32],
    /// Stored handshake transcript for the exchange hash.
    server_kexinit_payload: [u8; 512],
    server_kexinit_payload_length: usize,
    client_kexinit_payload: [u8; 2048],
    client_kexinit_payload_length: usize,
}

impl SshSession {
    /// Creates a session with the given X25519 ephemeral private scalar (the
    /// kernel passes fresh CSPRNG bytes; tests pass a fixed value).
    pub fn new(ephemeral_private: [u8; 32]) -> Self {
        Self {
            phase: SshPhase::AwaitingClientVersion,
            receive_buffer: [0u8; RECEIVE_BUFFER_SIZE],
            receive_length: 0,
            client_identification: [0u8; 256],
            client_identification_length: 0,
            cookie: [0x42u8; 16],
            server_kexinit_sent: false,
            ephemeral_private,
            server_kexinit_payload: [0u8; 512],
            server_kexinit_payload_length: 0,
            client_kexinit_payload: [0u8; 2048],
            client_kexinit_payload_length: 0,
        }
    }

    pub fn phase(&self) -> SshPhase {
        self.phase
    }

    /// Diagnostic: (bytes buffered, first 8 buffered bytes as a big-endian u64).
    pub fn debug_buffer_state(&self) -> (usize, u64) {
        let mut first_eight = 0u64;
        for index in 0..8.min(self.receive_length) {
            first_eight = (first_eight << 8) | self.receive_buffer[index] as u64;
        }
        (self.receive_length, first_eight)
    }

    /// The server identification line to send immediately on connect.
    pub fn server_identification() -> &'static [u8] {
        SERVER_IDENTIFICATION
    }

    pub fn client_identification(&self) -> &[u8] {
        &self.client_identification[..self.client_identification_length]
    }

    /// Feeds received bytes into the session, processing as much as possible.
    /// Writes any response bytes to `out` and returns the number written.
    pub fn on_received(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.append(data);
        let mut written = 0;
        loop {
            let progressed = match self.phase {
                SshPhase::AwaitingClientVersion => self.process_version(),
                SshPhase::AwaitingClientKexInit => self.process_client_kexinit(out, &mut written),
                SshPhase::AwaitingKexEcdhInit => self.process_kex_ecdh_init(out, &mut written),
                SshPhase::KexNegotiated | SshPhase::Rejected => false,
            };
            if !progressed {
                break;
            }
        }
        written
    }

    fn append(&mut self, data: &[u8]) {
        let space = RECEIVE_BUFFER_SIZE - self.receive_length;
        let count = data.len().min(space);
        self.receive_buffer[self.receive_length..self.receive_length + count]
            .copy_from_slice(&data[..count]);
        self.receive_length += count;
    }

    /// Removes the first `count` bytes from the receive buffer.
    fn consume(&mut self, count: usize) {
        self.receive_buffer.copy_within(count..self.receive_length, 0);
        self.receive_length -= count;
    }

    fn process_version(&mut self) -> bool {
        let newline = self.receive_buffer[..self.receive_length]
            .iter()
            .position(|&byte| byte == b'\n');
        let newline_index = match newline {
            Some(index) => index,
            None => return false,
        };
        let mut line_length = newline_index;
        if line_length > 0 && self.receive_buffer[line_length - 1] == b'\r' {
            line_length -= 1;
        }
        self.client_identification_length = line_length.min(self.client_identification.len());
        self.client_identification[..self.client_identification_length]
            .copy_from_slice(&self.receive_buffer[..self.client_identification_length]);
        self.consume(newline_index + 1);
        if client_version_is_supported(self.client_identification()) {
            self.phase = SshPhase::AwaitingClientKexInit;
        } else {
            self.phase = SshPhase::Rejected;
        }
        true
    }

    fn process_client_kexinit(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        // Queue our KEXINIT exactly once (right after version exchange).
        if !self.server_kexinit_sent {
            let payload_length =
                build_server_kexinit(&self.cookie, &mut self.server_kexinit_payload);
            self.server_kexinit_payload_length = payload_length;
            let packet_length = write_packet(
                &self.server_kexinit_payload[..payload_length],
                &self.cookie,
                &mut out[*written..],
            );
            *written += packet_length;
            self.server_kexinit_sent = true;
        }
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false, // wait for the client's KEXINIT
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        let compatible = !payload.is_empty()
            && payload[0] == SSH_MSG_KEXINIT
            && client_kexinit_is_compatible(payload);
        // Store the client's KEXINIT payload (I_C) for the exchange hash.
        let client_length = payload.len().min(self.client_kexinit_payload.len());
        self.client_kexinit_payload[..client_length].copy_from_slice(&payload[..client_length]);
        self.client_kexinit_payload_length = client_length;
        let total = parsed.total_length;
        self.consume(total);
        self.phase = if compatible {
            SshPhase::AwaitingKexEcdhInit
        } else {
            SshPhase::Rejected
        };
        true
    }

    /// On KEX_ECDH_INIT, run the X25519 exchange, sign the exchange hash with
    /// the ed25519 host key, and emit KEX_ECDH_REPLY followed by NEWKEYS.
    fn process_kex_ecdh_init(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        // KEX_ECDH_INIT = byte(30) string(Q_C). Q_C is the client's X25519 public.
        let total = parsed.total_length;
        if payload.len() < 1 + 4 + 32 || payload[0] != SSH_MSG_KEX_ECDH_INIT {
            self.consume(total);
            self.phase = SshPhase::Rejected;
            return true;
        }
        let mut client_public = [0u8; 32];
        client_public.copy_from_slice(&payload[5..37]);
        self.consume(total);
        self.emit_kex_ecdh_reply(&client_public, out, written);
        self.phase = SshPhase::KexNegotiated;
        true
    }

    fn emit_kex_ecdh_reply(&mut self, client_public: &[u8; 32], out: &mut [u8], written: &mut usize) {
        use crate::ssh::crypto;
        use crate::ssh::packet::{SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_NEWKEYS};

        let server_public = crypto::x25519_public_key(&self.ephemeral_private);
        let shared_secret = crypto::x25519_shared_secret(&self.ephemeral_private, client_public);

        let mut host_key_blob = [0u8; 128];
        let host_key_blob_length = crypto::build_host_key_blob(&mut host_key_blob);

        let exchange_hash = crypto::compute_exchange_hash(
            self.client_identification(),
            version::server_identification_without_crlf(),
            &self.client_kexinit_payload[..self.client_kexinit_payload_length],
            &self.server_kexinit_payload[..self.server_kexinit_payload_length],
            &host_key_blob[..host_key_blob_length],
            client_public,
            &server_public,
            &shared_secret,
        );
        let signature = crypto::host_sign(&exchange_hash);
        let mut signature_blob = [0u8; 128];
        let signature_blob_length = crypto::build_signature_blob(&signature, &mut signature_blob);

        // KEX_ECDH_REPLY = byte(31) string(K_S) string(Q_S) string(signature).
        let mut reply = [0u8; 512];
        reply[0] = SSH_MSG_KEX_ECDH_REPLY;
        let mut offset = crypto::write_string(&mut reply, 1, &host_key_blob[..host_key_blob_length]);
        offset = crypto::write_string(&mut reply, offset, &server_public);
        offset = crypto::write_string(&mut reply, offset, &signature_blob[..signature_blob_length]);
        *written += write_packet(&reply[..offset], &self.cookie, &mut out[*written..]);

        // Immediately follow with NEWKEYS (we switch ciphers on the client's NEWKEYS).
        let newkeys_payload = [SSH_MSG_NEWKEYS];
        *written += write_packet(&newkeys_payload, &self.cookie, &mut out[*written..]);
    }
}

impl Default for SshSession {
    fn default() -> Self {
        Self::new([0x42u8; 32])
    }
}

#[cfg(test)]
mod tests {
    use super::{SshPhase, SshSession};
    use crate::ssh::kex::build_server_kexinit;
    use crate::ssh::packet::{write_packet, SSH_MSG_KEX_ECDH_INIT};

    #[test]
    fn test_server_identification_is_ssh2() {
        assert!(SshSession::server_identification().starts_with(b"SSH-2.0-"));
        assert!(SshSession::server_identification().ends_with(b"\r\n"));
    }

    #[test]
    fn test_version_then_kexinit_then_ecdh() {
        let mut session = SshSession::new([0x55u8; 32]);
        let mut out = [0u8; 1024];

        // Client sends its version line + a KEXINIT packet together.
        let cookie = [0x77u8; 16];
        let mut kexinit_payload = [0u8; 512];
        let payload_length = build_server_kexinit(&cookie, &mut kexinit_payload);
        let mut kexinit_packet = [0u8; 600];
        let packet_length =
            write_packet(&kexinit_payload[..payload_length], &cookie, &mut kexinit_packet);

        let mut client_data = [0u8; 700];
        let version = b"SSH-2.0-OpenSSH_9.6\r\n";
        client_data[..version.len()].copy_from_slice(version);
        client_data[version.len()..version.len() + packet_length]
            .copy_from_slice(&kexinit_packet[..packet_length]);
        let total = version.len() + packet_length;

        let written = session.on_received(&client_data[..total], &mut out);
        // We sent our KEXINIT in response.
        assert!(written > 0);
        assert_eq!(session.phase(), SshPhase::AwaitingKexEcdhInit);

        // Client sends KEX_ECDH_INIT.
        let mut ecdh_payload = [0u8; 64];
        ecdh_payload[0] = SSH_MSG_KEX_ECDH_INIT;
        ecdh_payload[1..5].copy_from_slice(&32u32.to_be_bytes()); // a 32-byte public key
        let mut ecdh_packet = [0u8; 128];
        let ecdh_length = write_packet(&ecdh_payload[..37], &cookie, &mut ecdh_packet);
        session.on_received(&ecdh_packet[..ecdh_length], &mut out);
        assert_eq!(session.phase(), SshPhase::KexNegotiated);
    }

    #[test]
    fn test_rejects_ssh1() {
        let mut session = SshSession::new([0x55u8; 32]);
        let mut out = [0u8; 64];
        session.on_received(b"SSH-1.5-Ancient\r\n", &mut out);
        assert_eq!(session.phase(), SshPhase::Rejected);
    }
}
