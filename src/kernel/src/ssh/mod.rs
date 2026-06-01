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
    /// Fixed cookie/padding source for now (randomized when the exchange hash
    /// makes it security-relevant).
    cookie: [u8; 16],
    server_kexinit_sent: bool,
}

impl SshSession {
    pub fn new() -> Self {
        Self {
            phase: SshPhase::AwaitingClientVersion,
            receive_buffer: [0u8; RECEIVE_BUFFER_SIZE],
            receive_length: 0,
            client_identification: [0u8; 256],
            client_identification_length: 0,
            cookie: [0x42u8; 16],
            server_kexinit_sent: false,
        }
    }

    pub fn phase(&self) -> SshPhase {
        self.phase
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
                SshPhase::AwaitingKexEcdhInit => self.process_kex_ecdh_init(),
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
            let mut kexinit_payload = [0u8; 512];
            let payload_length = build_server_kexinit(&self.cookie, &mut kexinit_payload);
            let packet_length = write_packet(
                &kexinit_payload[..payload_length],
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
        let total = parsed.total_length;
        self.consume(total);
        self.phase = if compatible {
            SshPhase::AwaitingKexEcdhInit
        } else {
            SshPhase::Rejected
        };
        true
    }

    fn process_kex_ecdh_init(&mut self) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        let is_ecdh_init = !payload.is_empty() && payload[0] == SSH_MSG_KEX_ECDH_INIT;
        let total = parsed.total_length;
        self.consume(total);
        if is_ecdh_init {
            self.phase = SshPhase::KexNegotiated;
        }
        true
    }
}

impl Default for SshSession {
    fn default() -> Self {
        Self::new()
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
        let mut session = SshSession::new();
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
        let mut session = SshSession::new();
        let mut out = [0u8; 64];
        session.on_received(b"SSH-1.5-Ancient\r\n", &mut out);
        assert_eq!(session.phase(), SshPhase::Rejected);
    }
}
