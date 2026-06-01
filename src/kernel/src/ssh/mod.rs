//! BraiNIX SSH server — an SSH-2.0 implementation integrated into the OS,
//! served over the kernel TCP stack.
//!
//! Layered build-out (RFC 4251-4254):
//!   1. version exchange      (this module, `version`)       — DONE
//!   2. KEXINIT negotiation   (`packet`, `kex`)              — in progress
//!   3. X25519 key exchange + ed25519 host key + exchange hash
//!   4. ChaCha20-Poly1305 transport encryption + NEWKEYS
//!   5. userauth (password, via the kernel credential store)
//!   6. session channel -> interactive shell
//!
//! The session is a pure state machine over byte buffers (no hardware), driven
//! by the kernel network service loop which owns the TCP connection.

pub mod version;

use version::{client_version_is_supported, SERVER_IDENTIFICATION};

/// Phases of the SSH connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SshPhase {
    /// Banner sent; waiting for the client's identification line.
    AwaitingClientVersion,
    /// Versions exchanged; ready for binary-packet key exchange.
    VersionExchanged,
    /// The client sent an unsupported identification string.
    Rejected,
}

/// One SSH connection's state.
pub struct SshSession {
    phase: SshPhase,
    /// Accumulates the client's identification line until CR/LF.
    identification_buffer: [u8; 256],
    identification_length: usize,
}

impl SshSession {
    pub fn new() -> Self {
        Self {
            phase: SshPhase::AwaitingClientVersion,
            identification_buffer: [0u8; 256],
            identification_length: 0,
        }
    }

    pub fn phase(&self) -> SshPhase {
        self.phase
    }

    /// The server identification line to send immediately on connect.
    pub fn server_identification() -> &'static [u8] {
        SERVER_IDENTIFICATION
    }

    /// Feeds received bytes into the session. Writes any response bytes to
    /// `out` and returns the number written. (Through version exchange this
    /// produces no response — the banner is sent on connect; later phases
    /// reply here.)
    pub fn on_received(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        let _ = out;
        match self.phase {
            SshPhase::AwaitingClientVersion => self.accumulate_client_version(data),
            SshPhase::VersionExchanged | SshPhase::Rejected => {}
        }
        0
    }

    /// True once the client's identification line has been received and accepted.
    pub fn version_exchanged(&self) -> bool {
        self.phase == SshPhase::VersionExchanged
    }

    /// The client's identification line (without CR/LF), valid after exchange.
    pub fn client_identification(&self) -> &[u8] {
        &self.identification_buffer[..self.identification_length]
    }

    fn accumulate_client_version(&mut self, data: &[u8]) {
        for &byte in data {
            if byte == b'\n' {
                // Strip a trailing CR.
                if self.identification_length > 0
                    && self.identification_buffer[self.identification_length - 1] == b'\r'
                {
                    self.identification_length -= 1;
                }
                self.phase = if client_version_is_supported(self.client_identification()) {
                    SshPhase::VersionExchanged
                } else {
                    SshPhase::Rejected
                };
                return;
            }
            if self.identification_length < self.identification_buffer.len() {
                self.identification_buffer[self.identification_length] = byte;
                self.identification_length += 1;
            }
        }
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

    #[test]
    fn test_server_identification_is_ssh2() {
        assert!(SshSession::server_identification().starts_with(b"SSH-2.0-"));
        assert!(SshSession::server_identification().ends_with(b"\r\n"));
    }

    #[test]
    fn test_accepts_ssh2_client_version() {
        let mut session = SshSession::new();
        let mut out = [0u8; 64];
        session.on_received(b"SSH-2.0-OpenSSH_9.6\r\n", &mut out);
        assert_eq!(session.phase(), SshPhase::VersionExchanged);
        assert!(session.version_exchanged());
        assert_eq!(session.client_identification(), b"SSH-2.0-OpenSSH_9.6");
    }

    #[test]
    fn test_accepts_version_split_across_reads() {
        let mut session = SshSession::new();
        let mut out = [0u8; 64];
        session.on_received(b"SSH-2.0-Op", &mut out);
        assert_eq!(session.phase(), SshPhase::AwaitingClientVersion);
        session.on_received(b"enSSH_9.6\r\n", &mut out);
        assert!(session.version_exchanged());
    }

    #[test]
    fn test_rejects_ssh1() {
        let mut session = SshSession::new();
        let mut out = [0u8; 64];
        session.on_received(b"SSH-1.5-Ancient\r\n", &mut out);
        assert_eq!(session.phase(), SshPhase::Rejected);
    }
}
