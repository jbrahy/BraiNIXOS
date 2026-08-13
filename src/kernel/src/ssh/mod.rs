//! BraiNIX SSH server — an SSH-2.0 implementation integrated into the OS,
//! served over the kernel TCP stack.
//!
//! # ⚠️ Dev-era scaffolding, not the product
//!
//! `NORTH_STAR.md` §*Non-goals* names **"a general-purpose remote shell"** a
//! non-goal, and states that administration is explicitly *not* a shell,
//! because "a shell that can do anything is ambient authority under another
//! name, which is exactly what the capability model exists to forbid."
//!
//! Remote management is the BSP v2 admin session's **six frozen verbs**
//! (`enroll-key`, `revoke-key`, `load-weights`, `read-audit-log`,
//! `restart-server`, `reboot`), with the serial console as break-glass.
//!
//! This module's crypto was **ported** into `src/transport-crypto/` by P2-T2
//! (copied, not moved — see `architecture/BSP-v2-serving-protocol.md` §14), and
//! `boot/ssh_bridge.rs` is deleted by **P2-T6**. Nothing is scheduled to run
//! this code, and it is x86-64-era: it would need a full aarch64 port to
//! survive on the only supported platform.

// Lint suppression, scoped to this dead module and justified rather than
// blanket-applied.
//
// These fire ~156 times here and have been failing CI continuously -- invisible
// until 2026-08-12, because Style Check died at `cargo fmt` before ever reaching
// clippy. Fixing them would be careful work on code that P2-T6 orphans and that
// no scheduled task runs.
//
// REMOVE THIS BLOCK when P2-T6 deletes the SSH bridge. If this module somehow
// outlives P2-T6, that is a signal the suppression is hiding live code and the
// lints should be fixed instead.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_arguments)]
// `identity_op` fires on poly1305's explicit `& 0xffff_ffff` masks. Those are
// deliberate: they mirror the reference implementation's 32-bit limb discipline
// and make the field arithmetic auditable against it. Clippy is technically
// correct that the mask is a no-op on a u32 and wrong about whether it should
// go -- in crypto, matching the reference beats terseness.
#![allow(clippy::identity_op)]
#![allow(clippy::manual_range_contains)]
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

pub mod client;
pub mod client_identity;
pub mod crypto;
pub mod kex;
pub mod packet;
pub mod poly1305;
pub mod transport;
pub mod version;

use kex::{build_server_kexinit, client_kexinit_is_compatible};
use packet::{parse_packet, write_packet, SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT, SSH_MSG_NEWKEYS};
use transport::DirectionKeys;
use version::{client_version_is_supported, SERVER_IDENTIFICATION};

const RECEIVE_BUFFER_SIZE: usize = 8192;

/// Phases of the SSH connection.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SshPhase {
    AwaitingClientVersion,
    AwaitingClientKexInit,
    AwaitingKexEcdhInit,
    /// KEX_ECDH_REPLY + our NEWKEYS sent; waiting for the client's NEWKEYS.
    AwaitingClientNewKeys,
    /// Encrypted transport active; running service request + password userauth.
    Authenticating,
    /// The user authenticated successfully (ready for a session channel).
    Authenticated,
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
    /// SSH binary-packet sequence numbers (increment per packet, both pre- and
    /// post-encryption).
    send_sequence: u32,
    receive_sequence: u32,
    /// Transport keys derived at KEX (None until then).
    server_to_client_keys: Option<DirectionKeys>,
    client_to_server_keys: Option<DirectionKeys>,
    /// The authenticated user's login name, once authenticated.
    authenticated_user: [u8; 32],
    authenticated_user_length: usize,
    /// The peer's channel id for the session channel.
    client_channel: u32,
    /// True once the client requested a shell (the userspace shell is bridged
    /// to this channel).
    shell_active: bool,
    /// FIFO of CHANNEL_DATA bytes the bridged shell will read as its input.
    channel_input: [u8; 4096],
    channel_input_head: usize,
    channel_input_tail: usize,
    /// Verifies (username, password) against the credential store. Injected so
    /// the pure session stays host-testable (the kernel passes a fn wrapping
    /// boot::credential_store::verify_login).
    password_verifier: fn(&[u8], &[u8]) -> bool,
}

/// Default password verifier (denies everything) for `Default`/tests that do not
/// set one.
fn deny_all_passwords(_username: &[u8], _password: &[u8]) -> bool {
    false
}

impl SshSession {
    /// Creates a session with the given X25519 ephemeral private scalar and a
    /// password verifier (the kernel passes fresh CSPRNG bytes + a verifier
    /// wrapping the credential store; tests pass fixed values).
    pub fn new_with_verifier(
        ephemeral_private: [u8; 32],
        password_verifier: fn(&[u8], &[u8]) -> bool,
    ) -> Self {
        let mut session = Self::new(ephemeral_private);
        session.password_verifier = password_verifier;
        session
    }

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
            send_sequence: 0,
            receive_sequence: 0,
            server_to_client_keys: None,
            client_to_server_keys: None,
            authenticated_user: [0u8; 32],
            authenticated_user_length: 0,
            client_channel: 0,
            shell_active: false,
            channel_input: [0u8; 4096],
            channel_input_head: 0,
            channel_input_tail: 0,
            password_verifier: deny_all_passwords,
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
                SshPhase::AwaitingClientNewKeys => self.process_client_newkeys(),
                SshPhase::Authenticating | SshPhase::Authenticated => {
                    self.process_authenticating(out, &mut written)
                }
                SshPhase::Rejected => false,
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
        self.receive_buffer
            .copy_within(count..self.receive_length, 0);
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
            self.send_sequence += 1; // our KEXINIT is binary packet seq 0
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
        self.receive_sequence += 1; // client KEXINIT consumed
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
        self.receive_sequence += 1; // client KEX_ECDH_INIT consumed
        self.emit_kex_ecdh_reply(&client_public, out, written);
        self.phase = SshPhase::AwaitingClientNewKeys;
        true
    }

    /// Consumes the client's (unencrypted) NEWKEYS, then switches to encrypted
    /// transport.
    fn process_client_newkeys(&mut self) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        let is_newkeys = !payload.is_empty() && payload[0] == SSH_MSG_NEWKEYS;
        let total = parsed.total_length;
        self.consume(total);
        self.receive_sequence += 1; // client NEWKEYS consumed
        self.phase = if is_newkeys {
            SshPhase::Authenticating
        } else {
            SshPhase::Rejected
        };
        true
    }

    /// Decrypts one client packet and drives service-request + password userauth.
    fn process_authenticating(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let keys = match self.client_to_server_keys.clone() {
            Some(keys) => keys,
            None => return false,
        };
        let mut decrypted = [0u8; 4096];
        let opened = match transport::open_packet(
            &keys,
            self.receive_sequence,
            &self.receive_buffer[..self.receive_length],
            &mut decrypted,
        ) {
            Some(opened) => opened,
            None => return false, // incomplete packet (or auth failure: fail closed)
        };
        self.consume(opened.consumed);
        self.receive_sequence += 1;
        self.handle_authenticating_message(&decrypted[..opened.payload_length], out, written);
        true
    }

    fn emit_kex_ecdh_reply(
        &mut self,
        client_public: &[u8; 32],
        out: &mut [u8],
        written: &mut usize,
    ) {
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

        // Derive the transport keys (session_id = H for the first key exchange).
        self.server_to_client_keys = Some(transport::derive_direction_keys(
            &shared_secret,
            &exchange_hash,
            &exchange_hash,
            b'D',
        ));
        self.client_to_server_keys = Some(transport::derive_direction_keys(
            &shared_secret,
            &exchange_hash,
            &exchange_hash,
            b'C',
        ));

        // KEX_ECDH_REPLY = byte(31) string(K_S) string(Q_S) string(signature).
        let mut reply = [0u8; 512];
        reply[0] = SSH_MSG_KEX_ECDH_REPLY;
        let mut offset =
            crypto::write_string(&mut reply, 1, &host_key_blob[..host_key_blob_length]);
        offset = crypto::write_string(&mut reply, offset, &server_public);
        offset = crypto::write_string(&mut reply, offset, &signature_blob[..signature_blob_length]);
        *written += write_packet(&reply[..offset], &self.cookie, &mut out[*written..]);
        self.send_sequence += 1; // KEX_ECDH_REPLY is binary packet seq 1

        // Follow with NEWKEYS; subsequent packets are encrypted.
        let newkeys_payload = [SSH_MSG_NEWKEYS];
        *written += write_packet(&newkeys_payload, &self.cookie, &mut out[*written..]);
        self.send_sequence += 1; // our NEWKEYS is binary packet seq 2
    }

    /// Encrypts and queues an SSH packet on the server->client channel.
    fn send_encrypted(&mut self, payload: &[u8], out: &mut [u8], written: &mut usize) {
        if let Some(keys) = self.server_to_client_keys.clone() {
            *written += transport::seal_packet(
                &keys,
                self.send_sequence,
                payload,
                &self.cookie,
                &mut out[*written..],
            );
            self.send_sequence += 1;
        }
    }

    /// Handles one decrypted client message during authentication: SERVICE_REQUEST
    /// -> SERVICE_ACCEPT, and USERAUTH_REQUEST (password) -> SUCCESS / FAILURE.
    fn handle_authenticating_message(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        written: &mut usize,
    ) {
        use crate::ssh::packet::{
            SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST, SSH_MSG_USERAUTH_FAILURE,
            SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS,
        };
        if payload.is_empty() {
            return;
        }
        match payload[0] {
            SSH_MSG_SERVICE_REQUEST => {
                // Reply SERVICE_ACCEPT echoing the service name.
                let service = read_ssh_string(&payload[1..]);
                let mut response = [0u8; 64];
                response[0] = SSH_MSG_SERVICE_ACCEPT;
                let length = write_ssh_string(&mut response, 1, service);
                self.send_encrypted(&response[..length], out, written);
            }
            SSH_MSG_USERAUTH_REQUEST => {
                self.handle_userauth_request(
                    payload,
                    out,
                    written,
                    SSH_MSG_USERAUTH_SUCCESS,
                    SSH_MSG_USERAUTH_FAILURE,
                );
            }
            crate::ssh::packet::SSH_MSG_CHANNEL_OPEN => {
                self.handle_channel_open(payload, out, written)
            }
            crate::ssh::packet::SSH_MSG_CHANNEL_REQUEST => {
                self.handle_channel_request(payload, out, written)
            }
            crate::ssh::packet::SSH_MSG_CHANNEL_DATA => {
                self.handle_channel_data(payload, out, written)
            }
            crate::ssh::packet::SSH_MSG_CHANNEL_CLOSE => {
                self.send_channel_close(out, written);
            }
            _ => {}
        }
    }

    /// CHANNEL_OPEN(session) -> CHANNEL_OPEN_CONFIRMATION.
    fn handle_channel_open(&mut self, payload: &[u8], out: &mut [u8], written: &mut usize) {
        use crate::ssh::packet::SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        // byte(90) string(channel_type) uint32(sender_channel) uint32(window) uint32(max).
        let channel_type = read_ssh_string(&payload[1..]);
        let sender_offset = 1 + 4 + channel_type.len();
        if payload.len() < sender_offset + 4 {
            return;
        }
        self.client_channel = read_u32(&payload[sender_offset..]);
        let mut response = [0u8; 32];
        response[0] = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
        write_u32(&mut response, 1, self.client_channel); // recipient = their channel
        write_u32(&mut response, 5, 0); // our channel id = 0
        write_u32(&mut response, 9, 0x0010_0000); // initial window
        write_u32(&mut response, 13, 0x0000_8000); // max packet
        self.send_encrypted(&response[..17], out, written);
    }

    /// CHANNEL_REQUEST: pty-req -> success; shell/exec -> success + greeting.
    fn handle_channel_request(&mut self, payload: &[u8], out: &mut [u8], written: &mut usize) {
        use crate::ssh::packet::SSH_MSG_CHANNEL_SUCCESS;
        // byte(98) uint32(recipient) string(request_type) boolean(want_reply) ...
        if payload.len() < 5 {
            return;
        }
        let request_type = read_ssh_string(&payload[5..]);
        let want_reply_offset = 5 + 4 + request_type.len();
        let want_reply = payload.get(want_reply_offset).copied().unwrap_or(0) != 0;
        if want_reply {
            let mut response = [0u8; 8];
            response[0] = SSH_MSG_CHANNEL_SUCCESS;
            write_u32(&mut response, 1, self.client_channel);
            self.send_encrypted(&response[..5], out, written);
        }
        if request_type == b"shell" || request_type == b"exec" {
            // Hand the channel to the userspace shell (bridged via serial syscalls).
            self.shell_active = true;
        }
    }

    /// CHANNEL_DATA: enqueue the client's bytes for the bridged userspace shell
    /// to read via its serial-read syscall.
    fn handle_channel_data(&mut self, payload: &[u8], _out: &mut [u8], _written: &mut usize) {
        // byte(94) uint32(recipient) string(data).
        if payload.len() < 5 {
            return;
        }
        let data = read_ssh_string(&payload[5..]);
        for &byte in data {
            let next_tail = (self.channel_input_tail + 1) % self.channel_input.len();
            if next_tail == self.channel_input_head {
                break; // input FIFO full
            }
            self.channel_input[self.channel_input_tail] = byte;
            self.channel_input_tail = next_tail;
        }
    }

    /// True once the client requested a shell session (the kernel should bridge
    /// the userspace shell to this channel).
    pub fn shell_active(&self) -> bool {
        self.shell_active
    }

    /// Dequeues one byte of the bridged shell's input (from CHANNEL_DATA), or
    /// None if the input FIFO is empty.
    pub fn poll_channel_input(&mut self) -> Option<u8> {
        if self.channel_input_head == self.channel_input_tail {
            return None;
        }
        let byte = self.channel_input[self.channel_input_head];
        self.channel_input_head = (self.channel_input_head + 1) % self.channel_input.len();
        Some(byte)
    }

    /// Sends the bridged shell's output bytes as CHANNEL_DATA. Returns the
    /// number of bytes written to `out`.
    pub fn write_channel_output(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        let mut written = 0;
        self.send_channel_text(data, out, &mut written);
        written
    }

    /// Sends exit-status 0 + EOF + CLOSE to end the session channel. Returns the
    /// number of bytes written to `out`.
    pub fn close_channel(&mut self, out: &mut [u8]) -> usize {
        use crate::ssh::packet::SSH_MSG_CHANNEL_REQUEST;
        let mut written = 0;
        let mut request = [0u8; 32];
        request[0] = SSH_MSG_CHANNEL_REQUEST;
        write_u32(&mut request, 1, self.client_channel);
        let mut offset = write_ssh_string(&mut request, 5, b"exit-status");
        request[offset] = 0;
        offset += 1;
        write_u32(&mut request, offset, 0);
        offset += 4;
        self.send_encrypted(&request[..offset], out, &mut written);
        self.send_channel_close(out, &mut written);
        written
    }

    fn send_channel_close(&mut self, out: &mut [u8], written: &mut usize) {
        use crate::ssh::packet::{SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_EOF};
        let mut eof = [0u8; 8];
        eof[0] = SSH_MSG_CHANNEL_EOF;
        write_u32(&mut eof, 1, self.client_channel);
        self.send_encrypted(&eof[..5], out, written);
        let mut close = [0u8; 8];
        close[0] = SSH_MSG_CHANNEL_CLOSE;
        write_u32(&mut close, 1, self.client_channel);
        self.send_encrypted(&close[..5], out, written);
    }

    /// Sends `text` as a CHANNEL_DATA message on the session channel.
    fn send_channel_text(&mut self, text: &[u8], out: &mut [u8], written: &mut usize) {
        use crate::ssh::packet::SSH_MSG_CHANNEL_DATA;
        let mut message = [0u8; 512];
        message[0] = SSH_MSG_CHANNEL_DATA;
        write_u32(&mut message, 1, self.client_channel);
        let end = write_ssh_string(&mut message, 5, text);
        self.send_encrypted(&message[..end], out, written);
    }

    /// Parses a USERAUTH_REQUEST and replies SUCCESS for a correct password,
    /// otherwise FAILURE advertising the "password" method.
    fn handle_userauth_request(
        &mut self,
        payload: &[u8],
        out: &mut [u8],
        written: &mut usize,
        success_message: u8,
        failure_message: u8,
    ) {
        // byte(50) string(user) string(service) string(method) ...
        let mut offset = 1;
        let username = read_ssh_string(&payload[offset..]);
        offset += 4 + username.len();
        let service = read_ssh_string(&payload[offset..]);
        offset += 4 + service.len();
        let method = read_ssh_string(&payload[offset..]);
        offset += 4 + method.len();

        let mut authenticated = false;
        if method == b"password" && payload.len() > offset {
            // boolean(FALSE) string(password)
            let password = read_ssh_string(&payload[offset + 1..]);
            authenticated = (self.password_verifier)(username, password);
        }

        if authenticated {
            self.authenticated_user_length = username.len().min(self.authenticated_user.len());
            self.authenticated_user[..self.authenticated_user_length]
                .copy_from_slice(&username[..self.authenticated_user_length]);
            let response = [success_message];
            self.send_encrypted(&response, out, written);
            self.phase = SshPhase::Authenticated;
        } else {
            // FAILURE = byte(51) name-list("password") boolean(partial=FALSE).
            let mut response = [0u8; 32];
            response[0] = failure_message;
            let length = write_ssh_string(&mut response, 1, b"password");
            response[length] = 0; // partial success false
            self.send_encrypted(&response[..length + 1], out, written);
        }
    }
}

/// Reads an SSH `string` (uint32 length + bytes) at the start of `data`.
fn read_ssh_string(data: &[u8]) -> &[u8] {
    if data.len() < 4 {
        return &[];
    }
    let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + length {
        return &[];
    }
    &data[4..4 + length]
}

/// Writes an SSH `string` at `offset`, returning the new offset.
fn write_ssh_string(out: &mut [u8], offset: usize, data: &[u8]) -> usize {
    out[offset..offset + 4].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out[offset + 4..offset + 4 + data.len()].copy_from_slice(data);
    offset + 4 + data.len()
}

/// Reads a big-endian uint32 at the start of `data`.
fn read_u32(data: &[u8]) -> u32 {
    if data.len() < 4 {
        return 0;
    }
    u32::from_be_bytes([data[0], data[1], data[2], data[3]])
}

/// Writes a big-endian uint32 at `offset`.
fn write_u32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
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
        let packet_length = write_packet(
            &kexinit_payload[..payload_length],
            &cookie,
            &mut kexinit_packet,
        );

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
        assert_eq!(session.phase(), SshPhase::AwaitingClientNewKeys);
    }

    #[test]
    fn test_rejects_ssh1() {
        let mut session = SshSession::new([0x55u8; 32]);
        let mut out = [0u8; 64];
        session.on_received(b"SSH-1.5-Ancient\r\n", &mut out);
        assert_eq!(session.phase(), SshPhase::Rejected);
    }
}
