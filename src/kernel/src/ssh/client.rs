//! BraiNIX SSH *client* — the initiator counterpart to [`super::SshSession`].
//!
//! Where the server reacts to inbound bytes, the client must *speak first* each
//! phase, so it exposes [`advance`](SshClientSession::advance) (emit the next
//! client-initiated message) in addition to
//! [`on_received`](SshClientSession::on_received). Both share one `drive` loop.
//!
//! Security posture (outbound-only): the server's host key is verified by
//! signature over the exchange hash AND pinned (the offered key must byte-match
//! the `expected_host_key` supplied by the driver from the allowlist — no TOFU).
//! User authentication tries ed25519 public-key first, then falls back to
//! password. The client signing key is the kernel-TCB secret in
//! [`client_identity`].
//!
//! AEAD direction note: the client *sends* with the `b'C'` (client→server) keys
//! and *receives* with the `b'D'` (server→client) keys — the inverse of the
//! server's variable naming. This is exercised by the end-to-end test.
//!
//! Pure state machine over byte buffers (no hardware), like the server.

use super::{read_ssh_string, read_u32, write_ssh_string};
use crate::ssh::client_identity;
use crate::ssh::crypto;
use crate::ssh::kex::{build_client_kexinit, server_kexinit_is_compatible};
use crate::ssh::packet::{
    parse_packet, write_packet, SSH_MSG_CHANNEL_CLOSE, SSH_MSG_CHANNEL_DATA,
    SSH_MSG_CHANNEL_FAILURE, SSH_MSG_CHANNEL_OPEN, SSH_MSG_CHANNEL_OPEN_CONFIRMATION,
    SSH_MSG_CHANNEL_REQUEST, SSH_MSG_CHANNEL_SUCCESS, SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT,
    SSH_MSG_KEX_ECDH_REPLY, SSH_MSG_NEWKEYS, SSH_MSG_SERVICE_ACCEPT, SSH_MSG_SERVICE_REQUEST,
    SSH_MSG_USERAUTH_FAILURE, SSH_MSG_USERAUTH_REQUEST, SSH_MSG_USERAUTH_SUCCESS,
};
use crate::ssh::transport::{self, derive_direction_keys, DirectionKeys};
use crate::ssh::version::{
    client_version_is_supported, server_identification_without_crlf, SERVER_IDENTIFICATION,
};

const RECEIVE_BUFFER_SIZE: usize = 8192;
const OUTPUT_FIFO_SIZE: usize = 4096;

/// Phases of the outbound SSH connection (initiator).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SshClientPhase {
    SendBanner,
    AwaitServerBanner,
    SendKexInit,
    AwaitServerKexInit,
    SendKexEcdhInit,
    AwaitKexEcdhReply,
    SendNewKeys,
    AwaitServerNewKeys,
    SendServiceRequest,
    AwaitServiceAccept,
    SendUserauthPublicKey,
    SendUserauthPassword,
    AwaitUserauthReply,
    SendChannelOpen,
    AwaitChannelConfirm,
    SendChannelRequest,
    AwaitChannelReply,
    Relay,
    Rejected,
    Closed,
}

/// One outbound SSH connection's state.
pub struct SshClientSession {
    phase: SshClientPhase,
    receive_buffer: [u8; RECEIVE_BUFFER_SIZE],
    receive_length: usize,
    server_identification: [u8; 256],
    server_identification_length: usize,
    cookie: [u8; 16],
    ephemeral_private: [u8; 32],
    client_public: [u8; 32],
    client_kexinit_payload: [u8; 512],
    client_kexinit_payload_length: usize,
    server_kexinit_payload: [u8; 2048],
    server_kexinit_payload_length: usize,
    send_sequence: u32,
    receive_sequence: u32,
    /// SEND keys (client→server, derived with `b'C'`).
    client_to_server_keys: Option<DirectionKeys>,
    /// RECEIVE keys (server→client, derived with `b'D'`).
    server_to_client_keys: Option<DirectionKeys>,
    session_id: [u8; 32],
    /// The pinned host key for the target (driver supplies from the allowlist).
    expected_host_key: [u8; 32],
    username: [u8; 32],
    username_length: usize,
    password: [u8; 64],
    password_length: usize,
    command: [u8; 256],
    command_length: usize,
    password_attempted: bool,
    server_channel: u32,
    output_fifo: [u8; OUTPUT_FIFO_SIZE],
    output_head: usize,
    output_tail: usize,
}

impl SshClientSession {
    /// Creates an outbound session. `command` empty ⇒ request an interactive
    /// shell; otherwise exec it. `expected_host_key` is the pin for the target.
    pub fn new(
        ephemeral_private: [u8; 32],
        cookie: [u8; 16],
        expected_host_key: [u8; 32],
        username: &[u8],
        password: &[u8],
        command: &[u8],
    ) -> Self {
        let mut session = Self::empty(ephemeral_private, cookie, expected_host_key);
        session.username_length = copy_into(&mut session.username, username);
        session.password_length = copy_into(&mut session.password, password);
        session.command_length = copy_into(&mut session.command, command);
        session
    }

    fn empty(ephemeral_private: [u8; 32], cookie: [u8; 16], expected_host_key: [u8; 32]) -> Self {
        Self {
            phase: SshClientPhase::SendBanner,
            receive_buffer: [0u8; RECEIVE_BUFFER_SIZE],
            receive_length: 0,
            server_identification: [0u8; 256],
            server_identification_length: 0,
            cookie,
            ephemeral_private,
            client_public: [0u8; 32],
            client_kexinit_payload: [0u8; 512],
            client_kexinit_payload_length: 0,
            server_kexinit_payload: [0u8; 2048],
            server_kexinit_payload_length: 0,
            send_sequence: 0,
            receive_sequence: 0,
            client_to_server_keys: None,
            server_to_client_keys: None,
            session_id: [0u8; 32],
            expected_host_key,
            username: [0u8; 32],
            username_length: 0,
            password: [0u8; 64],
            password_length: 0,
            command: [0u8; 256],
            command_length: 0,
            password_attempted: false,
            server_channel: 0,
            output_fifo: [0u8; OUTPUT_FIFO_SIZE],
            output_head: 0,
            output_tail: 0,
        }
    }

    pub fn phase(&self) -> SshClientPhase {
        self.phase
    }

    fn username(&self) -> &[u8] {
        &self.username[..self.username_length]
    }

    fn password(&self) -> &[u8] {
        &self.password[..self.password_length]
    }

    fn command(&self) -> &[u8] {
        &self.command[..self.command_length]
    }

    /// Emits the next client-initiated message(s) for the current phase into
    /// `out`. Returns the number of bytes written (0 while waiting on the peer).
    pub fn advance(&mut self, out: &mut [u8]) -> usize {
        let mut written = 0;
        self.drive(out, &mut written);
        written
    }

    /// Feeds received (TCP-reassembled) bytes, processing as many complete
    /// banner lines / packets as available, and emits any resulting messages.
    pub fn on_received(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        self.append(data);
        let mut written = 0;
        self.drive(out, &mut written);
        written
    }

    fn drive(&mut self, out: &mut [u8], written: &mut usize) {
        loop {
            let progressed = match self.phase {
                SshClientPhase::SendBanner => self.emit_banner(out, written),
                SshClientPhase::AwaitServerBanner => self.process_server_banner(),
                SshClientPhase::SendKexInit => self.emit_kexinit(out, written),
                SshClientPhase::AwaitServerKexInit => self.process_server_kexinit(),
                SshClientPhase::SendKexEcdhInit => self.emit_kex_ecdh_init(out, written),
                SshClientPhase::AwaitKexEcdhReply => self.process_kex_ecdh_reply(),
                SshClientPhase::SendNewKeys => self.emit_newkeys(out, written),
                SshClientPhase::AwaitServerNewKeys => self.process_server_newkeys(),
                SshClientPhase::SendServiceRequest => self.emit_service_request(out, written),
                SshClientPhase::AwaitServiceAccept => self.process_service_accept(),
                SshClientPhase::SendUserauthPublicKey => self.emit_userauth_publickey(out, written),
                SshClientPhase::SendUserauthPassword => self.emit_userauth_password(out, written),
                SshClientPhase::AwaitUserauthReply => self.process_userauth_reply(),
                SshClientPhase::SendChannelOpen => self.emit_channel_open(out, written),
                SshClientPhase::AwaitChannelConfirm => self.process_channel_confirm(),
                SshClientPhase::SendChannelRequest => self.emit_channel_request(out, written),
                SshClientPhase::AwaitChannelReply => self.process_channel_reply(),
                SshClientPhase::Relay => self.process_relay(),
                SshClientPhase::Rejected | SshClientPhase::Closed => false,
            };
            if !progressed {
                break;
            }
        }
    }

    fn append(&mut self, data: &[u8]) {
        let space = RECEIVE_BUFFER_SIZE - self.receive_length;
        let count = data.len().min(space);
        self.receive_buffer[self.receive_length..self.receive_length + count]
            .copy_from_slice(&data[..count]);
        self.receive_length += count;
    }

    fn consume(&mut self, count: usize) {
        self.receive_buffer
            .copy_within(count..self.receive_length, 0);
        self.receive_length -= count;
    }

    // ---- KEX phase ----------------------------------------------------------

    fn emit_banner(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        out[*written..*written + SERVER_IDENTIFICATION.len()]
            .copy_from_slice(SERVER_IDENTIFICATION);
        *written += SERVER_IDENTIFICATION.len();
        self.phase = SshClientPhase::SendKexInit;
        true
    }

    fn emit_kexinit(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let length = build_client_kexinit(&self.cookie, &mut self.client_kexinit_payload);
        self.client_kexinit_payload_length = length;
        *written += write_packet(
            &self.client_kexinit_payload[..length],
            &self.cookie,
            &mut out[*written..],
        );
        self.send_sequence += 1;
        self.phase = SshClientPhase::AwaitServerBanner;
        true
    }

    fn process_server_banner(&mut self) -> bool {
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
        self.server_identification_length = line_length.min(self.server_identification.len());
        self.server_identification[..self.server_identification_length]
            .copy_from_slice(&self.receive_buffer[..self.server_identification_length]);
        self.consume(newline_index + 1);
        self.phase = if client_version_is_supported(self.server_identification()) {
            SshClientPhase::AwaitServerKexInit
        } else {
            SshClientPhase::Rejected
        };
        true
    }

    fn server_identification(&self) -> &[u8] {
        &self.server_identification[..self.server_identification_length]
    }

    fn process_server_kexinit(&mut self) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        let compatible = !payload.is_empty()
            && payload[0] == SSH_MSG_KEXINIT
            && server_kexinit_is_compatible(payload);
        let length = payload.len().min(self.server_kexinit_payload.len());
        self.server_kexinit_payload[..length].copy_from_slice(&payload[..length]);
        self.server_kexinit_payload_length = length;
        let total = parsed.total_length;
        self.consume(total);
        self.receive_sequence += 1;
        self.phase = if compatible {
            SshClientPhase::SendKexEcdhInit
        } else {
            SshClientPhase::Rejected
        };
        true
    }

    fn emit_kex_ecdh_init(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        self.client_public = crypto::x25519_public_key(&self.ephemeral_private);
        let mut payload = [0u8; 64];
        payload[0] = SSH_MSG_KEX_ECDH_INIT;
        let end = write_ssh_string(&mut payload, 1, &self.client_public);
        *written += write_packet(&payload[..end], &self.cookie, &mut out[*written..]);
        self.send_sequence += 1;
        self.phase = SshClientPhase::AwaitKexEcdhReply;
        true
    }

    fn process_kex_ecdh_reply(&mut self) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let mut payload = [0u8; 512];
        let length = (parsed.payload_end - parsed.payload_start).min(payload.len());
        payload[..length].copy_from_slice(
            &self.receive_buffer[parsed.payload_start..parsed.payload_start + length],
        );
        let total = parsed.total_length;
        self.consume(total);
        self.receive_sequence += 1;
        self.phase = if self.verify_and_derive(&payload[..length]) {
            SshClientPhase::SendNewKeys
        } else {
            SshClientPhase::Rejected
        };
        true
    }

    /// Parses KEX_ECDH_REPLY, computes the exchange hash, verifies the host-key
    /// signature, enforces the pin, and derives transport keys. Returns false
    /// (→ Rejected) on any parse/verify/pin failure (fail closed).
    fn verify_and_derive(&mut self, payload: &[u8]) -> bool {
        if payload.is_empty() || payload[0] != SSH_MSG_KEX_ECDH_REPLY {
            return false;
        }
        let mut offset = 1;
        let host_key_blob = read_ssh_string(&payload[offset..]);
        offset += 4 + host_key_blob.len();
        let server_public_slice = read_ssh_string(&payload[offset..]);
        offset += 4 + server_public_slice.len();
        let signature_blob = read_ssh_string(&payload[offset..]);
        let server_public: [u8; 32] = match server_public_slice.try_into() {
            Ok(array) => array,
            Err(_) => return false,
        };
        let shared_secret = crypto::x25519_shared_secret(&self.ephemeral_private, &server_public);
        let exchange_hash = self.exchange_hash_for(host_key_blob, &server_public, &shared_secret);
        if !self.host_key_is_acceptable(host_key_blob, signature_blob, &exchange_hash) {
            return false;
        }
        self.session_id = exchange_hash;
        self.derive_session_keys(&shared_secret, &exchange_hash);
        true
    }

    fn exchange_hash_for(
        &self,
        host_key_blob: &[u8],
        server_public: &[u8; 32],
        shared_secret: &[u8; 32],
    ) -> [u8; 32] {
        crypto::compute_exchange_hash(
            server_identification_without_crlf(),
            self.server_identification(),
            &self.client_kexinit_payload[..self.client_kexinit_payload_length],
            &self.server_kexinit_payload[..self.server_kexinit_payload_length],
            host_key_blob,
            &self.client_public,
            server_public,
            shared_secret,
        )
    }

    /// Fail-closed host-key acceptance: the signature must verify under the
    /// offered key AND that key must byte-match the pin (no TOFU). Both
    /// independent checks must pass.
    fn host_key_is_acceptable(
        &self,
        host_key_blob: &[u8],
        signature_blob: &[u8],
        exchange_hash: &[u8; 32],
    ) -> bool {
        let server_host_key = match crypto::parse_ed25519_key_blob(host_key_blob) {
            Some(key) => key,
            None => return false,
        };
        let signature = match crypto::parse_ed25519_signature_blob(signature_blob) {
            Some(signature) => signature,
            None => return false,
        };
        crypto::host_signature_is_valid(&server_host_key, exchange_hash, &signature)
            && client_identity::constant_time_equals(&server_host_key, &self.expected_host_key)
    }

    fn derive_session_keys(&mut self, shared_secret: &[u8; 32], exchange_hash: &[u8; 32]) {
        self.client_to_server_keys = Some(derive_direction_keys(
            shared_secret,
            exchange_hash,
            exchange_hash,
            b'C',
        ));
        self.server_to_client_keys = Some(derive_direction_keys(
            shared_secret,
            exchange_hash,
            exchange_hash,
            b'D',
        ));
    }

    fn emit_newkeys(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        *written += write_packet(&[SSH_MSG_NEWKEYS], &self.cookie, &mut out[*written..]);
        self.send_sequence += 1;
        self.phase = SshClientPhase::AwaitServerNewKeys;
        true
    }

    fn process_server_newkeys(&mut self) -> bool {
        let parsed = match parse_packet(&self.receive_buffer[..self.receive_length]) {
            Some(parsed) => parsed,
            None => return false,
        };
        let payload = &self.receive_buffer[parsed.payload_start..parsed.payload_end];
        let is_newkeys = !payload.is_empty() && payload[0] == SSH_MSG_NEWKEYS;
        let total = parsed.total_length;
        self.consume(total);
        self.receive_sequence += 1;
        self.phase = if is_newkeys {
            SshClientPhase::SendServiceRequest
        } else {
            SshClientPhase::Rejected
        };
        true
    }

    // ---- Encrypted transport helpers ---------------------------------------

    fn send_encrypted(&mut self, payload: &[u8], out: &mut [u8], written: &mut usize) {
        if let Some(keys) = self.client_to_server_keys.clone() {
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

    /// Decrypts one inbound packet, writing its payload to `decrypted`; returns
    /// the payload length, or None if no full packet is buffered (fail closed).
    fn open_encrypted(&mut self, decrypted: &mut [u8]) -> Option<usize> {
        let keys = self.server_to_client_keys.clone()?;
        let opened = transport::open_packet(
            &keys,
            self.receive_sequence,
            &self.receive_buffer[..self.receive_length],
            decrypted,
        )?;
        self.consume(opened.consumed);
        self.receive_sequence += 1;
        Some(opened.payload_length)
    }

    // ---- Userauth phase -----------------------------------------------------

    fn emit_service_request(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let mut payload = [0u8; 32];
        payload[0] = SSH_MSG_SERVICE_REQUEST;
        let end = write_ssh_string(&mut payload, 1, b"ssh-userauth");
        self.send_encrypted(&payload[..end], out, written);
        self.phase = SshClientPhase::AwaitServiceAccept;
        true
    }

    fn process_service_accept(&mut self) -> bool {
        let mut decrypted = [0u8; 4096];
        let length = match self.open_encrypted(&mut decrypted) {
            Some(length) => length,
            None => return false,
        };
        if length > 0 && decrypted[0] == SSH_MSG_SERVICE_ACCEPT {
            self.phase = SshClientPhase::SendUserauthPublicKey;
        }
        true
    }

    fn emit_userauth_publickey(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let mut request = [0u8; 512];
        let request_length = self.build_publickey_request_body(&mut request);
        let mut signing_blob = [0u8; 640];
        let signing_length = build_signing_blob(
            &self.session_id,
            &request[..request_length],
            &mut signing_blob,
        );
        let signature = client_identity::client_sign(&signing_blob[..signing_length]);
        let mut payload = [0u8; 768];
        let payload_length =
            assemble_publickey_payload(&request[..request_length], &signature, &mut payload);
        self.send_encrypted(&payload[..payload_length], out, written);
        self.phase = SshClientPhase::AwaitUserauthReply;
        true
    }

    /// Builds the publickey USERAUTH_REQUEST body (everything that is signed,
    /// minus the leading string(session_id)): byte(50) string(user)
    /// string("ssh-connection") string("publickey") TRUE string("ssh-ed25519")
    /// string(client-key-blob).
    fn build_publickey_request_body(&self, out: &mut [u8]) -> usize {
        out[0] = SSH_MSG_USERAUTH_REQUEST;
        let mut offset = write_ssh_string(out, 1, self.username());
        offset = write_ssh_string(out, offset, b"ssh-connection");
        offset = write_ssh_string(out, offset, b"publickey");
        out[offset] = 1; // boolean TRUE: a signature follows
        offset += 1;
        offset = write_ssh_string(out, offset, crypto::HOST_KEY_ALGORITHM_NAME);
        let mut key_blob = [0u8; 64];
        let key_blob_length = build_client_key_blob(&mut key_blob);
        write_ssh_string(out, offset, &key_blob[..key_blob_length])
    }

    fn emit_userauth_password(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let mut payload = [0u8; 256];
        payload[0] = SSH_MSG_USERAUTH_REQUEST;
        let mut offset = write_ssh_string(&mut payload, 1, self.username());
        offset = write_ssh_string(&mut payload, offset, b"ssh-connection");
        offset = write_ssh_string(&mut payload, offset, b"password");
        payload[offset] = 0; // boolean FALSE: not a change-password request
        offset += 1;
        offset = write_ssh_string(&mut payload, offset, self.password());
        self.send_encrypted(&payload[..offset], out, written);
        self.password_attempted = true;
        self.phase = SshClientPhase::AwaitUserauthReply;
        true
    }

    fn process_userauth_reply(&mut self) -> bool {
        let mut decrypted = [0u8; 4096];
        let length = match self.open_encrypted(&mut decrypted) {
            Some(length) => length,
            None => return false,
        };
        if length == 0 {
            return true;
        }
        self.apply_userauth_reply(decrypted[0]);
        true
    }

    fn apply_userauth_reply(&mut self, message: u8) {
        self.phase = match message {
            SSH_MSG_USERAUTH_SUCCESS => SshClientPhase::SendChannelOpen,
            SSH_MSG_USERAUTH_FAILURE if !self.password_attempted => {
                SshClientPhase::SendUserauthPassword
            }
            SSH_MSG_USERAUTH_FAILURE => SshClientPhase::Rejected,
            _ => self.phase,
        };
    }

    // ---- Channel phase ------------------------------------------------------

    fn emit_channel_open(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let mut payload = [0u8; 64];
        payload[0] = SSH_MSG_CHANNEL_OPEN;
        let mut offset = write_ssh_string(&mut payload, 1, b"session");
        offset = write_u32_at(&mut payload, offset, 0); // our channel id
        offset = write_u32_at(&mut payload, offset, 0x0010_0000); // initial window
        offset = write_u32_at(&mut payload, offset, 0x0000_8000); // max packet
        self.send_encrypted(&payload[..offset], out, written);
        self.phase = SshClientPhase::AwaitChannelConfirm;
        true
    }

    fn process_channel_confirm(&mut self) -> bool {
        let mut decrypted = [0u8; 4096];
        let length = match self.open_encrypted(&mut decrypted) {
            Some(length) => length,
            None => return false,
        };
        if length >= 9 && decrypted[0] == SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
            self.server_channel = read_u32(&decrypted[5..]); // their sender channel
            self.phase = SshClientPhase::SendChannelRequest;
        }
        true
    }

    fn emit_channel_request(&mut self, out: &mut [u8], written: &mut usize) -> bool {
        let mut payload = [0u8; 320];
        let offset = self.build_channel_request(&mut payload);
        self.send_encrypted(&payload[..offset], out, written);
        self.phase = SshClientPhase::AwaitChannelReply;
        true
    }

    /// byte(98) uint32(server_channel) string(type) TRUE [string(command)].
    /// `exec <command>` when a command was given, else an interactive `shell`.
    fn build_channel_request(&self, out: &mut [u8]) -> usize {
        out[0] = SSH_MSG_CHANNEL_REQUEST;
        let mut offset = write_u32_at(out, 1, self.server_channel);
        if self.command_length == 0 {
            offset = write_ssh_string(out, offset, b"shell");
            out[offset] = 1; // want_reply
            return offset + 1;
        }
        offset = write_ssh_string(out, offset, b"exec");
        out[offset] = 1; // want_reply
        offset += 1;
        write_ssh_string(out, offset, self.command())
    }

    fn process_channel_reply(&mut self) -> bool {
        let mut decrypted = [0u8; 4096];
        let length = match self.open_encrypted(&mut decrypted) {
            Some(length) => length,
            None => return false,
        };
        if length > 0 {
            self.apply_channel_reply(&decrypted[..length]);
        }
        true
    }

    fn apply_channel_reply(&mut self, payload: &[u8]) {
        match payload[0] {
            SSH_MSG_CHANNEL_SUCCESS => self.phase = SshClientPhase::Relay,
            SSH_MSG_CHANNEL_FAILURE => self.phase = SshClientPhase::Rejected,
            SSH_MSG_CHANNEL_DATA => {
                self.enqueue_channel_data(payload);
                self.phase = SshClientPhase::Relay;
            }
            _ => {}
        }
    }

    fn process_relay(&mut self) -> bool {
        let mut decrypted = [0u8; 4096];
        let length = match self.open_encrypted(&mut decrypted) {
            Some(length) => length,
            None => return false,
        };
        if length > 0 {
            self.handle_relay_message(&decrypted[..length]);
        }
        true
    }

    fn handle_relay_message(&mut self, payload: &[u8]) {
        match payload[0] {
            SSH_MSG_CHANNEL_DATA => self.enqueue_channel_data(payload),
            SSH_MSG_CHANNEL_CLOSE => self.phase = SshClientPhase::Closed,
            _ => {}
        }
    }

    /// CHANNEL_DATA = byte(94) uint32(recipient) string(data); enqueue the data.
    fn enqueue_channel_data(&mut self, payload: &[u8]) {
        if payload.len() < 5 {
            return;
        }
        let data = read_ssh_string(&payload[5..]);
        for &byte in data {
            let next_tail = (self.output_tail + 1) % OUTPUT_FIFO_SIZE;
            if next_tail == self.output_head {
                break; // output FIFO full
            }
            self.output_fifo[self.output_tail] = byte;
            self.output_tail = next_tail;
        }
    }

    /// Dequeues one byte of the remote channel's output, or None if empty.
    pub fn poll_received_output(&mut self) -> Option<u8> {
        if self.output_head == self.output_tail {
            return None;
        }
        let byte = self.output_fifo[self.output_head];
        self.output_head = (self.output_head + 1) % OUTPUT_FIFO_SIZE;
        Some(byte)
    }

    /// Sends local input `data` to the remote as CHANNEL_DATA (interactive use).
    /// Returns the number of bytes written to `out`.
    pub fn write_channel_data(&mut self, data: &[u8], out: &mut [u8]) -> usize {
        let mut message = [0u8; 512];
        message[0] = SSH_MSG_CHANNEL_DATA;
        let offset = write_u32_at(&mut message, 1, self.server_channel);
        let end = write_ssh_string(&mut message, offset, data);
        let mut written = 0;
        self.send_encrypted(&message[..end], out, &mut written);
        written
    }
}

/// Copies `source` into `destination` (truncating), returning the byte count.
fn copy_into(destination: &mut [u8], source: &[u8]) -> usize {
    let length = source.len().min(destination.len());
    destination[..length].copy_from_slice(&source[..length]);
    length
}

/// Writes a big-endian uint32 at `offset`, returning the new offset.
fn write_u32_at(out: &mut [u8], offset: usize, value: u32) -> usize {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    offset + 4
}

/// Builds the ssh-ed25519 client key blob: string("ssh-ed25519") string(pubkey).
fn build_client_key_blob(out: &mut [u8]) -> usize {
    let offset = write_ssh_string(out, 0, crypto::HOST_KEY_ALGORITHM_NAME);
    write_ssh_string(out, offset, &client_identity::client_public_key())
}

/// Prefixes `request_body` with string(session_id) to form the publickey
/// signing input (RFC 4252 §7). Returns the total length.
fn build_signing_blob(session_id: &[u8; 32], request_body: &[u8], out: &mut [u8]) -> usize {
    let offset = write_ssh_string(out, 0, session_id);
    out[offset..offset + request_body.len()].copy_from_slice(request_body);
    offset + request_body.len()
}

/// Appends string(signature-blob) to the request body to form the full
/// publickey USERAUTH_REQUEST payload. Returns the total length.
fn assemble_publickey_payload(request_body: &[u8], signature: &[u8; 64], out: &mut [u8]) -> usize {
    out[..request_body.len()].copy_from_slice(request_body);
    let mut signature_blob = [0u8; 128];
    let signature_blob_length = crypto::build_signature_blob(signature, &mut signature_blob);
    write_ssh_string(
        out,
        request_body.len(),
        &signature_blob[..signature_blob_length],
    )
}

#[cfg(test)]
mod tests {
    use super::{SshClientPhase, SshClientSession};
    use crate::ssh::crypto;
    use crate::ssh::packet::{parse_packet, SSH_MSG_KEXINIT, SSH_MSG_KEX_ECDH_INIT};
    use crate::ssh::{SshPhase, SshSession};

    const EPHEMERAL: [u8; 32] = [0x55u8; 32];
    const COOKIE: [u8; 16] = [0x42u8; 16];

    fn client_pinning(expected_host_key: [u8; 32]) -> SshClientSession {
        SshClientSession::new(
            EPHEMERAL,
            COOKIE,
            expected_host_key,
            b"root",
            b"brainxos",
            b"",
        )
    }

    fn accepts_root_brainxos(username: &[u8], password: &[u8]) -> bool {
        username == b"root" && password == b"brainxos"
    }

    #[test]
    fn test_client_emits_banner_then_kexinit_first() {
        let mut client = client_pinning([0u8; 32]);
        let mut out = [0u8; 1024];
        let written = client.advance(&mut out);
        assert!(out[..written].starts_with(b"SSH-2.0-"));
        // After the banner line, the next bytes are our KEXINIT binary packet.
        let newline = out[..written].iter().position(|&b| b == b'\n').unwrap();
        let parsed = parse_packet(&out[newline + 1..written]).unwrap();
        assert_eq!(out[newline + 1 + parsed.payload_start], SSH_MSG_KEXINIT);
        assert_eq!(client.phase(), SshClientPhase::AwaitServerBanner);
    }

    /// Builds a KEX_ECDH_REPLY for `client_public` from a server identity, signed
    /// with the given host seed, mirroring what a real server emits. Returns the
    /// exchange-hash-derived reply bytes (payload, unframed) and the host key.
    fn drive_to_relay(expected_host_key: [u8; 32]) -> (SshClientSession, SshSession) {
        let mut client = client_pinning(expected_host_key);
        let mut server = SshSession::new_with_verifier([0x66u8; 32], accepts_root_brainxos);
        ping_pong(&mut client, &mut server);
        (client, server)
    }

    /// Drives the client and the in-tree server to completion. The server does
    /// not emit its own banner (the bridge normally does), so we inject it.
    fn ping_pong(client: &mut SshClientSession, server: &mut SshSession) {
        let mut client_out = [0u8; 8192];
        let mut server_out = [0u8; 8192];
        let mut combined = [0u8; 8192];
        let client_n = client.advance(&mut client_out); // banner + KEXINIT
        let server_n = server.on_received(&client_out[..client_n], &mut server_out);
        let banner = SshSession::server_identification();
        combined[..banner.len()].copy_from_slice(banner);
        combined[banner.len()..banner.len() + server_n].copy_from_slice(&server_out[..server_n]);
        let mut client_n =
            client.on_received(&combined[..banner.len() + server_n], &mut client_out);
        for _ in 0..40 {
            let server_n = if client_n > 0 {
                server.on_received(&client_out[..client_n], &mut server_out)
            } else {
                0
            };
            client_n = if server_n > 0 {
                client.on_received(&server_out[..server_n], &mut client_out)
            } else {
                0
            };
            if client_n == 0 && server_n == 0 {
                break;
            }
        }
    }

    #[test]
    fn test_full_handshake_against_server_with_password_fallback() {
        // The in-tree server only implements password userauth, so the client's
        // publickey attempt is rejected and it falls back to password.
        let (client, server) = drive_to_relay(crypto::host_public_key());
        assert_eq!(client.phase(), SshClientPhase::Relay);
        assert_eq!(server.phase(), SshPhase::Authenticated);
        assert!(server.shell_active());
    }

    #[test]
    fn test_handshake_rejects_unpinned_host_key() {
        // Pin a key that is NOT the server's real host key -> pin check fails,
        // the client rejects before authenticating.
        let (client, _server) = drive_to_relay([0xAAu8; 32]);
        assert_eq!(client.phase(), SshClientPhase::Rejected);
    }

    #[test]
    fn test_ecdh_init_carries_client_public_key() {
        let mut client = client_pinning(crypto::host_public_key());
        let mut server = SshSession::new_with_verifier([0x66u8; 32], accepts_root_brainxos);
        let mut client_out = [0u8; 8192];
        let mut server_out = [0u8; 8192];
        let mut combined = [0u8; 8192];
        let client_n = client.advance(&mut client_out);
        let server_n = server.on_received(&client_out[..client_n], &mut server_out);
        let banner = SshSession::server_identification();
        combined[..banner.len()].copy_from_slice(banner);
        combined[banner.len()..banner.len() + server_n].copy_from_slice(&server_out[..server_n]);
        let written = client.on_received(&combined[..banner.len() + server_n], &mut client_out);
        // The client should have emitted KEX_ECDH_INIT carrying Q_C.
        let parsed = parse_packet(&client_out[..written]).unwrap();
        assert_eq!(client_out[parsed.payload_start], SSH_MSG_KEX_ECDH_INIT);
    }
}
