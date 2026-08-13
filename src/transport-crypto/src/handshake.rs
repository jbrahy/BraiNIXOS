//! §5.5 — the cryptographic half of the handshake state machine.
//!
//! ```text
//!  WAIT_HELLO ──ClientHello──► scan (§5.3) ──► break-glass? ──► admission (servd)
//!                                                                     │
//!                              resolve chain into scratch (§6.3) ◄────┘
//!                                     │
//!                              derive PRK_session, both confirms, K_c2s, K_s2c
//!                              send ServerHello
//!                                     │
//!  WAIT_CLIENTAUTH ──ClientAuth──► constant-time compare (row H5)
//!                                     │ fail → Drop, no chain commit
//!                              commit the ratchet (§6.2)
//!                                     │
//!                                ESTABLISHED
//! ```
//!
//! **The order is normative and two placements are load-bearing** (§5.5). The
//! break-glass check sits immediately after the match, so no later step can be
//! reached with that credential. Chain resolution sits **after** admission
//! control, so the only unauthenticated work a peer can force before
//! `MAX_SESSIONS_PER_CREDENTIAL` applies is the fixed selector scan.
//!
//! That second placement is why [`ServerHandshake`] splits identification from
//! derivation: [`ServerHandshake::identify`] runs the scan and stops, and
//! [`ServerHandshake::derive`] resolves the chain. `servd` owns the session
//! pool, so admission happens between the two calls, in the caller — which is
//! the only place it *can* happen without this crate owning a pool it has no
//! business owning.
//!
//! # Structure is P2-T3's
//!
//! Every message is decoded by `brainix-bsp`, never re-parsed here. The server
//! side additionally drives a [`brainix_bsp::Session`], so the state guards of
//! rows H1, H2, and H4 and the "message arrived in the wrong state" rules are
//! enforced once, by the decoder, rather than twice with two chances to
//! disagree.
//!
//! # What a failure does
//!
//! Every failure in this module is §12 **Drop**. On the client-confirm
//! mismatch of row H5 the handshake zeroizes its derived material and its
//! scratch chain and **commits no chain advance** — §6.2's difference between a
//! ratchet and a remote kill switch.

use brainix_bsp::{
    ClientHello, CredentialRole, ServerHello, Session, SessionType, LEN_CLIENT_HELLO, LEN_CONFIRM,
    LEN_HANDLE, LEN_NONCE, LEN_SELECTOR, LEN_SERVER_HELLO,
};

use crate::credential::{Credential, CredentialTable, MatchedCredential};
use crate::error::TransportCryptoError;
use crate::ratchet::{ChainState, ScratchChain};
use crate::record::{RecordOpener, RecordSealer};
use crate::schedule::{SessionSecrets, Side, LEN_TRANSCRIPT};

/// Byte offsets of the `ClientHello` fields (§5.1), used only by the client's
/// encoder below.
mod hello_offsets {
    /// `magic`.
    pub const MAGIC: usize = 0;
    /// `version_major`.
    pub const VERSION_MAJOR: usize = 4;
    /// `version_minor`.
    pub const VERSION_MINOR: usize = 5;
    /// `reserved`, two bytes.
    pub const RESERVED: usize = 6;
    /// `chain_counter`, eight bytes.
    pub const CHAIN_COUNTER: usize = 8;
    /// `client_nonce`, 32 bytes.
    pub const CLIENT_NONCE: usize = 16;
    /// `key_selector`, 16 bytes.
    pub const KEY_SELECTOR: usize = 48;
}

/// A live session's record channels and its audit identity.
///
/// Produced only by a handshake that authenticated. There is no constructor
/// that skips the confirmation checks, which is what makes "no session exists
/// without mutual proof of possession" a property of the type rather than of
/// the call order.
pub struct EstablishedSession {
    /// Seals outbound records.
    pub sealer: RecordSealer,
    /// Opens inbound records.
    pub opener: RecordOpener,
    /// `session_id = TH_2` — audit correlation only, never on the wire (§5.4).
    pub session_id: [u8; LEN_TRANSCRIPT],
    /// The credential handle that authenticated this session.
    pub handle: [u8; LEN_HANDLE],
    /// The granted role, frozen at accept (§7.2).
    pub role: CredentialRole,
}

impl EstablishedSession {
    /// §9.4 teardown: destroys both directions' keys and the `session_id`.
    pub fn zeroize(&mut self) {
        self.sealer.zeroize();
        self.opener.zeroize();
        self.session_id.fill(0);
    }
}

/// Where the server's cryptographic half is in §5.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerPhase {
    /// Nothing received.
    WaitHello,
    /// The `ClientHello` decoded and a credential matched; admission is the
    /// caller's, and the chain has not been resolved.
    Identified,
    /// `ServerHello` sent; awaiting `ClientAuth`.
    WaitClientAuth,
    /// Authenticated, or dead. Either way this handshake accepts nothing more.
    Finished,
}

/// The server's handshake — the hostile-input side.
pub struct ServerHandshake {
    session: Session,
    phase: ServerPhase,
    client_hello: [u8; LEN_CLIENT_HELLO],
    declared_counter: u64,
    matched: Option<MatchedCredential>,
    scratch: Option<ScratchChain>,
    secrets: Option<SessionSecrets>,
}

impl Default for ServerHandshake {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerHandshake {
    /// A handshake in `WAIT_HELLO`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: Session::new(),
            phase: ServerPhase::WaitHello,
            client_hello: [0u8; LEN_CLIENT_HELLO],
            declared_counter: 0,
            matched: None,
            scratch: None,
            secrets: None,
        }
    }

    /// The slot the §5.3 scan matched. Server-internal, never on the wire.
    #[must_use]
    pub fn matched_slot(&self) -> Option<usize> {
        self.matched.as_ref().map(|matched| matched.slot)
    }

    /// Decodes a `ClientHello` and runs the §5.3 constant-work scan.
    ///
    /// Stops there. Admission control (§9.1, rows S1–S2) belongs to `servd`
    /// and runs between this call and [`ServerHandshake::derive`], because
    /// §5.5 puts the up-to-`MAX_CHAIN_CATCHUP` advances behind it.
    pub fn identify(
        &mut self,
        bytes: &[u8],
        table: &CredentialTable,
    ) -> Result<MatchedCredential, TransportCryptoError> {
        self.require_phase(ServerPhase::WaitHello)?;
        let hello = self.session.accept_client_hello(bytes)?;
        self.record_hello(bytes, &hello)?;
        let matched = table.scan(&hello)?;
        self.phase = ServerPhase::Identified;
        Ok(matched)
    }

    /// Resolves the chain into scratch, derives the §5.4 schedule, and returns
    /// the `ServerHello` bytes to send.
    ///
    /// Nothing is committed: §6.2 makes the persisted advance conditional on
    /// `client_confirm` verifying, so an unauthenticated peer replaying a
    /// captured `ClientHello` cannot move the server's chain at all.
    ///
    /// `server_nonce` MUST come from the kernel CSPRNG after entropy
    /// initialization (`INV-BOOT-005`). §5.6c: **server nonce freshness is the
    /// one assumption replay resistance rests on**, and a serving path that
    /// cannot prove entropy is available MUST refuse connections rather than
    /// emit a weak nonce (`INV-FAIL-003`). This crate cannot check that; it is
    /// stated at the parameter that carries the obligation.
    pub fn derive(
        &mut self,
        matched: MatchedCredential,
        server_nonce: &[u8; LEN_NONCE],
    ) -> Result<[u8; LEN_SERVER_HELLO], TransportCryptoError> {
        self.require_phase(ServerPhase::Identified)?;
        let scratch = self.resolve_chain(&matched)?;
        let secrets = SessionSecrets::derive(
            scratch.key(),
            matched.role,
            &self.client_hello,
            server_nonce,
        );
        let wire = encode_server_hello(server_nonce, secrets.server_confirm().expose())?;
        self.matched = Some(matched);
        self.scratch = Some(scratch);
        self.secrets = Some(secrets);
        self.phase = ServerPhase::WaitClientAuth;
        Ok(wire)
    }

    /// Row H5 — verifies `client_confirm` in constant time, and only then
    /// commits the ratchet (§6.2) and establishes the session.
    ///
    /// A mismatch destroys every derived value and every scratch chain key and
    /// returns [`TransportCryptoError::AuthenticationFailed`], which is the
    /// same variant a forged record returns. No chain advance is committed.
    pub fn accept_client_auth(
        &mut self,
        bytes: &[u8],
        table: &mut CredentialTable,
    ) -> Result<EstablishedSession, TransportCryptoError> {
        self.require_phase(ServerPhase::WaitClientAuth)?;
        let auth = self.session.accept_client_auth(bytes)?;
        let verified = self.confirm_matches(&auth.client_confirm);
        if !verified {
            self.abort();
            return Err(TransportCryptoError::AuthenticationFailed);
        }
        self.commit_chain(table);
        self.establish()
    }

    /// Destroys every secret this handshake holds — teardown from any state.
    pub fn abort(&mut self) {
        if let Some(secrets) = self.secrets.as_mut() {
            secrets.zeroize();
        }
        self.secrets = None;
        self.scratch = None;
        self.matched = None;
        self.client_hello.fill(0);
        self.phase = ServerPhase::Finished;
        self.session.close();
    }

    /// Keeps the verbatim 64-byte image the transcript hashes are taken over.
    fn record_hello(
        &mut self,
        bytes: &[u8],
        hello: &ClientHello,
    ) -> Result<(), TransportCryptoError> {
        let image = bytes
            .get(..LEN_CLIENT_HELLO)
            .ok_or(TransportCryptoError::WrongState)?;
        self.client_hello.copy_from_slice(image);
        self.declared_counter = hello.chain_counter;
        Ok(())
    }

    /// §6.3 — rows K3 and K4, into scratch.
    fn resolve_chain(
        &self,
        matched: &MatchedCredential,
    ) -> Result<ScratchChain, TransportCryptoError> {
        let persisted = ChainState::at(matched.chain_key.clone(), matched.chain_counter);
        persisted.resolve(self.declared_counter)
    }

    /// The constant-time comparison of row H5.
    fn confirm_matches(&self, received: &[u8; LEN_CONFIRM]) -> bool {
        self.secrets
            .as_ref()
            .is_some_and(|secrets| secrets.client_confirm().ct_eq_bytes(received))
    }

    /// §6.2's monotonic compare-and-swap, run only after row H5 passed.
    fn commit_chain(&mut self, table: &mut CredentialTable) {
        let (Some(scratch), Some(matched)) = (self.scratch.take(), self.matched.as_ref()) else {
            // COVERAGE-EXEMPT: commit_chain is called only after row H5 passed, which is exactly the condition that leaves scratch and matched populated.
            return;
        };
        if let Some(slot) = table.slot_mut(matched.slot) {
            let _committed = slot.chain_mut().commit(scratch);
        }
    }

    /// Turns the derived material into record channels and marks the P2-T3
    /// session `ESTABLISHED`.
    fn establish(&mut self) -> Result<EstablishedSession, TransportCryptoError> {
        let (Some(secrets), Some(matched)) = (self.secrets.take(), self.matched.take()) else {
            // COVERAGE-EXEMPT: establish() runs only after accept_client_auth has confirmed row H5, which requires both secrets and matched to be Some. Defence in depth against a future path that reaches establish earlier.
            return Err(TransportCryptoError::WrongState);
        };
        let role = CredentialRole::from_wire(matched.role)?;
        self.session.establish(session_type(role))?;
        self.phase = ServerPhase::Finished;
        Ok(assemble(secrets, Side::Server, matched.handle, role))
    }

    /// The cryptographic half's own state guard.
    fn require_phase(&self, expected: ServerPhase) -> Result<(), TransportCryptoError> {
        if self.phase == expected {
            return Ok(());
        }
        Err(TransportCryptoError::WrongState)
    }
}

/// Where the client's half is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientPhase {
    /// `ClientHello` sent; awaiting `ServerHello`.
    WaitServerHello,
    /// Authenticated, or aborted.
    Finished,
}

/// The client's handshake — the mirror of §5.5.
///
/// §5.5: "Client side is the mirror: derive the selector, send `ClientHello`;
/// on `ServerHello`, derive `PRK_session` and compare `server_confirm`
/// constant-time; on success advance its own chain (§6.3), send `ClientAuth`,
/// and treat the session as live; on any mismatch abort without sending
/// anything further."
pub struct ClientHandshake {
    phase: ClientPhase,
    client_hello: [u8; LEN_CLIENT_HELLO],
    role: CredentialRole,
    scratch: Option<ScratchChain>,
}

impl ClientHandshake {
    /// Derives the selector and produces the 64-byte `ClientHello`.
    ///
    /// `client_nonce` MUST be 32 fresh CSPRNG bytes: §5.6c makes the client's
    /// nonce the freshness that stops a recorded `ServerHello` being replayed
    /// at it.
    #[must_use]
    pub fn start(
        credential: &Credential,
        client_nonce: &[u8; LEN_NONCE],
    ) -> (Self, [u8; LEN_CLIENT_HELLO]) {
        let counter = credential.chain_counter();
        let selector = credential.candidate_selector(counter, client_nonce);
        let wire = encode_client_hello(counter, client_nonce, selector.expose());
        let handshake = Self {
            phase: ClientPhase::WaitServerHello,
            client_hello: wire,
            role: credential.role(),
            scratch: Some(credential.scratch()),
        };
        (handshake, wire)
    }

    /// Row H6 — verifies `server_confirm` in constant time.
    ///
    /// On success the client advances **its own** chain (§6.3: "The client
    /// commits its advance when it accepts `server_confirm`") and returns the
    /// 32-byte `ClientAuth` to send. On mismatch it aborts and sends nothing
    /// further, with the same indistinguishable
    /// [`TransportCryptoError::AuthenticationFailed`].
    pub fn accept_server_hello(
        &mut self,
        bytes: &[u8],
        credential: &mut Credential,
    ) -> Result<([u8; LEN_CONFIRM], EstablishedSession), TransportCryptoError> {
        if self.phase != ClientPhase::WaitServerHello {
            return Err(TransportCryptoError::WrongState);
        }
        let hello = ServerHello::decode(bytes)?;
        let secrets = self.derive_from(&hello)?;
        if !secrets.server_confirm().ct_eq_bytes(&hello.server_confirm) {
            self.abort();
            return Err(TransportCryptoError::AuthenticationFailed);
        }
        self.commit_chain(credential.chain_mut());
        let confirm = *secrets.client_confirm().expose();
        self.phase = ClientPhase::Finished;
        let handle = *credential.handle();
        Ok((confirm, assemble(secrets, Side::Client, handle, self.role)))
    }

    /// Destroys the scratch chain material — abort from any state.
    pub fn abort(&mut self) {
        self.scratch = None;
        self.client_hello.fill(0);
        self.phase = ClientPhase::Finished;
    }

    /// §5.4 over the client's own chain position.
    ///
    /// Denies rather than substituting a placeholder key if the scratch is
    /// gone: deriving a session under an all-zero chain key would be a
    /// fallback, and §6.4 forbids fallbacks absolutely.
    fn derive_from(&self, hello: &ServerHello) -> Result<SessionSecrets, TransportCryptoError> {
        let scratch = self
            .scratch
            .as_ref()
            .ok_or(TransportCryptoError::WrongState)?;
        Ok(SessionSecrets::derive(
            scratch.key(),
            self.role.to_wire(),
            &self.client_hello,
            &hello.server_nonce,
        ))
    }

    /// The client's own §6.2 commit.
    fn commit_chain(&mut self, chain: &mut ChainState) {
        if let Some(scratch) = self.scratch.take() {
            let _committed = chain.commit(scratch);
        }
    }
}

/// Builds the record channels for `side` and packages the audit identity.
fn assemble(
    secrets: SessionSecrets,
    side: Side,
    handle: [u8; LEN_HANDLE],
    role: CredentialRole,
) -> EstablishedSession {
    let session_id = *secrets.session_id();
    let (seal_keys, open_keys) = secrets.into_direction_keys(side);
    EstablishedSession {
        sealer: RecordSealer::new(seal_keys),
        opener: RecordOpener::new(open_keys),
        session_id,
        handle,
        role,
    }
}

/// The capability grant a role implies (§7.1).
const fn session_type(role: CredentialRole) -> SessionType {
    match role {
        CredentialRole::Client => SessionType::Client,
        CredentialRole::Admin => SessionType::Admin,
    }
}

/// Encodes a `ServerHello` through the P2-T3 encoder.
fn encode_server_hello(
    server_nonce: &[u8; LEN_NONCE],
    server_confirm: &[u8; LEN_CONFIRM],
) -> Result<[u8; LEN_SERVER_HELLO], TransportCryptoError> {
    let mut wire = [0u8; LEN_SERVER_HELLO];
    let hello = ServerHello {
        server_nonce: *server_nonce,
        server_confirm: *server_confirm,
    };
    hello.encode(&mut wire)?;
    Ok(wire)
}

/// Encodes a `ClientHello` at the §5.1 offsets.
///
/// **This is the one byte layout this crate writes itself**, because P2-T3
/// encodes only what the *server* sends and BSP's server never sends a
/// `ClientHello`. `a_client_hello_this_crate_encodes_decodes_back_identically`
/// pins the two representations together, so the encoder cannot drift from the
/// decoder that P2-T3 owns.
fn encode_client_hello(
    chain_counter: u64,
    client_nonce: &[u8; LEN_NONCE],
    key_selector: &[u8; LEN_SELECTOR],
) -> [u8; LEN_CLIENT_HELLO] {
    use hello_offsets as at;
    let mut wire = [0u8; LEN_CLIENT_HELLO];
    write_at(&mut wire, at::MAGIC, &brainix_bsp::BSP_MAGIC);
    write_at(
        &mut wire,
        at::VERSION_MAJOR,
        &[brainix_bsp::BSP_VERSION_MAJOR],
    );
    write_at(
        &mut wire,
        at::VERSION_MINOR,
        &[brainix_bsp::BSP_VERSION_MINOR],
    );
    write_at(
        &mut wire,
        at::RESERVED,
        &brainix_bsp::BSP_RESERVED.to_be_bytes(),
    );
    write_at(&mut wire, at::CHAIN_COUNTER, &chain_counter.to_be_bytes());
    write_at(&mut wire, at::CLIENT_NONCE, client_nonce);
    write_at(&mut wire, at::KEY_SELECTOR, key_selector);
    wire
}

/// Writes `value` at `offset`, or does nothing if it would not fit — total by
/// construction, so no offset can panic.
fn write_at(wire: &mut [u8; LEN_CLIENT_HELLO], offset: usize, value: &[u8]) {
    let end = offset.saturating_add(value.len());
    if let Some(destination) = wire.get_mut(offset..end) {
        destination.copy_from_slice(value);
    }
}
