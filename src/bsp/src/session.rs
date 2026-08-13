//! The §5.5 handshake state machine and the §10.2 request phase.
//!
//! This is the guard that decides **which message is legal in which state**. A
//! handshake message arriving mid-session denies; a request arriving pre-key
//! denies; a capability grant from anywhere but the one authenticated
//! transition denies.
//!
//! ```text
//!   WaitHello ──ClientHello──► WaitClientAuth ──ClientAuth──► AuthPending
//!                                                                  │
//!                                                    establish(role)│
//!                                                                  ▼
//!                                                            Established
//!                                                                  │
//!                                                            Close / Drop
//!                                                                  ▼
//!                                                              Closed
//! ```
//!
//! # What this machine does not decide
//!
//! `establish` takes the [`SessionType`] as an argument rather than reading it
//! from anywhere, because §7.1 is absolute: a session becomes admin **by the
//! credential and by nothing else**, and there is no wire field it could come
//! from (§5.1 has no session-type field). The caller reads `role` from the
//! credential record. A decoder that chose the session type would be the
//! ambient authority §7 exists to prevent.
//!
//! # Failure moves the machine
//!
//! Every denial whose §12 disposition is [`Disposition::Drop`] moves the
//! session to [`SessionState::Closed`], because that *is* the §12 action:
//! terminate the connection. A [`Disposition::ErrorKeep`] leaves the state
//! exactly as it was — no phase advances, no total accumulates, no request
//! opens. That is what "never advances session state on bad input" means, and
//! it is checkable here rather than asserted in prose.

use crate::admin::AdminVerb;
use crate::error::{BspError, Disposition};
use crate::handshake::{ClientAuth, ClientHello};
use crate::message::ClientRequest;
use crate::MAX_PROMPT_BYTES;

/// Which capability a session was granted at accept (§7.2). Frozen.
///
/// `CapAdmin` does not imply `CapServe`, and `CapServe` never derives
/// `CapAdmin`. A credential is one or the other, and neither can convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    /// `CapServe` for this slot: prompt in, tokens out. Nothing else.
    Client,
    /// `CapAdmin`: the six verbs of §10.4. Nothing outside them.
    Admin,
}

/// Where a session is in the §5.5 state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Awaiting exactly [`LEN_CLIENT_HELLO`](crate::LEN_CLIENT_HELLO) bytes.
    WaitHello,
    /// Awaiting exactly [`LEN_CLIENT_AUTH`](crate::LEN_CLIENT_AUTH) bytes.
    WaitClientAuth,
    /// `ClientAuth` decoded; its constant-time verification (row H5) and the
    /// §6.2 chain commit are the caller's, and neither has happened yet.
    AuthPending,
    /// Live. The capability is granted and frozen (§9.2, §9.3).
    Established,
    /// Torn down. Nothing is legal here (§9.4).
    Closed,
}

/// Where a client session is in the §10.2 request lifecycle.
///
/// [`MAX_INFLIGHT_PER_SESSION`](crate::MAX_INFLIGHT_PER_SESSION) is 1, and this
/// enum is how: there is exactly one place to put an open request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestPhase {
    /// No request open. The only phase in which `InferBegin` is legal.
    Idle,

    /// A request is open and prompt bytes are being reassembled.
    Collecting {
        /// The open request's inert correlation token.
        request_id: u32,
        /// The total the client declared at `InferBegin`.
        declared_length: u32,
        /// Bytes accepted so far. Never exceeds `declared_length` (row M8).
        accumulated_length: u32,
    },

    /// The prompt is committed and the model is streaming.
    Streaming {
        /// The streaming request's inert correlation token.
        request_id: u32,
    },
}

/// A decoded data-phase message, dispatched by the session's granted type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundMessage<'a> {
    /// A §10.2 message on a client session.
    Client(ClientRequest<'a>),
    /// A §10.4 verb on an admin session.
    Admin(AdminVerb),
}

/// One connection's protocol state.
///
/// Holds **no key material, no prompt buffer, and no slot index**. The session
/// slot, its `prompt_buf`, and its directional keys are `servd`'s (§9.1); the
/// slot index is server-internal and never appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Session {
    state: SessionState,
    session_type: Option<SessionType>,
    request: RequestPhase,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    /// A fresh session in [`SessionState::WaitHello`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SessionState::WaitHello,
            session_type: None,
            request: RequestPhase::Idle,
        }
    }

    /// The current handshake state.
    #[must_use]
    pub const fn state(self) -> SessionState {
        self.state
    }

    /// The granted capability, or `None` before `ESTABLISHED`.
    #[must_use]
    pub const fn session_type(self) -> Option<SessionType> {
        self.session_type
    }

    /// The current request phase.
    #[must_use]
    pub const fn request_phase(self) -> RequestPhase {
        self.request
    }

    /// Decodes a `ClientHello`, legal only in [`SessionState::WaitHello`].
    ///
    /// Enforces rows H1 and H2 and the §5.5 ordering. A `ClientHello` arriving
    /// mid-session is [`BspError::HandshakeMessageInWrongState`] and drops:
    /// there is no renegotiation in BSP and a second handshake on a live
    /// channel could only be an attempt to reset one.
    ///
    /// Verified by: `tests::state_machine::a_client_hello_mid_session_denies`
    pub fn accept_client_hello(&mut self, bytes: &[u8]) -> Result<ClientHello, BspError> {
        self.require_state(
            SessionState::WaitHello,
            BspError::HandshakeMessageInWrongState,
        )?;
        let hello = self.record(ClientHello::decode(bytes))?;
        self.state = SessionState::WaitClientAuth;
        Ok(hello)
    }

    /// Decodes a `ClientAuth`, legal only in
    /// [`SessionState::WaitClientAuth`].
    ///
    /// Enforces row H4. Reaching [`SessionState::AuthPending`] means the bytes
    /// were the right shape and **nothing more**: row H5's constant-time
    /// comparison has not run, no capability is granted, and no chain advance
    /// is committed.
    pub fn accept_client_auth(&mut self, bytes: &[u8]) -> Result<ClientAuth, BspError> {
        self.require_state(
            SessionState::WaitClientAuth,
            BspError::HandshakeMessageInWrongState,
        )?;
        let auth = self.record(ClientAuth::decode(bytes))?;
        self.state = SessionState::AuthPending;
        Ok(auth)
    }

    /// Grants the capability and enters `ESTABLISHED` (§7.2, §9.2).
    ///
    /// Legal **only** from [`SessionState::AuthPending`], which is only
    /// reachable by a `ClientAuth` that decoded in the right state. The caller
    /// asserts by calling this that row H5 passed and that §6.2's monotonic
    /// commit has been made.
    ///
    /// The grant is frozen here and BSP defines no message that widens it
    /// (`INV-AUTH-009`).
    ///
    /// Verified by: `tests::state_machine::establishing_before_client_auth_denies`
    pub fn establish(&mut self, session_type: SessionType) -> Result<(), BspError> {
        self.require_state(
            SessionState::AuthPending,
            BspError::EstablishBeforeAuthentication,
        )?;
        self.session_type = Some(session_type);
        self.state = SessionState::Established;
        Ok(())
    }

    /// Decodes one data-phase message and applies every state rule to it.
    ///
    /// Dispatches on the **granted** session type, which is what makes row M2
    /// structural: a `0x1X` tag never reaches an admin decoder on a client
    /// session, because the client decoder is the only one this session can
    /// call.
    ///
    /// Verified by: `tests::state_machine::a_request_before_the_keys_exist_denies`
    pub fn accept_message<'a>(
        &mut self,
        payload: &'a [u8],
    ) -> Result<InboundMessage<'a>, BspError> {
        self.require_established()?;
        match self.session_type {
            Some(SessionType::Client) => self.accept_client_request(payload),
            Some(SessionType::Admin) => self.accept_admin_verb(payload),
            // COVERAGE-EXEMPT: session_type is None only after close(), which also sets state to Closed, so require_established() above denies first. Defence in depth against a future state that clears the type without closing.
            None => Err(self.deny(BspError::DataMessageBeforeEstablished)),
        }
    }

    /// Decodes a §10.2 message and advances the request phase.
    fn accept_client_request<'a>(
        &mut self,
        payload: &'a [u8],
    ) -> Result<InboundMessage<'a>, BspError> {
        let request = self.record(ClientRequest::decode(payload))?;
        self.record(self.request.admit(&request))?;
        self.apply(&request);
        Ok(InboundMessage::Client(request))
    }

    /// Decodes a §10.4 verb. Admin sessions have no reassembly phase: §8 bounds
    /// in-flight *inference*, and inventing an in-flight rule for verbs would
    /// be adding a bound the specification does not state.
    fn accept_admin_verb<'a>(&mut self, payload: &'a [u8]) -> Result<InboundMessage<'a>, BspError> {
        let verb = self.record(AdminVerb::decode(payload))?;
        Ok(InboundMessage::Admin(verb))
    }

    /// Applies an admitted message's phase transition.
    fn apply(&mut self, request: &ClientRequest<'_>) {
        match self.request.next(request) {
            Some(phase) => self.request = phase,
            None => self.close(),
        }
    }

    /// Tears the session down (§9.4). Idempotent and reachable from every
    /// non-`Closed` state.
    ///
    /// Zeroizing keys, `prompt_buf`, and the KV region, and returning the slot,
    /// are `servd`'s: this type holds none of them. What it does hold is
    /// reset, so no residue of the request phase survives.
    pub fn close(&mut self) {
        self.state = SessionState::Closed;
        self.session_type = None;
        self.request = RequestPhase::Idle;
    }

    /// Denies unless the session is in `expected`.
    fn require_state(&mut self, expected: SessionState, reason: BspError) -> Result<(), BspError> {
        if self.state == expected {
            return Ok(());
        }
        Err(self.deny(reason))
    }

    /// Denies unless the session is `ESTABLISHED`.
    fn require_established(&mut self) -> Result<(), BspError> {
        match self.state {
            SessionState::Established => Ok(()),
            SessionState::Closed => Err(self.deny(BspError::SessionClosed)),
            _ => Err(self.deny(BspError::DataMessageBeforeEstablished)),
        }
    }

    /// Applies the §12 disposition of a failure and returns it unchanged.
    fn deny(&mut self, reason: BspError) -> BspError {
        if reason.disposition() == Disposition::Drop {
            self.close();
        }
        reason
    }

    /// Applies [`Session::deny`] to a failed result, leaving success alone.
    fn record<T>(&mut self, outcome: Result<T, BspError>) -> Result<T, BspError> {
        match outcome {
            Ok(value) => Ok(value),
            Err(reason) => Err(self.deny(reason)),
        }
    }
}

impl RequestPhase {
    /// Decides whether `request` is legal in this phase — rows M6 to M10.
    ///
    /// Pure: it changes nothing and is independently testable against every
    /// (phase, message) pair, which is what the state-machine test walks.
    fn admit(self, request: &ClientRequest<'_>) -> Result<(), BspError> {
        match request {
            ClientRequest::InferBegin(_) => self.admit_begin(),
            ClientRequest::PromptChunk { request_id, chunk } => {
                self.admit_chunk(*request_id, chunk.len())
            }
            ClientRequest::InferCommit { request_id } => self.admit_commit(*request_id),
            ClientRequest::Cancel { request_id } => self.admit_cancel(*request_id),
            ClientRequest::Close => Ok(()),
        }
    }

    /// Row M6 — a second `InferBegin` while a request is in flight.
    fn admit_begin(self) -> Result<(), BspError> {
        if self == Self::Idle {
            return Ok(());
        }
        Err(BspError::RequestAlreadyInFlight)
    }

    /// Rows M7 and M8 — the open request, then the two reassembly bounds.
    fn admit_chunk(self, request_id: u32, chunk_length: usize) -> Result<(), BspError> {
        let (open_id, declared, accumulated) = self.collecting()?;
        require_matching_request_id(open_id, request_id)?;
        let total = accumulated
            .checked_add(u32::try_from(chunk_length).map_err(|_| BspError::OffsetOverflow)?)
            .ok_or(BspError::PromptChunkExceedsPromptBuffer)?;
        check_running_total(total, declared)
    }

    /// Rows M7 and M9 — the open request, then the exact-length commit check.
    fn admit_commit(self, request_id: u32) -> Result<(), BspError> {
        let (open_id, declared, accumulated) = self.collecting()?;
        require_matching_request_id(open_id, request_id)?;
        if accumulated != declared {
            return Err(BspError::PromptIncomplete);
        }
        Ok(())
    }

    /// Row M7 — `Cancel` is legal while collecting or streaming, and names the
    /// request it cancels.
    fn admit_cancel(self, request_id: u32) -> Result<(), BspError> {
        let open_id = match self {
            Self::Collecting {
                request_id: open, ..
            }
            | Self::Streaming { request_id: open } => open,
            Self::Idle => return Err(BspError::MessageInvalidInState),
        };
        require_matching_request_id(open_id, request_id)
    }

    /// The reassembly triple, or row M10 if no prompt is being collected.
    fn collecting(self) -> Result<(u32, u32, u32), BspError> {
        match self {
            Self::Collecting {
                request_id,
                declared_length,
                accumulated_length,
            } => Ok((request_id, declared_length, accumulated_length)),
            Self::Idle | Self::Streaming { .. } => Err(BspError::MessageInvalidInState),
        }
    }

    /// The phase an **already admitted** message moves to, or `None` when the
    /// message ends the session.
    fn next(self, request: &ClientRequest<'_>) -> Option<Self> {
        match request {
            ClientRequest::InferBegin(begin) => Some(Self::Collecting {
                request_id: begin.request_id,
                declared_length: begin.prompt_total_length,
                accumulated_length: 0,
            }),
            ClientRequest::PromptChunk { chunk, .. } => self.accumulate(chunk.len()),
            ClientRequest::InferCommit { request_id } => Some(Self::Streaming {
                request_id: *request_id,
            }),
            ClientRequest::Cancel { .. } => Some(Self::Idle),
            ClientRequest::Close => None,
        }
    }

    /// Adds an admitted chunk to the running total.
    ///
    /// The addition is checked and cannot have overflowed, because
    /// [`RequestPhase::admit_chunk`] already formed and bounded the same sum;
    /// it is checked again rather than assumed, because "a previous function
    /// checked it" is exactly the reasoning that fails when a caller is added.
    fn accumulate(self, chunk_length: usize) -> Option<Self> {
        let (request_id, declared_length, accumulated) = self.collecting().ok()?;
        let added = u32::try_from(chunk_length).ok()?;
        Some(Self::Collecting {
            request_id,
            declared_length,
            accumulated_length: accumulated.checked_add(added)?,
        })
    }
}

/// Row M7 — the only comparison `request_id` ever participates in.
///
/// Enforces `INV-SERVE-001`: the comparison is scoped to one slot, so a
/// duplicate or garbage value cannot reach another session.
fn require_matching_request_id(open_id: u32, offered: u32) -> Result<(), BspError> {
    if open_id == offered {
        return Ok(());
    }
    Err(BspError::RequestIdMismatch)
}

/// Row M8 — the running total against the declared length and the buffer.
///
/// Both bounds are checked. The buffer bound is implied by the declared bound
/// today, and is kept because the cap is the buffer size, never `len`.
fn check_running_total(total: u32, declared: u32) -> Result<(), BspError> {
    if total > declared {
        return Err(BspError::PromptChunkExceedsDeclaredLength);
    }
    if total > MAX_PROMPT_BYTES {
        // COVERAGE-EXEMPT: unreachable today and the comment above says why: the declared-length bound is tighter than the buffer bound, so it always denies first. Kept because the cap is the buffer size, never `len`.
        return Err(BspError::PromptChunkExceedsPromptBuffer);
    }
    Ok(())
}
