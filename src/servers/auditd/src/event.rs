//! The serving-event record: fixed size, and with nowhere to put a secret.
//!
//! P2-T8 subscribes `auditd` to the serving path's events. `INV-AUD-001`
//! wants them attributable, `INV-AUD-003` wants audit pressure bounded, and the
//! serving spec is explicit about what a record may carry: the credential
//! handle and the session id, and **never** key material, prompt bytes, or
//! token bytes.
//!
//! # The redaction is the type, not a function
//!
//! A record that carried a `&[u8]` payload would need a rule saying what may go
//! in it, and a rule is something an implementation can get wrong on one path
//! out of twenty. [`AuditEvent`] has no such field. There is no byte slice, no
//! buffer, and no length — so there is no path, correct or otherwise, by which
//! a prompt or a token or a key reaches the audit log. That is the difference
//! between redacting and having nothing to redact.
//!
//! # Fixed size is the bound
//!
//! `INV-AUD-003` is that audit generation cannot destabilize the system through
//! unbounded backpressure. Every record encodes to exactly [`RECORD_LEN`]
//! bytes, whatever the event, so the cost of an event is a constant and the log
//! is sized by *count* alone. An event whose size depended on its content would
//! make a client's prompt length a term in the audit subsystem's memory
//! footprint.

/// Bytes in one encoded audit record.
///
/// 1 kind + 1 outcome + 1 session + 16 credential handle + 4 sequence = 23.
pub const RECORD_LEN: usize = 23;

/// Bytes in a credential handle, matching the protocol's `LEN_HANDLE`.
pub const CREDENTIAL_HANDLE_LEN: usize = 16;

/// What happened. One discriminant per event the serving path attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// A connection was accepted into a session slot.
    SessionAccepted,
    /// Authentication succeeded or failed for a session.
    Authentication,
    /// A capability was granted at session establishment.
    CapabilityGranted,
    /// An admin verb was invoked.
    AdminVerb,
    /// A session was torn down.
    SessionTeardown,
    /// A request was denied.
    Denial,
}

impl EventKind {
    /// The wire discriminant.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::SessionAccepted => 1,
            Self::Authentication => 2,
            Self::CapabilityGranted => 3,
            Self::AdminVerb => 4,
            Self::SessionTeardown => 5,
            Self::Denial => 6,
        }
    }

    /// The kind for a wire discriminant.
    ///
    /// # Errors
    ///
    /// `None` for any value outside the enumeration — an unknown kind is a
    /// record this build does not understand, and guessing at one would put a
    /// fiction in the audit log.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::SessionAccepted),
            2 => Some(Self::Authentication),
            3 => Some(Self::CapabilityGranted),
            4 => Some(Self::AdminVerb),
            5 => Some(Self::SessionTeardown),
            6 => Some(Self::Denial),
            _ => None,
        }
    }
}

/// Whether the attributed action succeeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The action was permitted and completed.
    Allowed,
    /// The action was refused.
    Denied,
}

impl Outcome {
    /// The wire discriminant.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Allowed => 1,
            Self::Denied => 2,
        }
    }

    /// The outcome for a wire discriminant.
    ///
    /// # Errors
    ///
    /// `None` for anything else. There is no third outcome, and a record
    /// claiming one is not a record about this system.
    #[must_use]
    pub const fn from_wire(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Allowed),
            2 => Some(Self::Denied),
            _ => None,
        }
    }
}

/// One attributable serving event.
///
/// Everything it can hold is here, and none of it is secret: which credential,
/// which session slot, what happened, whether it was allowed, and a sequence
/// number for ordering. **There is no payload field**, by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    /// What happened.
    pub kind: EventKind,
    /// Whether it was permitted.
    pub outcome: Outcome,
    /// The session slot it happened in. Server-internal, never wire-addressable.
    pub session_slot: u8,
    /// The credential that authenticated the session — a handle, not a key.
    pub credential: [u8; CREDENTIAL_HANDLE_LEN],
    /// Monotonic ordering within the log.
    pub sequence: u32,
}

/// Why a record did not decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordError {
    /// The buffer is not exactly [`RECORD_LEN`] bytes.
    WrongLength,
    /// The kind discriminant names no event this build knows.
    UnknownKind,
    /// The outcome discriminant names neither allowed nor denied.
    UnknownOutcome,
}

/// Encodes an event into exactly [`RECORD_LEN`] bytes.
///
/// Total: there is no event this can refuse, because every field is a fixed
/// width and none of them is attacker-sized.
#[must_use]
pub fn encode(event: &AuditEvent) -> [u8; RECORD_LEN] {
    let mut record = [0u8; RECORD_LEN];
    record[0] = event.kind.to_wire();
    record[1] = event.outcome.to_wire();
    record[2] = event.session_slot;
    let credential_end = 3usize.saturating_add(CREDENTIAL_HANDLE_LEN);
    if let Some(slice) = record.get_mut(3..credential_end) {
        slice.copy_from_slice(&event.credential);
    }
    let sequence = event.sequence.to_le_bytes();
    if let Some(slice) = record.get_mut(credential_end..RECORD_LEN) {
        slice.copy_from_slice(&sequence);
    }
    record
}

/// Decodes a record, or refuses it.
///
/// # Errors
///
/// [`RecordError`] for a wrong length or an unknown discriminant. Fail closed:
/// a record that does not decode is dropped, never guessed at, because an audit
/// log that invents the events it could not read is worse than one with a gap.
pub fn decode(bytes: &[u8]) -> Result<AuditEvent, RecordError> {
    if bytes.len() != RECORD_LEN {
        return Err(RecordError::WrongLength);
    }
    let kind = bytes
        .first()
        .and_then(|value| EventKind::from_wire(*value))
        .ok_or(RecordError::UnknownKind)?;
    let outcome = bytes
        .get(1)
        .and_then(|value| Outcome::from_wire(*value))
        .ok_or(RecordError::UnknownOutcome)?;
    let session_slot = *bytes.get(2).ok_or(RecordError::WrongLength)?;

    let credential_end = 3usize.saturating_add(CREDENTIAL_HANDLE_LEN);
    let credential_bytes = bytes
        .get(3..credential_end)
        .ok_or(RecordError::WrongLength)?;
    let credential: [u8; CREDENTIAL_HANDLE_LEN] = credential_bytes
        .try_into()
        .map_err(|_| RecordError::WrongLength)?;

    let sequence_bytes = bytes
        .get(credential_end..RECORD_LEN)
        .ok_or(RecordError::WrongLength)?;
    let sequence_array: [u8; 4] = sequence_bytes
        .try_into()
        .map_err(|_| RecordError::WrongLength)?;

    Ok(AuditEvent {
        kind,
        outcome,
        session_slot,
        credential,
        sequence: u32::from_le_bytes(sequence_array),
    })
}
