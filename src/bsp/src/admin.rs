//! The six admin verbs (§10.4), and nothing else.
//!
//! **The set is frozen at exactly six and is a compile-time enumeration.** No
//! verb dispatches to a command interpreter, names a filesystem path, or grants
//! a capability (`INV-AUTH-009`). There is deliberately no `rotate` — rotation
//! is `enroll-key` followed by `revoke-key`, so it names no authority the
//! frozen set does not already contain (§7.3) — and no `set-config`,
//! `read-file`, `write-file`, or `exec`.
//!
//! [`AdminVerb`] having six variants **is** that guarantee: a seventh verb is a
//! source change to this enum, visible in a diff, not a value an input can
//! reach. An unrecognized tag denies (row M1); it is never ignored.
//!
//! # What this module refuses to know
//!
//! The break-glass refusals of row A4 are **not here**. `EnrollKey` and
//! `RevokeKey` compare against the break-glass handle unconditionally and
//! non-configurably (`INV-BOOT-008`), and the handle is a credential-store
//! fact, not a wire fact — for `EnrollKey` it is not even present in the
//! message, since §10.4 derives it from the supplied key material. A decoder
//! that claimed to enforce A4 would be claiming a control it cannot perform.

use crate::error::BspError;
use crate::message::{decode_request_id_only, require_tag_range, split_tag, TagRange};
use crate::raw::FieldReader;
use crate::{LEN_HANDLE, LEN_PSK, LEN_WEIGHTS_DIGEST, MAX_AUDIT_RECORDS};

/// `EnrollKey` (§10.4).
pub(crate) const TAG_ENROLL_KEY: u8 = 0x11;

/// `RevokeKey` (§10.4).
pub(crate) const TAG_REVOKE_KEY: u8 = 0x12;

/// `LoadWeights` (§10.4).
pub(crate) const TAG_LOAD_WEIGHTS: u8 = 0x13;

/// `ReadAuditLog` (§10.4).
pub(crate) const TAG_READ_AUDIT_LOG: u8 = 0x14;

/// `RestartServer` (§10.4).
pub(crate) const TAG_RESTART_SERVER: u8 = 0x15;

/// `Reboot` (§10.4).
pub(crate) const TAG_REBOOT: u8 = 0x16;

/// The `role` a credential is enrolled with (§2.2, §10.4).
///
/// `role` is bound into all three §5.2 expansions, so a credential enrolled as
/// a client can never produce the identification or chain material of an admin
/// credential even if a caller later passes the wrong role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialRole {
    /// `0x01` — grants `CapServe` for the session it authenticates.
    Client,
    /// `0x02` — grants `CapAdmin`, the six verbs and nothing outside them.
    Admin,
}

impl CredentialRole {
    /// Wire value for [`CredentialRole::Client`].
    pub const WIRE_CLIENT: u8 = 0x01;

    /// Wire value for [`CredentialRole::Admin`].
    pub const WIRE_ADMIN: u8 = 0x02;

    /// Decodes `EnrollKey`'s `role` byte — row A1.
    ///
    /// Any value outside `{0x01, 0x02}` is a **Drop**: an out-of-range
    /// authority byte is not a benign mistake. Past this boundary the role is a
    /// Rust enum, so an unrecognized one is not merely refused — it is
    /// unrepresentable.
    pub const fn from_wire(value: u8) -> Result<Self, BspError> {
        match value {
            Self::WIRE_CLIENT => Ok(Self::Client),
            Self::WIRE_ADMIN => Ok(Self::Admin),
            _ => Err(BspError::InvalidEnrollRole),
        }
    }

    /// The wire value this role is written as.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Client => Self::WIRE_CLIENT,
            Self::Admin => Self::WIRE_ADMIN,
        }
    }
}

/// `RestartServer`'s enumerated target (§10.4).
///
/// **An enumerated server identity, not a name and not a path.** Restart
/// re-launches the target with its existing frozen manifest and mints nothing
/// (`INV-FAIL-002`).
///
/// **Spec reading.** §10.4 names the four identities and assigns them no
/// numeric values. The wire values below are this crate's, in the order the
/// specification lists them, and are **1-based** to match the only other
/// enumerated authority byte the protocol defines — `role`, where `0x00` is
/// likewise not a value. `0x00` is therefore not "unspecified" or "default": it
/// is the value a client that never read §10.4 sends, and it denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartTarget {
    /// The serving transport terminator.
    Servd,
    /// The confined inference tenant.
    Inferd,
    /// The audit sink.
    Auditd,
    /// The GPU driver.
    Gpud,
}

impl RestartTarget {
    /// Provisional wire value for [`RestartTarget::Servd`].
    pub const WIRE_SERVD: u8 = 0x01;

    /// Provisional wire value for [`RestartTarget::Inferd`].
    pub const WIRE_INFERD: u8 = 0x02;

    /// Provisional wire value for [`RestartTarget::Auditd`].
    pub const WIRE_AUDITD: u8 = 0x03;

    /// Provisional wire value for [`RestartTarget::Gpud`].
    pub const WIRE_GPUD: u8 = 0x04;

    /// Decodes `RestartServer`'s `target` byte — row A6.
    ///
    /// Unlike row A1 this is `Error`-then-continue: §12 treats an unknown
    /// restart target as a benign mistake, because unlike `role` it grants no
    /// authority.
    pub const fn from_wire(value: u8) -> Result<Self, BspError> {
        match value {
            Self::WIRE_SERVD => Ok(Self::Servd),
            Self::WIRE_INFERD => Ok(Self::Inferd),
            Self::WIRE_AUDITD => Ok(Self::Auditd),
            Self::WIRE_GPUD => Ok(Self::Gpud),
            _ => Err(BspError::UnknownRestartTarget),
        }
    }

    /// The wire value this target is written as.
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::Servd => Self::WIRE_SERVD,
            Self::Inferd => Self::WIRE_INFERD,
            Self::Auditd => Self::WIRE_AUDITD,
            Self::Gpud => Self::WIRE_GPUD,
        }
    }
}

/// A decoded admin verb. **Exactly six, frozen (§10.4).**
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminVerb {
    /// `0x11` — enroll a credential from 32 bytes of caller-supplied material.
    EnrollKey {
        /// The peer's inert correlation token.
        request_id: u32,
        /// `client` or `admin`; row A1 already refused anything else.
        role: CredentialRole,
        /// **Secret.** Destroying it after the §5.2 expansion is the caller's
        /// obligation (§10.4); this crate never learns when that is done and so
        /// cannot zeroize it for them.
        key_material: [u8; LEN_PSK],
    },

    /// `0x12` — revoke the credential with this handle.
    RevokeKey {
        /// The peer's inert correlation token.
        request_id: u32,
        /// The non-secret administrative handle `KeyEnrolled` returned.
        handle: [u8; LEN_HANDLE],
    },

    /// `0x13` — activate the weight generation with this measured digest.
    ///
    /// **Reboot-class, not a hot swap** (§10.4): it terminates every session
    /// including the one that issued it, so the reply is best-effort and a
    /// caller must not depend on receiving it. The blob is **not carried over
    /// BSP** — this verb names a digest, never a path and never a byte stream.
    LoadWeights {
        /// The peer's inert correlation token.
        request_id: u32,
        /// The exact measured digest to activate.
        weights_digest: [u8; LEN_WEIGHTS_DIGEST],
    },

    /// `0x14` — read audit records. Read-only; reading grants no authority.
    ReadAuditLog {
        /// The peer's inert correlation token.
        request_id: u32,
        /// Opaque resume position from a previous `AuditChunk`.
        cursor: u64,
        /// Bounded by [`MAX_AUDIT_RECORDS`](crate::MAX_AUDIT_RECORDS) — row A7.
        max_records: u16,
    },

    /// `0x15` — restart one enumerated server with its existing manifest.
    RestartServer {
        /// The peer's inert correlation token.
        request_id: u32,
        /// An enumerated identity, never a name and never a path.
        target: RestartTarget,
    },

    /// `0x16` — reboot the machine. The admin session is torn down first.
    Reboot {
        /// The peer's inert correlation token.
        request_id: u32,
    },
}

impl AdminVerb {
    /// Decodes one admin-session inbound message from a record payload.
    ///
    /// Order: range before value, as in [`ClientRequest::decode`]. A `0x0X` tag
    /// here is row M2 — the client-session range on an admin session — and is a
    /// Drop, because `CapServe` never derives `CapAdmin` and the reverse
    /// confusion must not be a recoverable hiccup either.
    ///
    /// [`ClientRequest::decode`]: crate::ClientRequest::decode
    ///
    /// Verified by: `tests::adversarial::an_unrecognized_admin_verb_tag_denies`
    pub fn decode(payload: &[u8]) -> Result<Self, BspError> {
        let (tag, body) = split_tag(payload)?;
        require_tag_range(tag, TagRange::AdminInbound)?;
        Self::dispatch(tag, body)
    }

    /// Dispatches on the tag. **Six arms and a denial.** An unrecognized value
    /// in the admin range denies (row M1); it is never ignored.
    fn dispatch(tag: u8, body: &[u8]) -> Result<Self, BspError> {
        match tag {
            TAG_ENROLL_KEY => Self::decode_enroll_key(body),
            TAG_REVOKE_KEY => Self::decode_revoke_key(body),
            TAG_LOAD_WEIGHTS => Self::decode_load_weights(body),
            TAG_READ_AUDIT_LOG => Self::decode_read_audit_log(body),
            TAG_RESTART_SERVER => Self::decode_restart_server(body),
            TAG_REBOOT => Ok(Self::Reboot {
                request_id: decode_request_id_only(body)?,
            }),
            _ => Err(BspError::UnknownMessageType),
        }
    }

    /// `request_id[4]`, `role[1]`, `key_material[32]`.
    fn decode_enroll_key(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let role = CredentialRole::from_wire(reader.take_u8()?)?;
        let key_material = reader.take_array()?;
        reader.finish()?;
        Ok(Self::EnrollKey {
            request_id,
            role,
            key_material,
        })
    }

    /// `request_id[4]`, `handle[16]`.
    fn decode_revoke_key(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let handle = reader.take_array()?;
        reader.finish()?;
        Ok(Self::RevokeKey { request_id, handle })
    }

    /// `request_id[4]`, `weights_digest[32]`.
    fn decode_load_weights(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let weights_digest = reader.take_array()?;
        reader.finish()?;
        Ok(Self::LoadWeights {
            request_id,
            weights_digest,
        })
    }

    /// `request_id[4]`, `cursor[8]`, `max_records[2]`, then row A7.
    fn decode_read_audit_log(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let cursor = reader.take_u64()?;
        let max_records = reader.take_u16()?;
        reader.finish()?;
        Self::admit_audit_request(request_id, cursor, max_records)
    }

    /// Row A7 — `max_records ≤ MAX_AUDIT_RECORDS`, else `Error{ERR_LIMIT}`.
    fn admit_audit_request(
        request_id: u32,
        cursor: u64,
        max_records: u16,
    ) -> Result<Self, BspError> {
        if max_records > MAX_AUDIT_RECORDS {
            return Err(BspError::AuditRecordCountExceedsLimit);
        }
        Ok(Self::ReadAuditLog {
            request_id,
            cursor,
            max_records,
        })
    }

    /// `request_id[4]`, `target[1]`.
    fn decode_restart_server(body: &[u8]) -> Result<Self, BspError> {
        let mut reader = FieldReader::new(body);
        let request_id = reader.take_u32()?;
        let target = RestartTarget::from_wire(reader.take_u8()?)?;
        reader.finish()?;
        Ok(Self::RestartServer { request_id, target })
    }

    /// The `request_id` this verb correlates with. Every verb carries one.
    #[must_use]
    pub const fn request_id(&self) -> u32 {
        match self {
            Self::EnrollKey { request_id, .. }
            | Self::RevokeKey { request_id, .. }
            | Self::LoadWeights { request_id, .. }
            | Self::ReadAuditLog { request_id, .. }
            | Self::RestartServer { request_id, .. }
            | Self::Reboot { request_id } => *request_id,
        }
    }
}
