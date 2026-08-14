//! Admin verb dispatch: exactly six handlers, and nothing that is a shell
//! (P2-T14).
//!
//! The threat model is blunt about why this shape and not another:
//! **"'not a shell' is a security property, not an ergonomic one."** A
//! general-purpose remote shell can do whatever the process hosting it can do,
//! so its blast radius is not enumerable, which means it cannot be reviewed and
//! cannot be bounded. The enumerated set is what makes the compromise
//! *finite* — and the finiteness checkable by reading a compile-time table.
//!
//! So this module is a table. [`DISPATCH`] has six entries, a test counts them,
//! and there is no path from a decoded verb to anything that is not one of the
//! six.
//!
//! # What is absent, deliberately
//!
//! No command interpreter. No path or filename anywhere in the surface — the
//! weight blob does not travel over BSP, and `LoadWeights` names a *measured
//! digest*. No handler that adds, removes or widens a capability. And no
//! `rotate` verb: rotation is `EnrollKey` followed by `RevokeKey`, so it names
//! no authority the set does not already contain. A verb needing authority the
//! six do not cover requires a new named capability, never a widened
//! `CapAdmin`.
//!
//! # The two refusals that are not about the verb
//!
//! - **A client session reaches none of them.** The session type is decided at
//!   accept and frozen there, and [`dispatch`] takes it as an argument rather
//!   than reading it from the message, because a session type carried in the
//!   request is a session type the requester chooses.
//! - **The break-glass credential is refused unconditionally and
//!   non-configurably.** `INV-BOOT-008`: it is provisioned over the serial
//!   console and authenticates over serial alone, so a compromised admin
//!   session cannot lock the owner out. That refusal is not a policy the
//!   dispatcher consults; it is a branch nothing can turn off.

use brainix_bsp::{AdminVerb, RestartTarget, SessionType};

/// One entry of the compile-time handler table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handler {
    /// The verb this entry handles, by its wire tag.
    pub tag: u8,
    /// The verb's name, for the audit record and for a reader.
    pub name: &'static str,
    /// Whether the verb tears the serving stack down (§10.4).
    pub reboot_class: bool,
}

/// The six verbs, and there is no seventh.
///
/// `INV-AUTH-009` names them: enroll-key, revoke-key, load-weights,
/// read-audit-log, restart-server, reboot. The count is the security property.
pub const DISPATCH: [Handler; 6] = [
    Handler {
        tag: 0x11,
        name: "enroll-key",
        reboot_class: false,
    },
    Handler {
        tag: 0x12,
        name: "revoke-key",
        reboot_class: false,
    },
    Handler {
        tag: 0x13,
        // Reboot-class: it terminates every session including the one that
        // issued it, re-runs `modeld` against the newly named generation, and
        // relaunches `inferd`. A reload is a new generation, not a mutation,
        // and no sealed weights page is ever made writable again.
        name: "load-weights",
        reboot_class: true,
    },
    Handler {
        tag: 0x14,
        name: "read-audit-log",
        reboot_class: false,
    },
    Handler {
        tag: 0x15,
        name: "restart-server",
        reboot_class: false,
    },
    Handler {
        tag: 0x16,
        name: "reboot",
        reboot_class: true,
    },
];

/// Why a verb was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRefusal {
    /// The session does not hold `CapAdmin`.
    NotAnAdminSession,
    /// The verb targets the break-glass credential (`INV-BOOT-008`).
    BreakGlassHandle,
}

/// What the dispatcher decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accepted {
    /// The handler that will run.
    pub handler: Handler,
    /// Whether every session, including the caller's, is about to end.
    pub terminates_all_sessions: bool,
}

/// Routes a decoded verb, or refuses it.
///
/// `session_type` comes from the slot, never from the message. `break_glass`
/// is whether the verb's credential target is the break-glass handle, which the
/// caller resolves because only the credential store knows which handle that
/// is — and which this function refuses unconditionally when it is.
///
/// # Errors
///
/// [`AdminRefusal`], and every refusal is attributable: the caller emits one
/// audit event per outcome, refusals included.
pub const fn dispatch(
    verb: &AdminVerb,
    session_type: SessionType,
    break_glass: bool,
) -> Result<Accepted, AdminRefusal> {
    if !matches!(session_type, SessionType::Admin) {
        return Err(AdminRefusal::NotAnAdminSession);
    }

    let index = match verb {
        AdminVerb::EnrollKey { .. } => 0,
        AdminVerb::RevokeKey { .. } => 1,
        AdminVerb::LoadWeights { .. } => 2,
        AdminVerb::ReadAuditLog { .. } => 3,
        AdminVerb::RestartServer { .. } => 4,
        AdminVerb::Reboot { .. } => 5,
    };

    // Only the two credential verbs can name a handle, and neither may name
    // this one — unconditionally, and with no configuration that changes it.
    if break_glass && (index == 0 || index == 1) {
        return Err(AdminRefusal::BreakGlassHandle);
    }

    let handler = DISPATCH[index];
    Ok(Accepted {
        handler,
        terminates_all_sessions: handler.reboot_class,
    })
}

/// Whether a restart target is one the enumeration names.
///
/// `RestartServer` takes an **enumerated identity, never a name**, so this is a
/// total function over the enumeration rather than a lookup that could fail on
/// a string. It exists so the audit record can name the target without the
/// dispatcher ever handling one that is not in the list.
#[must_use]
pub const fn restart_target_name(target: RestartTarget) -> &'static str {
    match target {
        RestartTarget::Servd => "servd",
        RestartTarget::Inferd => "inferd",
        RestartTarget::Auditd => "auditd",
        RestartTarget::Gpud => "gpud",
    }
}
