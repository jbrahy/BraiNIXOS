//! Six handlers, and no seventh: the admin surface as a countable table.
//!
//! "Not a shell" is the security property. A general-purpose remote shell's
//! blast radius is not enumerable, so it cannot be reviewed; the enumerated set
//! is what makes the compromise finite and the finiteness checkable.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::{AdminVerb, CredentialRole, RestartTarget, SessionType};
use brainix_servd::admin::{dispatch, restart_target_name, AdminRefusal, DISPATCH};

fn every_verb() -> [AdminVerb; 6] {
    [
        AdminVerb::EnrollKey {
            request_id: 1,
            role: CredentialRole::Client,
            key_material: [0u8; 32],
        },
        AdminVerb::RevokeKey {
            request_id: 2,
            handle: [0u8; 16],
        },
        AdminVerb::LoadWeights {
            request_id: 3,
            weights_digest: [0u8; 32],
        },
        AdminVerb::ReadAuditLog {
            request_id: 4,
            cursor: 0,
            max_records: 1,
        },
        AdminVerb::RestartServer {
            request_id: 5,
            target: RestartTarget::Inferd,
        },
        AdminVerb::Reboot { request_id: 6 },
    ]
}

#[test]
fn the_table_holds_exactly_six_handlers_and_no_rotate() {
    assert_eq!(DISPATCH.len(), 6);
    for handler in &DISPATCH {
        assert_ne!(handler.name, "rotate", "rotation is enroll-then-revoke");
    }
    let names: [&str; 6] = [
        "enroll-key",
        "revoke-key",
        "load-weights",
        "read-audit-log",
        "restart-server",
        "reboot",
    ];
    for (handler, expected) in DISPATCH.iter().zip(names) {
        assert_eq!(handler.name, expected);
    }
}

#[test]
fn every_verb_dispatches_from_an_admin_session() {
    for verb in every_verb() {
        assert!(
            dispatch(&verb, SessionType::Admin, false).is_ok(),
            "an admin session must reach every verb"
        );
    }
}

#[test]
fn a_client_session_reaches_none_of_them() {
    // The session type comes from the slot, never from the message: a type
    // carried in the request is a type the requester chooses.
    for verb in every_verb() {
        assert_eq!(
            dispatch(&verb, SessionType::Client, false),
            Err(AdminRefusal::NotAnAdminSession)
        );
    }
}

#[test]
fn the_break_glass_handle_is_refused_by_both_credential_verbs() {
    // INV-BOOT-008: provisioned over serial, authenticates over serial alone,
    // so a compromised admin session cannot lock the owner out.
    let enroll = AdminVerb::EnrollKey {
        request_id: 1,
        role: CredentialRole::Admin,
        key_material: [7u8; 32],
    };
    let revoke = AdminVerb::RevokeKey {
        request_id: 2,
        handle: [7u8; 16],
    };
    assert_eq!(
        dispatch(&enroll, SessionType::Admin, true),
        Err(AdminRefusal::BreakGlassHandle)
    );
    assert_eq!(
        dispatch(&revoke, SessionType::Admin, true),
        Err(AdminRefusal::BreakGlassHandle)
    );
}

#[test]
fn a_break_glass_target_does_not_block_the_verbs_that_name_no_handle() {
    // Only the credential verbs can name a handle. The refusal must not become
    // a blanket condition that quietly disables the other four.
    for verb in [
        AdminVerb::LoadWeights {
            request_id: 3,
            weights_digest: [0u8; 32],
        },
        AdminVerb::ReadAuditLog {
            request_id: 4,
            cursor: 0,
            max_records: 1,
        },
        AdminVerb::RestartServer {
            request_id: 5,
            target: RestartTarget::Servd,
        },
        AdminVerb::Reboot { request_id: 6 },
    ] {
        assert!(dispatch(&verb, SessionType::Admin, true).is_ok());
    }
}

#[test]
fn load_weights_and_reboot_are_the_reboot_class_verbs() {
    // A reload is a new generation, not a mutation: it terminates every
    // session including the one that issued it. A test asserting a session
    // survives it would be asserting a hot swap, which §10.4 forbids.
    let load = dispatch(
        &AdminVerb::LoadWeights {
            request_id: 3,
            weights_digest: [0u8; 32],
        },
        SessionType::Admin,
        false,
    )
    .expect("admin");
    assert!(load.terminates_all_sessions);

    let reboot = dispatch(
        &AdminVerb::Reboot { request_id: 6 },
        SessionType::Admin,
        false,
    )
    .expect("admin");
    assert!(reboot.terminates_all_sessions);

    // And the other four do not.
    for verb in [
        AdminVerb::EnrollKey {
            request_id: 1,
            role: CredentialRole::Client,
            key_material: [0u8; 32],
        },
        AdminVerb::RevokeKey {
            request_id: 2,
            handle: [1u8; 16],
        },
        AdminVerb::ReadAuditLog {
            request_id: 4,
            cursor: 0,
            max_records: 1,
        },
        AdminVerb::RestartServer {
            request_id: 5,
            target: RestartTarget::Auditd,
        },
    ] {
        let accepted = dispatch(&verb, SessionType::Admin, false).expect("admin");
        assert!(
            !accepted.terminates_all_sessions,
            "{}",
            accepted.handler.name
        );
    }
}

#[test]
fn every_restart_target_is_an_enumerated_identity_with_a_name() {
    // Never a name on the wire, always a name in the audit record.
    for (target, expected) in [
        (RestartTarget::Servd, "servd"),
        (RestartTarget::Inferd, "inferd"),
        (RestartTarget::Auditd, "auditd"),
        (RestartTarget::Gpud, "gpud"),
    ] {
        assert_eq!(restart_target_name(target), expected);
    }
}

#[test]
fn no_handler_name_suggests_a_path_a_file_or_an_interpreter() {
    // There is no path or filename anywhere in the surface: the weight blob
    // does not travel over BSP, and LoadWeights names a measured digest.
    for handler in &DISPATCH {
        for forbidden in ["exec", "shell", "file", "path", "run", "eval"] {
            assert!(
                !handler.name.contains(forbidden),
                "{} suggests {forbidden}",
                handler.name
            );
        }
    }
}
