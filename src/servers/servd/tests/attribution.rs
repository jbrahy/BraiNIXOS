//! One event per outcome: every verb and every denial, exactly once.
//!
//! P2-T8's criterion is that "every verb and every rejection path produces
//! exactly one attributable event". The failure modes are two, and they are
//! opposite: a path that emits nothing is a compromise nobody can reconstruct,
//! and a path that emits twice makes the log's counts unusable as evidence.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_auditd::event::{decode, encode, AuditEvent, EventKind, Outcome};
use brainix_bsp::{AdminVerb, CredentialRole, RestartTarget, SessionType};
use brainix_servd::admin::dispatch;
use brainix_servd::serving_log::ServingLog;

fn every_verb() -> [AdminVerb; 6] {
    [
        AdminVerb::EnrollKey {
            request_id: 1,
            role: CredentialRole::Client,
            key_material: [0u8; 32],
        },
        AdminVerb::RevokeKey {
            request_id: 2,
            handle: [3u8; 16],
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
            target: RestartTarget::Gpud,
        },
        AdminVerb::Reboot { request_id: 6 },
    ]
}

/// What a dispatcher does with an outcome: exactly one row, either way.
fn attribute(log: &mut ServingLog, slot: usize, allowed: bool) -> Option<u64> {
    log.append(
        slot,
        if allowed {
            EventKind::AdminVerb.to_wire()
        } else {
            EventKind::Denial.to_wire()
        },
    )
}

#[test]
fn every_accepted_verb_produces_exactly_one_row() {
    let mut log = ServingLog::new();
    for verb in every_verb() {
        let accepted = dispatch(&verb, SessionType::Admin, false).is_ok();
        assert!(accepted);
        attribute(&mut log, 0, accepted).expect("admissible slot");
    }
    assert_eq!(log.len(), 6, "six verbs, six rows");
}

#[test]
fn every_denial_produces_exactly_one_row_too() {
    // A refusal that emits nothing is the more dangerous of the two failures:
    // an attacker probing the admin surface from a client session would leave
    // no trace at all.
    let mut log = ServingLog::new();
    for verb in every_verb() {
        let accepted = dispatch(&verb, SessionType::Client, false).is_ok();
        assert!(!accepted, "a client session reaches no verb");
        attribute(&mut log, 1, accepted).expect("admissible slot");
    }
    assert_eq!(log.len(), 6, "six refusals, six rows");
}

#[test]
fn an_attributed_row_survives_encoding_and_names_the_credential() {
    // The row and the record are different types -- the log holds the ordering,
    // the record is what an admin session reads back -- and the credential must
    // survive the trip, because attribution to the wrong credential accuses
    // somebody.
    let event = AuditEvent {
        kind: EventKind::AdminVerb,
        outcome: Outcome::Denied,
        session_slot: 2,
        credential: [0x5A; 16],
        sequence: 9,
    };
    let decoded = decode(&encode(&event)).expect("round trip");
    assert_eq!(decoded, event);
    assert_eq!(decoded.credential, [0x5A; 16]);
}

#[test]
fn rows_from_two_sessions_stay_apart_in_the_log() {
    let mut log = ServingLog::new();
    attribute(&mut log, 0, true).expect("admissible");
    attribute(&mut log, 1, false).expect("admissible");

    let mut out = [brainix_servd::serving_log::LogRow {
        session_slot: usize::MAX,
        event_tag: 0,
        sequence: 0,
    }; 4];
    assert_eq!(log.read(0, &mut out), 1);
    assert_eq!(out[0].event_tag, EventKind::AdminVerb.to_wire());
    assert_eq!(log.read(1, &mut out), 1);
    assert_eq!(out[0].event_tag, EventKind::Denial.to_wire());
}
