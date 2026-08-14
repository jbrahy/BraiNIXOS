//! The audit record: fixed size, total encoding, fail-closed decoding.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_auditd::event::{
    decode, encode, AuditEvent, EventKind, Outcome, RecordError, CREDENTIAL_HANDLE_LEN, RECORD_LEN,
};

const EVERY_KIND: [EventKind; 6] = [
    EventKind::SessionAccepted,
    EventKind::Authentication,
    EventKind::CapabilityGranted,
    EventKind::AdminVerb,
    EventKind::SessionTeardown,
    EventKind::Denial,
];

fn event(kind: EventKind, outcome: Outcome) -> AuditEvent {
    AuditEvent {
        kind,
        outcome,
        session_slot: 3,
        credential: [0xAB; CREDENTIAL_HANDLE_LEN],
        sequence: 0x0102_0304,
    }
}

#[test]
fn every_event_encodes_to_the_same_number_of_bytes() {
    // INV-AUD-003: the cost of an event is a constant, so the log is sized by
    // count alone and no client's input is a term in it.
    for kind in EVERY_KIND {
        for outcome in [Outcome::Allowed, Outcome::Denied] {
            assert_eq!(encode(&event(kind, outcome)).len(), RECORD_LEN);
        }
    }
}

#[test]
fn every_event_round_trips() {
    for kind in EVERY_KIND {
        for outcome in [Outcome::Allowed, Outcome::Denied] {
            let original = event(kind, outcome);
            let decoded = decode(&encode(&original)).expect("a record we encoded decodes");
            assert_eq!(decoded, original);
        }
    }
}

#[test]
fn a_record_of_the_wrong_length_is_refused() {
    let record = encode(&event(EventKind::Denial, Outcome::Denied));
    assert_eq!(
        decode(&record[..RECORD_LEN - 1]),
        Err(RecordError::WrongLength)
    );
    assert_eq!(decode(&[]), Err(RecordError::WrongLength));

    let mut too_long = [0u8; RECORD_LEN + 1];
    too_long[..RECORD_LEN].copy_from_slice(&record);
    assert_eq!(decode(&too_long), Err(RecordError::WrongLength));
}

#[test]
fn an_unknown_discriminant_is_refused_rather_than_guessed_at() {
    // An audit log that invents the events it could not read is worse than one
    // with a gap in it.
    let mut record = encode(&event(EventKind::AdminVerb, Outcome::Allowed));
    record[0] = 0;
    assert_eq!(decode(&record), Err(RecordError::UnknownKind));
    record[0] = 7;
    assert_eq!(decode(&record), Err(RecordError::UnknownKind));

    let mut record = encode(&event(EventKind::AdminVerb, Outcome::Allowed));
    record[1] = 0;
    assert_eq!(decode(&record), Err(RecordError::UnknownOutcome));
    record[1] = 3;
    assert_eq!(decode(&record), Err(RecordError::UnknownOutcome));
}

#[test]
fn the_discriminants_round_trip_and_reject_everything_else() {
    for kind in EVERY_KIND {
        assert_eq!(EventKind::from_wire(kind.to_wire()), Some(kind));
    }
    for outcome in [Outcome::Allowed, Outcome::Denied] {
        assert_eq!(Outcome::from_wire(outcome.to_wire()), Some(outcome));
    }
    for value in 0u8..=255 {
        let known_kind = EVERY_KIND.iter().any(|kind| kind.to_wire() == value);
        assert_eq!(EventKind::from_wire(value).is_some(), known_kind);
        let known_outcome = value == 1 || value == 2;
        assert_eq!(Outcome::from_wire(value).is_some(), known_outcome);
    }
}

#[test]
fn the_record_carries_the_credential_handle_and_the_sequence_verbatim() {
    let mut original = event(EventKind::Authentication, Outcome::Denied);
    original.credential = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    original.sequence = u32::MAX;
    original.session_slot = 7;

    let decoded = decode(&encode(&original)).expect("round trip");
    assert_eq!(decoded.credential, original.credential);
    assert_eq!(decoded.sequence, u32::MAX);
    assert_eq!(decoded.session_slot, 7);
}
