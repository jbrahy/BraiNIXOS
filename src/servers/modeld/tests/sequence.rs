//! The §10.1 stage order, driven every way it should refuse.
//!
//! "The order is normative" is the sentence under test. A machine that accepts
//! S2 before S1 accepts validating bytes that are not the bytes that will be
//! used, which is the time-of-check/time-of-use gap §10.1 exists to close.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_modeld::{DenialDuty, LoadSequence, SequenceError, SequenceState, Stage};

const EVERY_STAGE: [Stage; 12] = [
    Stage::S0ObtainLength,
    Stage::S1CopyIntoRegion,
    Stage::S2ValidateHeader,
    Stage::S3TableExtent,
    Stage::S4TableDigest,
    Stage::S5ValidateRecords,
    Stage::S6RequiredNames,
    Stage::S7PayloadPass,
    Stage::S8DigestAndSignature,
    Stage::S9TokenizerBlob,
    Stage::S10Seal,
    Stage::S11AuditAndExit,
];

#[test]
fn a_load_starts_at_s0_and_ends_exited() {
    let mut sequence = LoadSequence::new();
    assert_eq!(
        sequence.state(),
        SequenceState::Awaiting(Stage::S0ObtainLength)
    );
    assert!(!sequence.has_exited());

    for stage in EVERY_STAGE {
        sequence.complete(stage).expect("stages run in order");
    }

    assert_eq!(sequence.state(), SequenceState::Exited);
    assert!(sequence.has_exited());
}

#[test]
fn the_default_sequence_is_a_new_one() {
    assert_eq!(LoadSequence::default(), LoadSequence::new());
}

#[test]
fn no_stage_may_be_skipped() {
    // Every prefix of the sequence, followed by a jump over the stage that is
    // actually due. Each jump must be refused and must name what was expected.
    for (position, due) in EVERY_STAGE.iter().enumerate() {
        let mut sequence = LoadSequence::new();
        for earlier in &EVERY_STAGE[..position] {
            sequence.complete(*earlier).expect("in order");
        }
        for later in &EVERY_STAGE[position.saturating_add(1)..] {
            assert_eq!(
                sequence.complete(*later),
                Err(SequenceError::OutOfOrder { expected: *due }),
                "skipping from {due:?} to {later:?} must be refused"
            );
        }
    }
}

#[test]
fn a_stage_may_not_be_repeated() {
    let mut sequence = LoadSequence::new();
    sequence.complete(Stage::S0ObtainLength).expect("in order");
    assert_eq!(
        sequence.complete(Stage::S0ObtainLength),
        Err(SequenceError::OutOfOrder {
            expected: Stage::S1CopyIntoRegion
        })
    );
}

#[test]
fn s0_denies_without_touching_the_region_and_every_later_stage_zeroizes() {
    for (position, stage) in EVERY_STAGE.iter().enumerate() {
        if !stage.can_deny() {
            continue;
        }
        let mut sequence = LoadSequence::new();
        for earlier in &EVERY_STAGE[..position] {
            sequence.complete(*earlier).expect("in order");
        }

        let duty = sequence.deny().expect("this stage may deny");
        let expected = if *stage == Stage::S0ObtainLength {
            // Nothing has been written yet. Zeroizing would be a write through
            // the writable-weights capability for no reason.
            DenialDuty::NoCopy
        } else {
            // From S1 the region holds bytes an attacker supplied.
            DenialDuty::Zeroize
        };
        assert_eq!(duty, expected, "denial duty at {stage:?}");
        assert_eq!(
            sequence.state(),
            SequenceState::Denied {
                stage: *stage,
                duty: expected
            }
        );
    }
}

#[test]
fn the_seal_and_the_audit_event_have_no_failure_path() {
    // §10.1's table has no "on failure" column for S10 or S11: by then the
    // bytes are verified and what remains is a kernel seal and an event.
    for stage in [Stage::S10Seal, Stage::S11AuditAndExit] {
        assert!(!stage.can_deny());

        let mut sequence = LoadSequence::new();
        for earlier in EVERY_STAGE.iter().take_while(|s| **s != stage) {
            sequence.complete(*earlier).expect("in order");
        }
        assert_eq!(
            sequence.deny(),
            Err(SequenceError::OutOfOrder { expected: stage })
        );
    }
}

#[test]
fn a_denied_load_never_resumes() {
    let mut sequence = LoadSequence::new();
    sequence.complete(Stage::S0ObtainLength).expect("in order");
    sequence.deny().expect("S1 may deny");

    // §10.5 makes a reload a new generation, not a continuation, so there is no
    // path from Denied back into the sequence.
    assert_eq!(
        sequence.complete(Stage::S1CopyIntoRegion),
        Err(SequenceError::AlreadyDenied)
    );
    assert_eq!(sequence.deny(), Err(SequenceError::AlreadyDenied));
    assert!(!sequence.has_exited());
}

#[test]
fn an_exited_loader_accepts_nothing_further() {
    let mut sequence = LoadSequence::new();
    for stage in EVERY_STAGE {
        sequence.complete(stage).expect("in order");
    }

    assert_eq!(
        sequence.complete(Stage::S11AuditAndExit),
        Err(SequenceError::AlreadyFinished)
    );
    assert_eq!(sequence.deny(), Err(SequenceError::AlreadyFinished));
}

#[test]
fn the_stage_chain_visits_every_stage_once_and_stops() {
    let mut stage = Stage::S0ObtainLength;
    let mut visited = 1;
    while let Some(next) = stage.next() {
        assert!(next > stage, "the chain must move forward");
        stage = next;
        visited += 1;
    }
    assert_eq!(stage, Stage::S11AuditAndExit);
    assert_eq!(visited, EVERY_STAGE.len());
    assert_eq!(Stage::S11AuditAndExit.next(), None);
}
