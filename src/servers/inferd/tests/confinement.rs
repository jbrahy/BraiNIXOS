//! `INV-MODEL-001`, as arithmetic rather than as a diff someone reads.
//!
//! The invariant's stated evidence is "manifest audit; the diff must show zero
//! capabilities beyond the three". These tests are that audit, run every time
//! rather than every time someone remembers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_bsp::MAX_SESSIONS;
use brainix_inferd::{teardown, BindingError, KvBinding, FORBIDDEN_SUBJECTS, MANIFEST};

#[test]
fn the_manifest_holds_exactly_three_capabilities() {
    assert_eq!(MANIFEST.len(), 3);
}

#[test]
fn the_manifest_names_none_of_the_authorities_the_invariant_withholds() {
    // "Not spawn. Not kernel mutation. Not network. Not another session." --
    // and not storage, which is modeld's precisely so it is not inferd's.
    for entry in &MANIFEST {
        let subject = entry.subject.to_ascii_lowercase();
        for forbidden in FORBIDDEN_SUBJECTS {
            assert!(
                !subject.contains(forbidden),
                "{} names the forbidden authority {forbidden}",
                entry.subject
            );
        }
    }
}

#[test]
fn every_capability_says_why_the_tenant_cannot_serve_without_it() {
    // A manifest entry with no justification is one nobody can argue against
    // when a fourth is proposed.
    for entry in &MANIFEST {
        assert!(!entry.subject.is_empty());
        assert!(!entry.because.is_empty(), "{} has no reason", entry.subject);
    }
}

#[test]
fn the_serving_endpoint_is_the_only_channel_named() {
    let endpoints = MANIFEST
        .iter()
        .filter(|entry| entry.subject.contains("CapEndpoint"))
        .count();
    assert_eq!(endpoints, 1, "a second channel is a second way out");
}

#[test]
fn a_session_binds_to_its_own_partition_and_no_other() {
    for slot in 0..MAX_SESSIONS {
        let binding = KvBinding::for_session(slot).expect("a slot servd can admit");
        assert_eq!(binding.session_slot(), slot);
        assert_eq!(binding.partition_index(), slot);

        for other_slot in 0..MAX_SESSIONS {
            let other = KvBinding::for_session(other_slot).expect("admissible");
            assert_eq!(
                binding.shares_partition_with(&other),
                slot == other_slot,
                "slots {slot} and {other_slot} share a partition only when they are the same slot"
            );
        }
    }
}

#[test]
fn a_slot_the_server_cannot_admit_denies_rather_than_clamping() {
    assert_eq!(
        KvBinding::for_session(MAX_SESSIONS),
        Err(BindingError::NoSuchSession)
    );
    assert_eq!(
        KvBinding::for_session(usize::MAX),
        Err(BindingError::NoSuchSession)
    );
    // Clamping would bind the tenant to the last partition, which belongs to a
    // different client. The boundary itself resolves.
    assert!(KvBinding::for_session(MAX_SESSIONS - 1).is_ok());
}

#[test]
fn teardown_owes_the_partition_the_session_actually_held() {
    for slot in 0..MAX_SESSIONS {
        let binding = KvBinding::for_session(slot).expect("admissible");
        let duty = teardown(binding);
        assert_eq!(duty.partition_index, slot);
    }
}

#[test]
fn there_is_no_way_to_name_a_partition_without_a_session() {
    // This test is a statement about the API surface rather than about a value:
    // `KvBinding` has no constructor taking a partition index, so there is no
    // call that could be handed another client's. If one is ever added, this
    // comment is the thing that should have stopped it.
    let binding = KvBinding::for_session(0).expect("admissible");
    assert_eq!(binding.partition_index(), binding.session_slot());
}
