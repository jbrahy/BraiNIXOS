//! The manifest, whose entire content is the number three.
//!
//! `INV-MODEL-001` is a count. The rejected design for the weight loader was a
//! *fourth* capability on `inferd`, and the reason this component exists at all
//! is to keep that number where it is. A test that counts is therefore not
//! bookkeeping; it is the invariant.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cognitive_complexity)]

use brainix_modeld::{writable_capability_count, Stage, MANIFEST};

#[test]
fn the_manifest_holds_exactly_three_capabilities() {
    assert_eq!(MANIFEST.len(), 3);
}

#[test]
fn exactly_one_capability_is_writable_and_it_is_the_weights_region() {
    assert_eq!(writable_capability_count(), 1);

    let writable = MANIFEST
        .iter()
        .find(|entry| entry.writable)
        .expect("one entry is writable");
    assert!(writable.subject.contains("WEIGHTS_REGION"));
    // It is needed at S1, the copy. Everything after S10 is sealed, which is
    // why the process exits rather than lingering with this capability.
    assert_eq!(writable.required_by, Stage::S1CopyIntoRegion);
}

#[test]
fn every_capability_names_the_stage_that_cannot_run_without_it() {
    // §10.0 justifies each entry by a stage. An entry justified by nothing is
    // an entry nobody can argue against later.
    let required: [Stage; 3] = [
        Stage::S0ObtainLength,
        Stage::S1CopyIntoRegion,
        Stage::S11AuditAndExit,
    ];
    for (entry, stage) in MANIFEST.iter().zip(required) {
        assert_eq!(entry.required_by, stage, "{}", entry.subject);
        assert!(!entry.subject.is_empty());
    }
}

#[test]
fn the_manifest_names_no_serving_authority() {
    // No CapServe, no CapModel, no CapAdmin, no network, no spawn. modeld
    // cannot accept a connection and is unreachable from any client session.
    for entry in &MANIFEST {
        let subject = entry.subject.to_ascii_lowercase();
        assert!(!subject.contains("capserve"), "{}", entry.subject);
        assert!(!subject.contains("capmodel"), "{}", entry.subject);
        assert!(!subject.contains("capadmin"), "{}", entry.subject);
        assert!(!subject.contains("spawn"), "{}", entry.subject);
        assert!(!subject.contains("network"), "{}", entry.subject);
    }
}

#[test]
fn storage_authority_is_present_because_inferd_may_not_hold_it() {
    // INV-MODEL-001 denies inferd any way to read a byte from storage, so some
    // principal must hold this and it must not be inferd.
    let storage = MANIFEST
        .iter()
        .find(|entry| entry.subject.contains("devd-ans2"))
        .expect("the storage endpoint is in the manifest");
    assert!(!storage.writable);
}

#[test]
fn the_audit_endpoint_is_send_only_and_confers_no_write_authority() {
    let audit = MANIFEST
        .iter()
        .find(|entry| entry.subject.contains("auditd"))
        .expect("the audit endpoint is in the manifest");
    assert!(audit.subject.contains("send-only"));
    assert!(!audit.writable);
}
