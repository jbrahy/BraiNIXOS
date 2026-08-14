//! `INV-AUDIT` is a list, and this counts it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cognitive_complexity)]

use brainix_auditd::manifest::{holds_write_authority, FORBIDDEN_SUBJECTS, MANIFEST};

#[test]
fn the_auditor_holds_two_capabilities_and_neither_can_write_the_log() {
    // An auditor that could write its own log could erase the record of its
    // own compromise.
    assert_eq!(MANIFEST.len(), 2);
    assert!(!holds_write_authority());
}

#[test]
fn the_manifest_names_none_of_the_authorities_that_would_make_it_omnipotent() {
    // INV-AUD-002: audit pipelines accidentally become privileged chokepoints.
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
fn every_capability_says_why_observing_requires_it() {
    for entry in &MANIFEST {
        assert!(!entry.subject.is_empty());
        assert!(!entry.because.is_empty(), "{} has no reason", entry.subject);
    }
}

#[test]
fn the_serving_endpoint_is_receive_only() {
    // Observing grants no authority to act: nothing is sent back down it.
    let endpoint = MANIFEST
        .iter()
        .find(|entry| entry.subject.contains("CapEndpoint"))
        .expect("the serving endpoint is in the manifest");
    assert!(endpoint.subject.contains("receive-only"));
}
