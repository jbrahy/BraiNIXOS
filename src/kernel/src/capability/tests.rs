//! Security unit tests for the capability manager.
//!
//! Tests 1–2 are fully implemented (Plan 01, Task 2).
//! Tests 3–6 are stubs pending later plans.

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_space::CapabilitySpace;

#[test]
fn test_new_capability_space_all_slots_read_as_null() {
    let capability_space = CapabilitySpace::new();
    let all_slots = capability_space.all_slots();
    for slot in all_slots.iter() {
        assert!(
            slot.is_null(),
            "expected every slot in a new CapabilitySpace to be null"
        );
    }
}

#[test]
fn test_ungranted_slot_returns_error() {
    let capability_space = CapabilitySpace::new();
    let lookup_result = capability_space.lookup_slot(0);
    assert_eq!(
        lookup_result.unwrap_err(),
        CapabilityError::NullCapability,
        "expected NullCapability error when looking up an ungranted slot"
    );
}

#[test]
fn test_derived_capability_cannot_have_rights_not_in_parent() {
    // Implementation: Plan 02, Task 1
}

#[test]
fn test_revoked_parent_makes_all_children_unusable() {
    // Implementation: Plan 02, Task 2
}

#[test]
fn test_revoked_slot_reads_as_null_not_stale_data() {
    // Implementation: Plan 02, Task 2
}

#[test]
fn test_temporal_capability_expires_after_use_count_is_reached() {
    // Implementation: Plan 03, Task 1
}
