//! Security unit tests for the capability manager.
//!
//! Tests 1–2 are fully implemented (Plan 01, Task 2).
//! Tests 3–5 are fully implemented (Plan 02, Task 2).
//! Tests 6–8 are fully implemented (Plan 03, Task 2).
//! Tests 9–13 are audit log tests (Plan 05, Task 2).

use crate::capability::audit_event_type::AuditEventType;
use crate::capability::audit_log::{AuditRingBuffer, AUDIT_LOG_CAPACITY};
use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_rights::{GRANT, READ, WRITE};
use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::capability::derivation_tree::CapabilityDerivationTree;
use crate::capability::derive_capability::derive_capability;
use crate::capability::revocation::revoke_capability;
use crate::capability::temporal_validation::validate_capability;

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

/// Inserts a valid capability slot directly into a CapabilitySpace for test setup.
///
/// Bypasses derive_capability to install root capabilities with arbitrary rights.
fn insert_valid_slot(
    capability_space: &mut CapabilitySpace,
    slot_index: u8,
    capability_type: CapabilityType,
    rights: crate::capability::capability_rights::CapabilityRights,
    object_pointer: u64,
) {
    let slot = capability_space.lookup_slot_mut(slot_index);
    slot.state = CapabilitySlotState::Valid;
    slot.capability_type = capability_type;
    slot.rights_bitmask = rights;
    slot.object_pointer = object_pointer;
    slot.generation_counter = 1;
}

#[test]
fn test_derived_capability_cannot_have_rights_not_in_parent() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    insert_valid_slot(
        &mut capability_space,
        0,
        CapabilityType::Memory,
        READ | WRITE,
        0x1000,
    );
    let amplified_result = derive_capability(
        &mut capability_space,
        &mut derivation_tree,
        0,
        1,
        READ | WRITE | GRANT,
    );
    assert_eq!(
        amplified_result.unwrap_err(),
        CapabilityError::RightsExceedParent,
        "deriving with rights not in parent must return RightsExceedParent"
    );
    let subset_result = derive_capability(&mut capability_space, &mut derivation_tree, 0, 1, READ);
    assert!(
        subset_result.is_ok(),
        "deriving with subset rights must succeed"
    );
}

#[test]
fn test_revoked_parent_makes_all_children_unusable() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    insert_valid_slot(
        &mut capability_space,
        0,
        CapabilityType::Memory,
        READ | WRITE,
        0x2000,
    );
    derive_capability(&mut capability_space, &mut derivation_tree, 0, 1, READ).unwrap();
    derive_capability(&mut capability_space, &mut derivation_tree, 1, 2, READ).unwrap();
    revoke_capability(&mut capability_space, &mut derivation_tree, 0).unwrap();
    assert!(
        capability_space.lookup_slot_ref(1).is_null(),
        "child slot 1 must be null after parent revocation"
    );
    assert!(
        capability_space.lookup_slot_ref(2).is_null(),
        "grandchild slot 2 must be null after parent revocation"
    );
}

#[test]
fn test_revoked_slot_reads_as_null_not_stale_data() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    insert_valid_slot(
        &mut capability_space,
        5,
        CapabilityType::Endpoint,
        READ | WRITE,
        0xDEAD_BEEF,
    );
    revoke_capability(&mut capability_space, &mut derivation_tree, 5).unwrap();
    let revoked_slot = *capability_space.lookup_slot_ref(5);
    assert_eq!(
        revoked_slot,
        CapabilitySlot::null(),
        "revoked slot must equal the null sentinel exactly — no stale data"
    );
}

#[test]
fn test_temporal_capability_expires_after_use_count_is_reached() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    let slot = capability_space.lookup_slot_mut(0);
    slot.state = CapabilitySlotState::Valid;
    slot.capability_type = CapabilityType::Memory;
    slot.rights_bitmask = READ | WRITE;
    slot.object_pointer = 0x1000;
    slot.generation_counter = 1;
    slot.use_count_remaining = Some(3);
    let first_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 0);
    assert!(first_result.is_ok(), "first invocation must succeed");
    assert_eq!(
        capability_space.lookup_slot_ref(0).use_count_remaining,
        Some(2),
        "use_count_remaining must be Some(2) after first invocation"
    );
    let second_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 0);
    assert!(second_result.is_ok(), "second invocation must succeed");
    assert_eq!(
        capability_space.lookup_slot_ref(0).use_count_remaining,
        Some(1),
        "use_count_remaining must be Some(1) after second invocation"
    );
    let third_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 0);
    assert!(third_result.is_ok(), "third invocation must succeed");
    assert_eq!(
        capability_space.lookup_slot_ref(0).use_count_remaining,
        Some(0),
        "use_count_remaining must be Some(0) after third invocation"
    );
    let fourth_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 0);
    assert_eq!(
        fourth_result.unwrap_err(),
        CapabilityError::CapabilityExpired,
        "fourth invocation must return CapabilityExpired"
    );
    assert!(
        capability_space.lookup_slot_ref(0).is_null(),
        "slot must be null after use count exhaustion"
    );
}

#[test]
fn test_temporal_capability_expires_after_time_window() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    let slot = capability_space.lookup_slot_mut(0);
    slot.state = CapabilitySlotState::Valid;
    slot.capability_type = CapabilityType::Memory;
    slot.rights_bitmask = READ | WRITE;
    slot.object_pointer = 0x2000;
    slot.generation_counter = 1;
    slot.expiry_tick = Some(100);
    let before_expiry_result =
        validate_capability(&mut capability_space, &mut derivation_tree, 0, 50);
    assert!(
        before_expiry_result.is_ok(),
        "invocation before expiry_tick must succeed"
    );
    let at_expiry_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 100);
    assert_eq!(
        at_expiry_result.unwrap_err(),
        CapabilityError::CapabilityExpired,
        "invocation at expiry_tick must return CapabilityExpired"
    );
    assert!(
        capability_space.lookup_slot_ref(0).is_null(),
        "slot must be null after time window expiry"
    );
}

#[test]
fn test_temporal_capability_whichever_bound_reached_first_expires() {
    let mut capability_space = CapabilitySpace::new();
    let mut derivation_tree = CapabilityDerivationTree::new();
    let slot = capability_space.lookup_slot_mut(0);
    slot.state = CapabilitySlotState::Valid;
    slot.capability_type = CapabilityType::Memory;
    slot.rights_bitmask = READ | WRITE;
    slot.object_pointer = 0x3000;
    slot.generation_counter = 1;
    slot.use_count_remaining = Some(5);
    slot.expiry_tick = Some(100);
    let first_result = validate_capability(&mut capability_space, &mut derivation_tree, 0, 99);
    assert!(
        first_result.is_ok(),
        "invocation at tick 99 with 5 uses remaining must succeed"
    );
    let time_expired_result =
        validate_capability(&mut capability_space, &mut derivation_tree, 0, 100);
    assert_eq!(
        time_expired_result.unwrap_err(),
        CapabilityError::CapabilityExpired,
        "time window must expire at tick 100 even though 4 uses remain"
    );
    assert!(
        capability_space.lookup_slot_ref(0).is_null(),
        "slot must be null after time-window bound fires first"
    );
}

#[test]
fn test_audit_ring_buffer_starts_empty() {
    let buffer = AuditRingBuffer::new();
    assert_eq!(buffer.entry_count(), 0, "new buffer must have zero entries");
    assert_eq!(
        buffer.current_sequence_number(),
        0,
        "new buffer sequence counter must start at zero"
    );
    let first_entry = buffer
        .read_entry(0)
        .expect("index 0 must always be in range");
    assert_eq!(
        first_entry.sequence_number, 0,
        "empty slot must have zero sequence number"
    );
}

#[test]
fn test_audit_ring_buffer_appends_entries_in_order() {
    let mut buffer = AuditRingBuffer::new();
    buffer.append_entry(AuditEventType::CapabilityDerived, 0, 100);
    buffer.append_entry(AuditEventType::CapabilityRevoked, 1, 200);
    buffer.append_entry(AuditEventType::CapabilityExpired, 2, 300);
    let first = buffer.read_entry(0).expect("entry 0 must exist");
    let second = buffer.read_entry(1).expect("entry 1 must exist");
    let third = buffer.read_entry(2).expect("entry 2 must exist");
    assert_eq!(first.sequence_number, 0, "first entry must have sequence 0");
    assert_eq!(
        second.sequence_number, 1,
        "second entry must have sequence 1"
    );
    assert_eq!(third.sequence_number, 2, "third entry must have sequence 2");
    assert_eq!(first.event_type, AuditEventType::CapabilityDerived);
    assert_eq!(second.event_type, AuditEventType::CapabilityRevoked);
    assert_eq!(third.event_type, AuditEventType::CapabilityExpired);
}

#[test]
fn test_audit_ring_buffer_wraps_at_capacity() {
    let mut buffer = AuditRingBuffer::new();
    let total_writes = AUDIT_LOG_CAPACITY + 10;
    for index in 0..total_writes {
        #[allow(clippy::arithmetic_side_effects)]
        let slot = (index % 256) as u8;
        buffer.append_entry(AuditEventType::BootSequenceEvent, slot, index as u64);
    }
    assert_eq!(
        buffer.entry_count(),
        total_writes as u64,
        "entry_count must equal total writes including wrapped entries"
    );
    let wrapped_entry = buffer.read_entry(0).expect("index 0 must be in range");
    assert_eq!(
        wrapped_entry.sequence_number, AUDIT_LOG_CAPACITY as u64,
        "slot 0 must hold the overwritten entry with sequence AUDIT_LOG_CAPACITY"
    );
}

#[test]
fn test_audit_log_entry_contains_slot_index() {
    let mut buffer = AuditRingBuffer::new();
    buffer.append_entry(AuditEventType::CapabilitySlotDeleted, 42, 999);
    let entry = buffer
        .read_entry(0)
        .expect("entry 0 must exist after append");
    assert_eq!(
        entry.capability_slot_index, 42,
        "entry must preserve the capability_slot_index field"
    );
}

#[test]
fn test_audit_log_records_derivation_event() {
    let mut buffer = AuditRingBuffer::new();
    buffer.append_entry(AuditEventType::CapabilityDerived, 7, 12345);
    let entry = buffer
        .read_entry(0)
        .expect("entry 0 must exist after append");
    assert_eq!(
        entry.event_type,
        AuditEventType::CapabilityDerived,
        "event_type must be CapabilityDerived as appended"
    );
    assert_eq!(entry.timestamp, 12345, "timestamp must be preserved");
}
