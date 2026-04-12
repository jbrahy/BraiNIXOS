//! Security unit tests for the capability manager.
//!
//! Tests 1–2 are fully implemented (Plan 01, Task 2).
//! Tests 3–6 are stubs pending later plans.
//! Tests 7–11 are audit log tests (Plan 05, Task 2).

use crate::capability::audit_event_type::AuditEventType;
use crate::capability::audit_log::{AuditRingBuffer, AUDIT_LOG_CAPACITY};
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
