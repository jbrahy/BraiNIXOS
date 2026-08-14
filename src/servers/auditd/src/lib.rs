//! auditd server: read-only audit log access.
//!
//! auditd holds CapAuditRead with Read-only rights. It reads
//! audit log entries via sys_audit_read syscall. The kernel copies
//! entries to auditd's userspace buffer. Per D-10, D-11.
//!
//! auditd CANNOT write to the audit log. Any attempt returns
//! CapabilityError::WriteRightNotGranted per D-11.
//!
//! Enforces INV-AUD-001: audit log integrity preserved.
#![no_std]
#![deny(unsafe_code)]

pub mod event;
pub mod manifest;

use brainix_libsyscall::syscall_audit_read;

/// Capability slot index for CapAuditRead in auditd's CSpace.
const CAPABILITY_SLOT_AUDIT_READ: u8 = 0;

/// Maximum number of audit entries to read per syscall invocation.
const MAXIMUM_ENTRIES_PER_READ: u64 = 64;

/// auditd main loop. Periodically reads audit log entries via sys_audit_read.
pub fn auditd_main() -> ! {
    let mut current_sequence: u64 = 0;
    loop {
        let entries_read = read_audit_entries(current_sequence);
        current_sequence = advance_sequence_counter(current_sequence, entries_read);
    }
}

fn read_audit_entries(start_sequence: u64) -> i64 {
    // Phase 7 stub: buffer_pointer would be a stack-allocated array address.
    // Passes 0 as buffer pointer until real buffer wired in boot integration.
    syscall_audit_read(
        CAPABILITY_SLOT_AUDIT_READ,
        start_sequence,
        MAXIMUM_ENTRIES_PER_READ,
        0,
    )
}

fn advance_sequence_counter(current_sequence: u64, entries_read: i64) -> u64 {
    if entries_read <= 0 {
        return current_sequence;
    }
    current_sequence.wrapping_add(entries_read as u64)
}
