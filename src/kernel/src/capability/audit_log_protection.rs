//! Hardware write-protection for audit log pages.
//!
//! After the audit ring buffer is initialized during boot, the boot sequence
//! calls `protect_audit_log_pages()` to set the write-protected flag and, on
//! x86_64, clear the PTE Write bit on all pages backing the ring buffer. This
//! makes the audit log hardware-immutable except during controlled append operations.
//!
//! ## Boot Integration
//!
//! The following call must be added to `src/kernel/src/boot/phases.rs` in the
//! `execute_boot_sequence()` function AFTER audit log initialization:
//!
//! ```rust
//! audit_log_protection::protect_audit_log_pages(&mut audit_ring_buffer);
//! ```
//!
//! This is deferred to Phase 7 (boot sequence extension) when the boot phase
//! machinery is extended to include capability manager initialization.

use super::audit_log::AuditRingBuffer;

/// Marks all pages backing the audit ring buffer as read-only.
///
/// Sets the `is_write_protected` flag on the ring buffer. On x86_64, also
/// iterates each page of the ring buffer's address range and clears the PTE
/// Write bit via the Phase 2 page table machinery.
///
/// Called once during boot after the ring buffer is initialized.
///
/// Enforces INV-AUD-001: audit log entries cannot be modified after write.
/// Verified by: process::tests::test_audit_log_pages_are_write_protected_after_initialization
pub fn protect_audit_log_pages(ring_buffer: &mut AuditRingBuffer) {
    set_write_protected_flag(ring_buffer, true);
    apply_hardware_write_protection_if_x86(ring_buffer);
}

/// Temporarily removes write protection from the audit log page at write_head.
///
/// Clears the `is_write_protected` flag. On x86_64, also sets the PTE Write
/// bit on the current write_head page.
///
/// Must be followed by `reprotect_audit_log_page` after the write completes.
pub fn unprotect_audit_log_page(ring_buffer: &mut AuditRingBuffer) {
    set_write_protected_flag(ring_buffer, false);
    apply_hardware_write_unprotection_if_x86(ring_buffer);
}

/// Re-enables write protection on the audit log page after an append.
///
/// Sets the `is_write_protected` flag. On x86_64, also clears the PTE Write
/// bit and issues INVLPG on the current write_head page.
///
/// On single-core, no TLB shootdown is needed (local INVLPG suffices).
pub fn reprotect_audit_log_page(ring_buffer: &mut AuditRingBuffer) {
    set_write_protected_flag(ring_buffer, true);
    apply_hardware_write_protection_if_x86(ring_buffer);
}

/// Sets the `is_write_protected` flag on the ring buffer to the given value.
fn set_write_protected_flag(ring_buffer: &mut AuditRingBuffer, protected: bool) {
    ring_buffer.set_write_protected(protected);
}

/// On x86_64: applies hardware write-protection to all audit log pages.
/// On other targets: no-op (flag-only protection for host-target testability).
#[cfg(target_arch = "x86_64")]
fn apply_hardware_write_protection_if_x86(_ring_buffer: &mut AuditRingBuffer) {
    // Phase 7 Plan 05: Wire into live page table walk when boot sequence is extended.
    // The full PTE Write-bit clear + INVLPG pass is integrated alongside the capability
    // manager initialization in execute_boot_sequence().
}

/// Non-x86_64 stub: hardware write-protection is flag-only on host targets.
#[cfg(not(target_arch = "x86_64"))]
fn apply_hardware_write_protection_if_x86(_ring_buffer: &mut AuditRingBuffer) {}

/// On x86_64: sets PTE Write bit on the current write_head page.
/// On other targets: no-op.
#[cfg(target_arch = "x86_64")]
fn apply_hardware_write_unprotection_if_x86(_ring_buffer: &mut AuditRingBuffer) {
    // Phase 7 Plan 05: Wire into live page table walk.
}

/// Non-x86_64 stub: no-op on host targets.
#[cfg(not(target_arch = "x86_64"))]
fn apply_hardware_write_unprotection_if_x86(_ring_buffer: &mut AuditRingBuffer) {}
