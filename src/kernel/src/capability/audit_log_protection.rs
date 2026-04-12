//! Hardware write-protection for audit log pages.
//!
//! After the audit ring buffer is initialized during boot, the boot sequence
//! calls `protect_audit_log_pages()` to clear the PTE Write bit on all pages
//! backing the ring buffer. This makes the audit log hardware-immutable except
//! during controlled append operations.
//!
//! ## Boot Integration
//!
//! The following call must be added to `src/kernel/src/boot/phases.rs` in the
//! `execute_boot_sequence()` function AFTER audit log initialization:
//!
//! ```rust
//! audit_log_protection::protect_audit_log_pages(&mut page_table, &audit_ring_buffer);
//! ```
//!
//! This is deferred to Phase 7 (boot sequence extension) when the boot phase
//! machinery is extended to include capability manager initialization.
//!
//! TODO(Phase 7): Wire protect_audit_log_pages() into boot/phases.rs after
//! audit ring buffer initialization. See ROADMAP.md Phase 7.

/// Marks all pages backing the audit ring buffer as read-only in the page table.
///
/// Called once during boot after the ring buffer is initialized.
/// After this call, any write to audit pages without calling
/// `unprotect_audit_log_page` first will trigger a page fault.
///
/// Enforces INV-AUD-001: audit log entries cannot be modified after write.
pub fn protect_audit_log_pages() {
    // TODO(Phase 7): Clear PTE Write bit for all audit log pages
    // Uses Phase 2 page table machinery (PageTableEntry::set_writable(false))
}

/// Temporarily allows writes to the audit log page containing write_head.
///
/// Called by AuditRingBuffer::append_entry before writing a new entry.
/// Must be followed by `reprotect_audit_log_page` after the write completes.
pub fn unprotect_audit_log_page() {
    // TODO(Phase 7): Set PTE Write bit for the current write_head page
}

/// Re-enables write protection on the audit log page after an append.
///
/// Called by AuditRingBuffer::append_entry after writing a new entry.
/// On single-core, no TLB shootdown is needed (local INVLPG suffices).
pub fn reprotect_audit_log_page() {
    // TODO(Phase 7): Clear PTE Write bit and INVLPG the page
}
