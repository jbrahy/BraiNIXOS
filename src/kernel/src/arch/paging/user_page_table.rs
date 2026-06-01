//! User page table construction.
//!
//! The user PML4 is intentionally empty in Phase 2: no userspace processes exist yet.
//!
//! Enforces INV-MEM-001 (userspace cannot read kernel memory) and INV-MEM-002
//! (userspace cannot write kernel memory) by construction: the user page table
//! contains no mappings in the kernel VA range (>= 0xFFFF_8000_0000_0000).
//! An empty PML4 cannot map any address in any range.
//!
//! Allowlist: src/kernel/src/arch/paging/ (UNSAFE_CODE_POLICY.md)
#![allow(unsafe_code)]

use x86_64::structures::paging::PageTable;

use crate::boot::logger::BootStepLogger;

/// User PML4 (top-level page table for userspace). Empty in Phase 2.
///
/// PageTable::new() produces all-zero entries. Zero entries have PRESENT=0,
/// so the CPU will never walk this table and find a valid mapping.
static mut USER_PAGE_MAP_LEVEL_4: PageTable = PageTable::new();

/// Constructs the user page table for Phase 2.
///
/// The user PML4 is initialized to all-zero entries (PageTable::new() already
/// guarantees this). No kernel VA entries are ever added here.
///
/// Enforces INV-MEM-001 and INV-MEM-002: an empty page table cannot expose
/// kernel memory to userspace under any circumstance.
pub fn build_user_page_table(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.step("Building user page table (KPTI: empty for Phase 2)");
    assert_user_page_table_is_empty();
    boot_step_logger.ok("User page table constructed (empty -- no userspace mappings in Phase 2)");
}

/// Asserts that the user PML4 is empty (all entries unused).
///
/// Structural enforcement of INV-MEM-001 and INV-MEM-002: an empty user PML4
/// cannot map any kernel VA range entry.
fn assert_user_page_table_is_empty() {
    // SAFETY: USER_PAGE_MAP_LEVEL_4 is accessed read-only here during single-threaded boot.
    // addr_of! avoids mutable-static-reference UB.
    // - Precondition: no concurrent access before scheduler starts.
    // - Invariant: INV-MEM-001, INV-MEM-002 (user PT contains no kernel VA entries).
    // - Evidence: PageTable::new() produces all-zero entries; PRESENT=0 means no mapping.
    let is_empty = unsafe { (*core::ptr::addr_of!(USER_PAGE_MAP_LEVEL_4)).is_empty() };
    assert!(
        is_empty,
        "user page table must be empty in Phase 2 (KPTI invariant)"
    );
}
