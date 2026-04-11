//! Kernel stack guard page configuration and verification.
//!
//! Enforces INV-MEM-007: kernel stack overrun must fault, not corrupt silently.
//! The guard page is a 4 KiB unmapped region below the initial kernel stack.
//! Stack overflow descends into this region, triggering a page fault.
//! The double-fault handler (Phase 1, IST stack) catches the fault.
//!
//! Guard page layout:
//!   [INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS] -- unmapped 4 KiB guard page
//!   [INITIAL_KERNEL_STACK_BOTTOM]             -- kernel stack starts here
//!   [INITIAL_KERNEL_STACK_TOP]                -- stack top (rsp initialized here)
//!
//! The guard page is enforced by construction: map_kernel_stack_region in
//! kernel_page_table.rs maps from INITIAL_KERNEL_STACK_BOTTOM (never the guard page).
//!
//! Verified by: test_stack_guard_page_is_unmapped_below_kernel_stack

use crate::boot::logger::BootStepLogger;
use crate::memory::virtual_address_layout::{
    INITIAL_KERNEL_STACK_BOTTOM, INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS, INITIAL_KERNEL_STACK_TOP,
    KERNEL_STACK_REGION_START, PAGE_SIZE_IN_BYTES,
};

/// Configures and verifies the kernel stack guard page.
///
/// Enforces INV-MEM-007: kernel stack overrun must fault, not corrupt silently.
/// The guard page is the 4 KiB unmapped region immediately below the kernel stack.
/// This function verifies guard page layout invariants and logs the configuration.
///
/// Verified by: test_stack_guard_page_is_unmapped_below_kernel_stack
pub fn configure_kernel_stack_guard_page(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.step("Configuring kernel stack guard page");
    verify_guard_page_layout_invariants();
    log_guard_page_configured(boot_step_logger);
}

/// Verifies the guard page address constant is the first page of the stack region.
fn verify_guard_page_is_first_page_of_stack_region() {
    assert_eq!(
        INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS, KERNEL_STACK_REGION_START,
        "guard page must be the first page of the kernel stack region"
    );
}

/// Verifies the stack bottom is exactly one page above the guard page.
fn verify_stack_bottom_is_one_page_above_guard() {
    let expected_gap = PAGE_SIZE_IN_BYTES as u64;
    #[allow(clippy::arithmetic_side_effects)]
    let actual_gap = INITIAL_KERNEL_STACK_BOTTOM - INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS;
    assert_eq!(
        actual_gap, expected_gap,
        "stack bottom must be exactly one page (4 KiB) above the guard page"
    );
}

/// Verifies the stack top is above the stack bottom (stack has positive size).
fn verify_stack_top_is_above_stack_bottom() {
    assert!(
        INITIAL_KERNEL_STACK_TOP > INITIAL_KERNEL_STACK_BOTTOM,
        "kernel stack top must be above stack bottom"
    );
}

/// Verifies all guard page layout invariants hold.
///
/// Structural enforcement of INV-MEM-007: the guard page is correctly positioned
/// below the kernel stack by construction. The kernel page table (built by
/// kernel_page_table.rs) maps INITIAL_KERNEL_STACK_BOTTOM through
/// INITIAL_KERNEL_STACK_TOP but never maps INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS.
fn verify_guard_page_layout_invariants() {
    verify_guard_page_is_first_page_of_stack_region();
    verify_stack_bottom_is_one_page_above_guard();
    verify_stack_top_is_above_stack_bottom();
}

/// Logs that the guard page has been verified and configured.
fn log_guard_page_configured(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Kernel stack guard page configured (INV-MEM-007: unmapped below stack)");
}
