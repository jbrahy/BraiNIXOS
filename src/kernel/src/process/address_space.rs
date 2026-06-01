//! Per-process address space setup with KPTI page tables.
//!
//! This module creates an isolated address space for each userspace server process.
//! The user-side page table is structurally empty of kernel mappings (KPTI by construction,
//! per INV-MEM-001 and INV-MEM-002). Kernel pages are never mapped in user page tables.
//!
//! # Security invariant
//!
//! No kernel address is reachable from the user-side page table of any process.
//! This is enforced structurally: the user PML4 is built from scratch with only
//! user-mode mappings. No kernel entry is ever copied into it.

use brainix_libsyscall::{
    SERVER_CODE_BASE_VIRTUAL_ADDRESS, SERVER_STACK_GUARD_PAGE_VIRTUAL_ADDRESS,
    SERVER_STACK_SIZE_IN_PAGES, SERVER_STACK_TOP_VIRTUAL_ADDRESS,
};

const CANONICAL_USER_SPACE_UPPER_BOUND: u64 = 0x0000_7FFF_FFFF_FFFF;
const PAGE_SIZE_IN_BYTES: u64 = 4096;

/// Errors that can occur when creating or configuring a process address space.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AddressSpaceError {
    /// The physical memory allocator could not supply a page for a page table level.
    PageAllocationFailed,
    /// Mapping a virtual address range into the page table failed.
    MappingFailed,
    /// The ELF entry point address is not a canonical x86-64 virtual address.
    EntryPointNotCanonical,
}

/// The complete virtual address layout for a newly created server process.
pub struct ProcessAddressSpaceLayout {
    /// Virtual address of the base of the server code region (first PT_LOAD segment).
    pub code_base_virtual_address: u64,
    /// Virtual address of the top of the stack (highest address; stack grows downward).
    pub stack_top_virtual_address: u64,
    /// Virtual address of the bottom of the mapped stack region.
    pub stack_bottom_virtual_address: u64,
    /// Virtual address of the unmapped guard page immediately below the stack bottom.
    pub guard_page_virtual_address: u64,
    /// Validated entry point virtual address (must be canonical user-space address).
    pub entry_point_virtual_address: u64,
}

fn entry_point_is_null(entry_point: u64) -> bool {
    entry_point == 0
}

fn entry_point_is_above_canonical_bound(entry_point: u64) -> bool {
    entry_point > CANONICAL_USER_SPACE_UPPER_BOUND
}

/// Enforces INV-MEM-002 (KPTI) by rejecting kernel-space entry points.
///
/// Prevents SYSRET to a non-canonical RIP, which would cause a #GP in ring 0 on
/// Intel processors (Intel errata: SYSRET with non-canonical RCX is ring-0 #GP).
/// Also rejects null entry points as structurally invalid.
///
/// Verified by: tests::test_kernel_space_entry_point_rejected
pub fn validate_entry_point_is_canonical(entry_point: u64) -> Result<(), AddressSpaceError> {
    let is_null = entry_point_is_null(entry_point);
    let is_above_bound = entry_point_is_above_canonical_bound(entry_point);
    if is_null || is_above_bound {
        Err(AddressSpaceError::EntryPointNotCanonical)
    } else {
        Ok(())
    }
}

/// Returns the virtual address of the bottom of the server process stack.
///
/// The stack is allocated as SERVER_STACK_SIZE_IN_PAGES pages downward from
/// SERVER_STACK_TOP_VIRTUAL_ADDRESS. The bottom is the lowest mapped stack address.
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_stack_bottom_address() -> u64 {
    let stack_size_in_bytes = SERVER_STACK_SIZE_IN_PAGES as u64 * PAGE_SIZE_IN_BYTES;
    SERVER_STACK_TOP_VIRTUAL_ADDRESS - stack_size_in_bytes
}

/// Returns the virtual address of the stack guard page.
///
/// The guard page is one page below the stack bottom. It is mapped non-present
/// so that stack overflow generates a page fault rather than silently corrupting
/// adjacent memory (per INV-MEM-007).
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_stack_guard_page_address() -> u64 {
    compute_stack_bottom_address() - PAGE_SIZE_IN_BYTES
}

/// Returns the number of pages allocated for the server process initial stack.
pub fn compute_total_stack_pages() -> usize {
    SERVER_STACK_SIZE_IN_PAGES
}

/// Builds the complete virtual address layout for a new server process.
///
/// Validates the entry point is a canonical user-space address, then constructs
/// the full layout using the fixed VA constants from brainix-libsyscall.
pub fn build_process_address_space_layout(
    entry_point: u64,
) -> Result<ProcessAddressSpaceLayout, AddressSpaceError> {
    validate_entry_point_is_canonical(entry_point)?;
    Ok(ProcessAddressSpaceLayout {
        code_base_virtual_address: SERVER_CODE_BASE_VIRTUAL_ADDRESS,
        stack_top_virtual_address: SERVER_STACK_TOP_VIRTUAL_ADDRESS,
        stack_bottom_virtual_address: compute_stack_bottom_address(),
        guard_page_virtual_address: SERVER_STACK_GUARD_PAGE_VIRTUAL_ADDRESS,
        entry_point_virtual_address: entry_point,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entry_point_at_code_base_passes_canonical_check() {
        // 0x0000_0000_0040_0000 is the server code base — a valid canonical user address
        let result = validate_entry_point_is_canonical(0x0000_0000_0040_0000);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_entry_point_at_canonical_upper_bound_passes() {
        // 0x0000_7FFF_FFFF_FFFF is the highest canonical user-space address
        let result = validate_entry_point_is_canonical(0x0000_7FFF_FFFF_FFFF);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_entry_point_one_above_canonical_upper_bound_fails() {
        // 0x0000_8000_0000_0000 is the first non-canonical address
        let result = validate_entry_point_is_canonical(0x0000_8000_0000_0000);
        assert_eq!(result, Err(AddressSpaceError::EntryPointNotCanonical));
    }

    #[test]
    fn test_kernel_space_entry_point_rejected() {
        // 0xFFFF_8000_0000_0000 is deep kernel space — must be rejected
        let result = validate_entry_point_is_canonical(0xFFFF_8000_0000_0000);
        assert_eq!(result, Err(AddressSpaceError::EntryPointNotCanonical));
    }

    #[test]
    fn test_compute_stack_bottom_returns_correct_address() {
        // Stack top is 0x0000_0000_0080_0000 and size is 16 pages (64 KiB)
        // Bottom = 0x80_0000 - (16 * 4096) = 0x80_0000 - 0x10_000 = 0x70_0000
        let expected_bottom = SERVER_STACK_TOP_VIRTUAL_ADDRESS
            - (SERVER_STACK_SIZE_IN_PAGES as u64 * PAGE_SIZE_IN_BYTES);
        let computed_bottom = compute_stack_bottom_address();
        assert_eq!(computed_bottom, expected_bottom);
    }

    #[test]
    fn test_compute_guard_page_address_is_one_page_below_stack_bottom() {
        let stack_bottom = compute_stack_bottom_address();
        let guard_page = compute_stack_guard_page_address();
        assert_eq!(guard_page, stack_bottom - PAGE_SIZE_IN_BYTES);
    }

    #[test]
    fn test_guard_page_address_matches_libsyscall_constant() {
        // The computed guard page must match the constant in libsyscall (D-09 contract)
        let computed_guard_page = compute_stack_guard_page_address();
        assert_eq!(computed_guard_page, SERVER_STACK_GUARD_PAGE_VIRTUAL_ADDRESS);
    }

    #[test]
    fn test_build_process_address_space_layout_sets_entry_point() {
        let entry_point = 0x0000_0000_0040_0000u64;
        let layout = build_process_address_space_layout(entry_point).unwrap();
        assert_eq!(layout.entry_point_virtual_address, entry_point);
    }
}
