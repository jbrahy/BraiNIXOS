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

/// Validates that an ELF entry point address is a canonical x86-64 virtual address.
///
/// Canonical addresses on x86-64 are in the range `0x0000_0000_0000_0000` through
/// `0x0000_7FFF_FFFF_FFFF` (user space). Addresses above this range are non-canonical
/// and will cause a #GP fault on the first instruction fetch.
///
/// Enforces INV-MEM-003: the kernel never transfers control to a non-canonical address.
pub fn validate_entry_point_is_canonical(entry_point: u64) -> Result<(), AddressSpaceError> {
    let canonical_user_space_maximum: u64 = 0x0000_7FFF_FFFF_FFFF;
    let entry_point_is_in_range = entry_point <= canonical_user_space_maximum;
    if entry_point_is_in_range {
        Ok(())
    } else {
        Err(AddressSpaceError::EntryPointNotCanonical)
    }
}
