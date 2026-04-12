//! Shared helper functions for page table construction.
//!
//! These helpers are used by both kernel_page_table.rs and direct_map.rs
//! to avoid duplicating VA-to-PA conversion and page table index extraction.
//!
//! Per CODE_STANDARDS.md Rule 3: any pattern appearing twice must be extracted.

use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use crate::memory::virtual_address_layout::KERNEL_BINARY_VIRTUAL_ADDRESS;

/// Physical address where the kernel binary is loaded by the bootloader (1 MiB).
pub const KERNEL_PHYSICAL_LOAD_ADDRESS: u64 = 0x0010_0000;

/// Intermediate page table entry flags (PRESENT | WRITABLE).
///
/// Used for PML4, PDPT, and PD entries that point to sub-tables.
pub fn compute_intermediate_page_table_flags() -> PageTableFlags {
    PageTableFlags::PRESENT | PageTableFlags::WRITABLE
}

/// Extracts the PML4 index from a virtual address (bits 47-39).
#[allow(clippy::arithmetic_side_effects)]
pub fn extract_page_map_level_4_index(virtual_address: u64) -> usize {
    ((virtual_address >> 39) & 0x1FF) as usize
}

/// Extracts the PDPT index from a virtual address (bits 38-30).
#[allow(clippy::arithmetic_side_effects)]
pub fn extract_page_directory_pointer_table_index(virtual_address: u64) -> usize {
    ((virtual_address >> 30) & 0x1FF) as usize
}

/// Extracts the PD index from a virtual address (bits 29-21).
#[allow(clippy::arithmetic_side_effects)]
pub fn extract_page_directory_index(virtual_address: u64) -> usize {
    ((virtual_address >> 21) & 0x1FF) as usize
}

/// Extracts the PT index from a virtual address (bits 20-12).
#[allow(clippy::arithmetic_side_effects)]
pub fn extract_page_table_index(virtual_address: u64) -> usize {
    ((virtual_address >> 12) & 0x1FF) as usize
}

/// Computes the physical address of a BSS-backed virtual address.
///
/// Uses the known identity: physical = virtual - KERNEL_BINARY_VIRTUAL_ADDRESS
///                                              + KERNEL_PHYSICAL_LOAD_ADDRESS
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_physical_address_of_bss_page(virtual_address: u64) -> PhysAddr {
    let physical_offset = virtual_address - KERNEL_BINARY_VIRTUAL_ADDRESS;
    PhysAddr::new(KERNEL_PHYSICAL_LOAD_ADDRESS + physical_offset)
}

/// Returns the physical address of a page table given its virtual address.
pub fn compute_page_table_physical_address(page_table: &PageTable) -> PhysAddr {
    let virtual_address = page_table as *const PageTable as u64;
    compute_physical_address_of_bss_page(virtual_address)
}

/// Converts a physical address (stored in a page table entry) back to a BSS virtual pointer.
///
/// Valid only for page table pages allocated from BSS bootstrap pools.
///
/// # Safety
/// Caller must ensure physical_address was previously stored by a BSS bootstrap allocator.
#[allow(clippy::arithmetic_side_effects)]
pub unsafe fn retrieve_page_table_by_physical_address(
    physical_address: PhysAddr,
) -> &'static mut PageTable {
    let virtual_address =
        physical_address.as_u64() - KERNEL_PHYSICAL_LOAD_ADDRESS + KERNEL_BINARY_VIRTUAL_ADDRESS;
    // SAFETY: virtual_address points into a BSS-backed bootstrap page table block.
    // - Precondition: physical_address was stored by a bootstrap allocator (caller contract).
    // - Invariant: INV-MEM-003 (structure only written with validated entries).
    // - Evidence: only called on physical addresses previously placed in page table entries.
    &mut *(virtual_address as *mut PageTable)
}
