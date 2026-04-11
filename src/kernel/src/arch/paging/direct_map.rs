//! Direct map region construction.
//!
//! Maps all physical RAM 1:1 at DIRECT_MAP_REGION_START using 2MB huge pages.
//! Every entry uses PRESENT | WRITABLE | NO_EXECUTE | HUGE_PAGE (data, never executable).
//!
//! Security invariants enforced:
//! - INV-MEM-003: W^X validator rejects writable+executable; direct map uses NO_EXECUTE.
//!
//! Allowlist: src/kernel/src/arch/paging/ (UNSAFE_CODE_POLICY.md)
#![allow(unsafe_code)]

use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use crate::arch::paging::mapping_error::MappingError;
use crate::arch::paging::page_table_flags_validator::validate_page_table_flags_enforce_write_xor_execute;
use crate::arch::paging::page_table_walk_helpers::{
    compute_intermediate_page_table_flags, compute_page_table_physical_address,
    extract_page_directory_index, extract_page_directory_pointer_table_index,
    extract_page_map_level_4_index, retrieve_page_table_by_physical_address,
};
use crate::boot::logger::BootStepLogger;
use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;

/// Size of a 2MB huge page in bytes.
const HUGE_PAGE_SIZE_IN_BYTES: u64 = 2 * 1024 * 1024;

/// Flags for direct-map entries: present, writable, no-execute, 2MB huge page.
///
/// Direct-map pages are data pages — they must never be executable.
/// Enforces INV-MEM-003 (W^X is global).
fn compute_direct_map_page_flags() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::HUGE_PAGE
}

/// Bootstrap page table storage for direct-map PDPT and PD pages.
///
/// For 128 MB with 2MB pages: 64 PD entries fit in 1 PD under 1 PDPT entry.
/// We need at most 1 PDPT + 1 PD = 2 tables. 4 provides a safety margin.
const DIRECT_MAP_BOOTSTRAP_TABLE_COUNT: usize = 4;

#[repr(align(4096))]
struct DirectMapPageTableBlock {
    tables: [PageTable; DIRECT_MAP_BOOTSTRAP_TABLE_COUNT],
}

static mut DIRECT_MAP_PAGE_TABLE_BLOCK: DirectMapPageTableBlock = DirectMapPageTableBlock {
    tables: [const { PageTable::new() }; DIRECT_MAP_BOOTSTRAP_TABLE_COUNT],
};

static mut NEXT_DIRECT_MAP_TABLE_INDEX: usize = 0;

/// Allocates a bootstrap page table for direct-map construction.
fn allocate_direct_map_page_table() -> &'static mut PageTable {
    // SAFETY: Single-threaded boot. addr_of_mut! avoids mutable-static-reference UB.
    // - Precondition: called only during boot before scheduler starts.
    // - Invariant: INV-MEM-003 (table pages never executable).
    // - Evidence: boot is single-threaded; no concurrent access possible.
    let index = unsafe { *core::ptr::addr_of!(NEXT_DIRECT_MAP_TABLE_INDEX) };
    assert!(
        index < DIRECT_MAP_BOOTSTRAP_TABLE_COUNT,
        "direct-map bootstrap page table pool exhausted"
    );
    unsafe {
        *core::ptr::addr_of_mut!(NEXT_DIRECT_MAP_TABLE_INDEX) = index.wrapping_add(1);
        &mut (*core::ptr::addr_of_mut!(DIRECT_MAP_PAGE_TABLE_BLOCK)).tables[index]
    }
}

/// Allocates a direct-map bootstrap page table and links a parent entry to it.
fn allocate_and_link_direct_map_table(
    parent_entry: &mut x86_64::structures::paging::PageTableEntry,
) -> &'static mut PageTable {
    let new_table = allocate_direct_map_page_table();
    let physical_address = compute_page_table_physical_address(new_table);
    parent_entry.set_addr(physical_address, compute_intermediate_page_table_flags());
    new_table
}

/// Ensures the PML4 entry for the direct-map region points to a PDPT.
fn ensure_direct_map_pdpt_exists(
    page_map_level_4: &mut PageTable,
    pml4_index: usize,
) -> &'static mut PageTable {
    if page_map_level_4[pml4_index].is_unused() {
        allocate_and_link_direct_map_table(&mut page_map_level_4[pml4_index])
    } else {
        // SAFETY: physical address was stored by allocate_and_link_direct_map_table above.
        // - Precondition: entry is non-empty; we stored a BSS bootstrap table address.
        // - Invariant: INV-MEM-003 (structure only written with validated entries).
        // - Evidence: only called on physical addresses we previously placed in entries.
        unsafe { retrieve_page_table_by_physical_address(page_map_level_4[pml4_index].addr()) }
    }
}

/// Ensures the PDPT entry for the given 1GB region points to a PD.
fn ensure_direct_map_pd_exists(
    page_directory_pointer_table: &mut PageTable,
    pdpt_index: usize,
) -> &'static mut PageTable {
    if page_directory_pointer_table[pdpt_index].is_unused() {
        allocate_and_link_direct_map_table(&mut page_directory_pointer_table[pdpt_index])
    } else {
        // SAFETY: physical address was stored by allocate_and_link_direct_map_table above.
        // - Precondition: entry is non-empty; we stored a BSS bootstrap table address.
        // - Invariant: INV-MEM-003 (entries validated before write).
        // - Evidence: only called on physical addresses we previously placed in entries.
        unsafe {
            retrieve_page_table_by_physical_address(page_directory_pointer_table[pdpt_index].addr())
        }
    }
}

/// Writes one 2MB huge page entry into the page directory with W^X validation.
fn write_direct_map_huge_page_entry(
    page_directory: &mut PageTable,
    page_directory_index: usize,
    physical_address: PhysAddr,
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    validate_page_table_flags_enforce_write_xor_execute(flags)?;
    // SAFETY: page_directory is a valid BSS-backed PageTable. page_directory_index in [0,511].
    // physical_address is a 2MB-aligned physical address for the huge page.
    // - Precondition: flags validated by W^X validator above.
    // - Invariant: INV-MEM-003 (W^X validated before this write).
    // - Evidence: test_writable_and_executable_flags_are_rejected.
    page_directory[page_directory_index].set_addr(physical_address, flags);
    Ok(())
}

/// Resolves the page directory for one 2MB huge page in the direct-map region.
#[allow(clippy::arithmetic_side_effects)]
fn resolve_direct_map_page_directory(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
) -> &'static mut PageTable {
    let pml4_index = extract_page_map_level_4_index(virtual_address);
    let pdpt_index = extract_page_directory_pointer_table_index(virtual_address);
    let page_directory_pointer_table = ensure_direct_map_pdpt_exists(page_map_level_4, pml4_index);
    ensure_direct_map_pd_exists(page_directory_pointer_table, pdpt_index)
}

/// Maps one 2MB huge page into the direct-map region.
#[allow(clippy::arithmetic_side_effects)]
fn map_one_direct_map_huge_page(
    page_map_level_4: &mut PageTable,
    huge_page_index: u64,
    flags: PageTableFlags,
) {
    let physical_address = PhysAddr::new(huge_page_index * HUGE_PAGE_SIZE_IN_BYTES);
    let virtual_address = DIRECT_MAP_REGION_START + huge_page_index * HUGE_PAGE_SIZE_IN_BYTES;
    let page_directory = resolve_direct_map_page_directory(page_map_level_4, virtual_address);
    let page_directory_index = extract_page_directory_index(virtual_address);
    write_direct_map_huge_page_entry(
        page_directory,
        page_directory_index,
        physical_address,
        flags,
    )
    .expect("direct-map huge page entry write failed");
}

/// Maps all huge pages for the direct-map region.
fn map_all_huge_pages(
    page_map_level_4: &mut PageTable,
    huge_page_count: u64,
    flags: PageTableFlags,
) {
    for huge_page_index in 0..huge_page_count {
        map_one_direct_map_huge_page(page_map_level_4, huge_page_index, flags);
    }
}

/// Computes the number of 2MB huge pages needed to cover the given memory size.
#[allow(clippy::arithmetic_side_effects)]
fn compute_huge_page_count(total_physical_memory_in_bytes: u64) -> u64 {
    (total_physical_memory_in_bytes + HUGE_PAGE_SIZE_IN_BYTES - 1) / HUGE_PAGE_SIZE_IN_BYTES
}

/// Maps the full physical RAM range at DIRECT_MAP_REGION_START using 2MB huge pages.
///
/// Eager mapping at boot (recommended per RESEARCH.md Open Questions).
///
/// Enforces INV-MEM-003 via validate_page_table_flags_enforce_write_xor_execute.
pub fn map_direct_map_region(
    page_map_level_4: &mut PageTable,
    total_physical_memory_in_bytes: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    boot_step_logger.step("Mapping direct-map region (2MB huge pages)");
    let direct_map_flags = compute_direct_map_page_flags();
    let huge_page_count = compute_huge_page_count(total_physical_memory_in_bytes);
    map_all_huge_pages(page_map_level_4, huge_page_count, direct_map_flags);
    boot_step_logger.ok("Direct-map region mapped");
}
