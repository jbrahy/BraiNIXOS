//! Page-table side-effects for the userspace ELF loader.
//!
//! Owns the single place where a per-process user page table is mutated
//! to materialize a server's PT_LOAD segments. Pure-data parsing lives
//! in `elf_loader.rs`; this module turns those parsed segments into real
//! mappings and copies the segment bytes through the kernel's direct
//! map view of the freshly-allocated physical pages.
//!
//! Falls under `src/kernel/src/process/elf_load_into_address_space.rs`
//! allowlist entry in `docs/security/UNSAFE_CODE_POLICY.md` (Task 10).
//!
//! No host-target unit tests: the primitives below mutate kernel-instance
//! singletons (physical allocator, per-process PML4). End-to-end coverage
//! comes from the boot regression in `bin/run-brainx.sh`.
#![allow(unsafe_code)]

use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use crate::arch::paging::kernel_page_table;
use crate::boot::multiboot2_info::global_physical_allocator_pointer;
use crate::memory::virtual_address_layout::{DIRECT_MAP_REGION_START, PAGE_SIZE_IN_BYTES};
use crate::process::address_space::{
    compute_stack_bottom_address, compute_total_stack_pages, ProcessAddressSpaceLayout,
};
use crate::process::elf_loader::{
    translate_segment_flags_to_user_page_permissions, ElfLoadError, LoadableSegment,
    UserPageMappingPermissions,
};

/// Number of PT_LOAD segment slots the parsing layer returns. Must match
/// the fixed-array length used by `extract_loadable_segments`.
pub const MAXIMUM_PT_LOAD_SEGMENT_SLOTS: usize = 8;

/// Maps every populated PT_LOAD segment of a parsed ELF image into the
/// user page table rooted at `user_page_map_level_4` and copies its
/// bytes into the freshly-allocated physical pages.
///
/// # Safety
/// Called only during boot, single-core, no concurrent access to the
/// global physical allocator or the supplied PML4. `elf_module_bytes`
/// must remain live for the duration of the call.
pub unsafe fn load_segments_into_user_page_table(
    user_page_map_level_4: &mut PageTable,
    elf_module_bytes: &[u8],
    segments: &[Option<LoadableSegment>; MAXIMUM_PT_LOAD_SEGMENT_SLOTS],
) -> Result<(), ElfLoadError> {
    for segment_slot in segments.iter() {
        load_optional_segment_into_user_page_table(
            user_page_map_level_4,
            elf_module_bytes,
            segment_slot,
        )?;
    }
    Ok(())
}

unsafe fn load_optional_segment_into_user_page_table(
    user_page_map_level_4: &mut PageTable,
    elf_module_bytes: &[u8],
    segment_slot: &Option<LoadableSegment>,
) -> Result<(), ElfLoadError> {
    match segment_slot {
        Some(segment) => {
            load_one_segment_into_user_page_table(user_page_map_level_4, elf_module_bytes, segment)
        }
        None => Ok(()),
    }
}

unsafe fn load_one_segment_into_user_page_table(
    user_page_map_level_4: &mut PageTable,
    elf_module_bytes: &[u8],
    segment: &LoadableSegment,
) -> Result<(), ElfLoadError> {
    let permissions = translate_segment_flags_to_user_page_permissions(segment.flags)?;
    let page_flags = build_user_page_table_flags(permissions);
    allocate_and_map_pages_for_segment(user_page_map_level_4, segment, page_flags)?;
    copy_segment_bytes_into_user_pages(user_page_map_level_4, elf_module_bytes, segment)?;
    zero_fill_bss_portion_of_segment(user_page_map_level_4, segment)?;
    Ok(())
}

/// Translates the toolchain-neutral `UserPageMappingPermissions` from
/// `elf_loader` into x86_64 `PageTableFlags`. Always sets `PRESENT` and
/// `USER_ACCESSIBLE`; adds `WRITABLE` and/or `NO_EXECUTE` to match the
/// permission request.
fn build_user_page_table_flags(permissions: UserPageMappingPermissions) -> PageTableFlags {
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if permissions.writable {
        flags |= PageTableFlags::WRITABLE;
    }
    if !permissions.executable {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    flags
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn allocate_and_map_pages_for_segment(
    user_page_map_level_4: &mut PageTable,
    segment: &LoadableSegment,
    page_flags: PageTableFlags,
) -> Result<(), ElfLoadError> {
    let start_virtual_address = align_down_to_page_boundary(segment.virtual_address);
    let end_virtual_address =
        align_up_to_page_boundary(segment.virtual_address + segment.memory_size);
    let mut current_virtual_address = start_virtual_address;
    while current_virtual_address < end_virtual_address {
        allocate_and_map_one_page(user_page_map_level_4, current_virtual_address, page_flags)?;
        current_virtual_address = current_virtual_address.wrapping_add(PAGE_SIZE_IN_BYTES as u64);
    }
    Ok(())
}

unsafe fn allocate_and_map_one_page(
    user_page_map_level_4: &mut PageTable,
    virtual_address: u64,
    page_flags: PageTableFlags,
) -> Result<(), ElfLoadError> {
    let physical_address = allocate_one_user_page()?;
    kernel_page_table::map_single_page_in_root(
        user_page_map_level_4,
        virtual_address,
        PhysAddr::new(physical_address),
        page_flags,
    )
    .map_err(|_| ElfLoadError::UserPageTableWalkFailed)
}

unsafe fn allocate_one_user_page() -> Result<u64, ElfLoadError> {
    let allocator_pointer = global_physical_allocator_pointer();
    (*allocator_pointer)
        .allocate_user_page()
        .map_err(|_| ElfLoadError::PageAllocationFailed)
}

#[allow(clippy::arithmetic_side_effects)]
fn align_down_to_page_boundary(address: u64) -> u64 {
    address & !(PAGE_SIZE_IN_BYTES as u64 - 1)
}

#[allow(clippy::arithmetic_side_effects)]
fn align_up_to_page_boundary(address: u64) -> u64 {
    align_down_to_page_boundary(address + PAGE_SIZE_IN_BYTES as u64 - 1)
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn copy_segment_bytes_into_user_pages(
    user_page_map_level_4: &mut PageTable,
    elf_module_bytes: &[u8],
    segment: &LoadableSegment,
) -> Result<(), ElfLoadError> {
    let source_start = segment.file_offset as usize;
    let source_end = source_start + segment.file_size as usize;
    if source_end > elf_module_bytes.len() {
        return Err(ElfLoadError::SegmentOutOfBounds);
    }
    let source_slice = &elf_module_bytes[source_start..source_end];
    copy_bytes_through_user_mapping(user_page_map_level_4, segment.virtual_address, source_slice)
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn zero_fill_bss_portion_of_segment(
    user_page_map_level_4: &mut PageTable,
    segment: &LoadableSegment,
) -> Result<(), ElfLoadError> {
    if segment.memory_size <= segment.file_size {
        return Ok(());
    }
    let bss_start_virtual_address = segment.virtual_address + segment.file_size;
    let bss_byte_count = (segment.memory_size - segment.file_size) as usize;
    write_zero_bytes_through_user_mapping(
        user_page_map_level_4,
        bss_start_virtual_address,
        bss_byte_count,
    )
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn copy_bytes_through_user_mapping(
    user_page_map_level_4: &mut PageTable,
    destination_virtual_address: u64,
    source_bytes: &[u8],
) -> Result<(), ElfLoadError> {
    for (byte_index, source_byte) in source_bytes.iter().enumerate() {
        let destination_address = destination_virtual_address + byte_index as u64;
        write_one_byte_to_user_address(user_page_map_level_4, destination_address, *source_byte)?;
    }
    Ok(())
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn write_zero_bytes_through_user_mapping(
    user_page_map_level_4: &mut PageTable,
    destination_virtual_address: u64,
    byte_count: usize,
) -> Result<(), ElfLoadError> {
    for byte_index in 0..byte_count {
        let destination_address = destination_virtual_address + byte_index as u64;
        write_one_byte_to_user_address(user_page_map_level_4, destination_address, 0)?;
    }
    Ok(())
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn write_one_byte_to_user_address(
    user_page_map_level_4: &mut PageTable,
    destination_virtual_address: u64,
    byte_value: u8,
) -> Result<(), ElfLoadError> {
    // resolve_mapped_physical_address returns the FRAME base (page-offset bits
    // masked off). Add the intra-page offset so each byte lands at its true
    // physical address — otherwise every byte of a page overwrites frame+0,
    // leaving the page zero-filled except for the last byte written.
    let frame_physical_address =
        resolve_user_virtual_to_physical(user_page_map_level_4, destination_virtual_address)?;
    let page_offset = destination_virtual_address & (PAGE_SIZE_IN_BYTES as u64 - 1);
    let byte_physical_address = frame_physical_address + page_offset;
    let direct_map_pointer = DIRECT_MAP_REGION_START.wrapping_add(byte_physical_address) as *mut u8;
    core::ptr::write_volatile(direct_map_pointer, byte_value);
    Ok(())
}

unsafe fn resolve_user_virtual_to_physical(
    user_page_map_level_4: &mut PageTable,
    virtual_address: u64,
) -> Result<u64, ElfLoadError> {
    kernel_page_table::resolve_mapped_physical_address(user_page_map_level_4, virtual_address)
        .map_err(|_| ElfLoadError::UserPageTableWalkFailed)
}

/// Allocates `compute_total_stack_pages()` user pages from the physical
/// allocator and maps them into `user_page_map_level_4` at the stack
/// region defined by `layout`. The guard page (`layout.guard_page_virtual_address`)
/// is intentionally left unmapped — INV-MEM-007 is structural.
///
/// # Safety
/// Called only during boot, single-core, no concurrent access to the
/// global physical allocator or the supplied PML4.
#[allow(clippy::arithmetic_side_effects)]
pub unsafe fn map_stack_pages_in_user_page_table(
    user_page_map_level_4: &mut PageTable,
    layout: &ProcessAddressSpaceLayout,
) -> Result<(), ElfLoadError> {
    let stack_page_flags = build_user_stack_page_flags();
    let stack_bottom = compute_stack_bottom_address();
    let stack_page_count = compute_total_stack_pages();
    map_stack_pages_in_range(
        user_page_map_level_4,
        stack_bottom,
        stack_page_count,
        stack_page_flags,
    )?;
    let _ = layout;
    Ok(())
}

fn build_user_stack_page_flags() -> PageTableFlags {
    PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE
}

#[allow(clippy::arithmetic_side_effects)]
unsafe fn map_stack_pages_in_range(
    user_page_map_level_4: &mut PageTable,
    stack_bottom_virtual_address: u64,
    stack_page_count: usize,
    page_flags: PageTableFlags,
) -> Result<(), ElfLoadError> {
    for stack_page_index in 0..stack_page_count {
        let virtual_address =
            stack_bottom_virtual_address + (stack_page_index as u64) * (PAGE_SIZE_IN_BYTES as u64);
        allocate_and_map_one_page(user_page_map_level_4, virtual_address, page_flags)?;
    }
    Ok(())
}
