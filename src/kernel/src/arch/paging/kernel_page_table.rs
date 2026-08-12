//! Kernel page table hierarchy construction.
//!
//! Builds the kernel PML4 -> PDPT -> PD -> PT hierarchy using BSS-backed
//! page table pages to avoid the chicken-and-egg problem: the direct map
//! does not exist yet when we are building it.
//!
//! Physical addresses of BSS pages are computed via the known VA-to-PA offset:
//!   physical = virtual - KERNEL_BINARY_VIRTUAL_ADDRESS + KERNEL_PHYSICAL_LOAD_ADDRESS
//!
//! Security invariants enforced:
//! - INV-MEM-003: W^X validator called before every entry write
//! - INV-MEM-007: Guard page (INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS) is never mapped
//!
//! Allowlist: src/kernel/src/arch/paging/ (UNSAFE_CODE_POLICY.md)
#![allow(unsafe_code)]

use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use crate::arch::paging::direct_map::map_direct_map_region;
use crate::arch::paging::mapping_error::MappingError;
use crate::arch::paging::page_table_flags_validator::{
    compute_kernel_code_page_flags, compute_kernel_data_page_flags,
    validate_page_table_flags_enforce_write_xor_execute,
};
use crate::arch::paging::page_table_walk_helpers::{
    compute_intermediate_page_table_flags, compute_page_table_physical_address,
    extract_page_directory_index, extract_page_directory_pointer_table_index,
    extract_page_map_level_4_index, extract_page_table_index,
    retrieve_page_table_by_physical_address, KERNEL_PHYSICAL_LOAD_ADDRESS,
};
use crate::boot::logger::BootStepLogger;
use crate::memory::virtual_address_layout::{
    INITIAL_KERNEL_STACK_BOTTOM, INITIAL_KERNEL_STACK_TOP, KERNEL_BINARY_VIRTUAL_ADDRESS,
    KERNEL_STACK_REGION_START, PAGE_SIZE_IN_BYTES, POOL_REGION_START,
};

/// Number of bootstrap page table pages available in BSS.
const BOOTSTRAP_PAGE_TABLE_PAGE_COUNT: usize = 32;

/// Total number of 4KB pages in the kernel binary region to map.
///
/// Must cover the kernel ELF's full LOAD extent (.text, .rodata, .data,
/// .bss). The current build's last PT_LOAD ends near physical 0x46D000
/// (~3.5 MiB above KERNEL_PHYSICAL_LOAD_ADDRESS), driven mostly by the
/// PhysicalAllocator's fixed-size tracking tables and other BSS
/// statics. Round to 1024 pages (4 MiB) so the kernel's own data
/// stays mapped after the Phase 4 CR3 swap retires the bootloader's
/// identity map. A smaller value silently relies on the bootloader's
/// identity map and breaks at the moment of CR3 load. The compile-time
/// overlap assertion in `boot::multiboot2_info` guards against this
/// region growing into the boot stack at 0x808000.
///
/// `boot::multiboot2_info` derives the physical allocator's kernel-binary
/// exclusion range from this so the allocator never hands out a frame that
/// is mapped into the kernel binary region.
pub const KERNEL_BINARY_PAGE_COUNT: u64 = 1024;

/// Physical extent the direct-map region must cover.
///
/// The direct map has to reach every physical frame the
/// `PhysicalAllocator` can return. That allocator tracks up to its maximum
/// supported physical range (1 GiB) and hands out the highest free frame
/// first (LIFO over an ascending enrollment), so the very first
/// `allocate_user_page` returns a frame near the top of installed RAM. A
/// direct map smaller than RAM faults the instant such a frame is zeroed
/// or written through `DIRECT_MAP_REGION_START + phys`. One GiB of 2 MiB
/// huge pages fits in a single page directory, so this costs no extra
/// direct-map bootstrap tables versus the previous 128 MiB value.
const DIRECT_MAP_PHYSICAL_COVERAGE_IN_BYTES: u64 = 1024 * 1024 * 1024;

/// Physical base of the boot stack the bootloader hands to the kernel.
///
/// `src/bootloader/src/main.rs` lays out a 32 KiB stack spanning physical
/// 0x808000..0x810000 (`bootloader_stack_bottom`..`bootloader_stack_top`);
/// the kernel runs its entire boot sequence on it.
///
/// `boot::multiboot2_info` derives the physical allocator's boot-stack
/// exclusion range from this so the live kernel stack is never handed out.
pub const BOOT_STACK_PHYSICAL_BASE_ADDRESS: u64 = 0x0080_8000;

/// Number of 4 KiB pages in the 32 KiB boot stack region.
pub const BOOT_STACK_PAGE_COUNT: u64 = 8;

/// Page-aligned BSS-backed storage for bootstrap page table pages.
///
/// Each entry is a full 4096-byte page table. Aligned to 4096 bytes so
/// the x86 MMU accepts them as valid page table roots.
///
/// SAFETY: Accessed only during single-threaded boot via addr_of_mut!.
/// No concurrent access is possible before the scheduler is initialized.
#[repr(align(4096))]
struct AlignedPageTableBlock {
    tables: [PageTable; BOOTSTRAP_PAGE_TABLE_PAGE_COUNT],
}

static mut BOOTSTRAP_PAGE_TABLE_BLOCK: AlignedPageTableBlock = AlignedPageTableBlock {
    tables: [const { PageTable::new() }; BOOTSTRAP_PAGE_TABLE_PAGE_COUNT],
};

/// Index of the next free bootstrap page table slot.
static mut NEXT_BOOTSTRAP_PAGE_TABLE_INDEX: usize = 0;

/// Kernel PML4 (top-level page table). Lives in BSS, 4096-byte aligned.
static mut KERNEL_PAGE_MAP_LEVEL_4: PageTable = PageTable::new();

/// Allocates the next available bootstrap page table from BSS.
///
/// Returns a mutable reference to a zeroed PageTable from the BSS pool.
/// Panics if the bootstrap pool is exhausted.
fn allocate_bootstrap_page_table() -> &'static mut PageTable {
    // SAFETY: Single-threaded boot only. addr_of_mut! avoids mutable-static-reference UB.
    // - Precondition: called only during boot before scheduler starts.
    // - Invariant: INV-MEM-003 (page table pages never executable -- only written to).
    // - Evidence: boot sequence is single-threaded; no concurrent access possible.
    let index = unsafe { *core::ptr::addr_of!(NEXT_BOOTSTRAP_PAGE_TABLE_INDEX) };
    assert!(
        index < BOOTSTRAP_PAGE_TABLE_PAGE_COUNT,
        "bootstrap page table pool exhausted"
    );
    unsafe {
        *core::ptr::addr_of_mut!(NEXT_BOOTSTRAP_PAGE_TABLE_INDEX) = index.wrapping_add(1);
        &mut (*core::ptr::addr_of_mut!(BOOTSTRAP_PAGE_TABLE_BLOCK)).tables[index]
    }
}

/// Allocates a bootstrap page table and sets a parent entry to point at it.
///
/// `intermediate_flags` carries the USER_ACCESSIBLE bit down from the leaf
/// mapping: the x86-64 walk ANDs U/S across every level, so a user leaf is only
/// reachable from ring 3 if every table on its path is also user-accessible.
fn allocate_and_link_bootstrap_table(
    parent_entry: &mut PageTableEntry,
    intermediate_flags: PageTableFlags,
) -> &'static mut PageTable {
    let new_table = allocate_bootstrap_page_table();
    let physical_address = compute_page_table_physical_address(new_table);
    parent_entry.set_addr(physical_address, intermediate_flags);
    new_table
}

/// Derives the intermediate-table flags for a leaf mapping. Always
/// PRESENT | WRITABLE; adds USER_ACCESSIBLE iff the leaf itself is user-accessible
/// (kernel mappings keep supervisor-only intermediates — defense in depth).
fn compute_intermediate_flags_for_leaf(leaf_flags: PageTableFlags) -> PageTableFlags {
    let mut flags = compute_intermediate_page_table_flags();
    if leaf_flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        flags |= PageTableFlags::USER_ACCESSIBLE;
    }
    flags
}

/// Ensures the PML4 entry at the given index points to a PDPT.
///
/// If not present, allocates a new bootstrap PDPT and sets the entry.
/// Returns a mutable reference to the PDPT.
fn ensure_page_directory_pointer_table_exists(
    page_map_level_4: &mut PageTable,
    pml4_index: usize,
    intermediate_flags: PageTableFlags,
) -> &'static mut PageTable {
    if page_map_level_4[pml4_index].is_unused() {
        allocate_and_link_bootstrap_table(&mut page_map_level_4[pml4_index], intermediate_flags)
    } else {
        // SAFETY: physical address was stored by allocate_and_link_bootstrap_table above.
        // - Precondition: entry is non-empty, meaning we stored a BSS bootstrap table address.
        // - Invariant: INV-MEM-003 (structure only written with validated entries).
        // - Evidence: only called on addresses we previously placed in page table entries.
        unsafe { retrieve_page_table_by_physical_address(page_map_level_4[pml4_index].addr()) }
    }
}

/// Ensures the PDPT entry at the given index points to a PD.
fn ensure_page_directory_exists(
    page_directory_pointer_table: &mut PageTable,
    pdpt_index: usize,
    intermediate_flags: PageTableFlags,
) -> &'static mut PageTable {
    if page_directory_pointer_table[pdpt_index].is_unused() {
        allocate_and_link_bootstrap_table(
            &mut page_directory_pointer_table[pdpt_index],
            intermediate_flags,
        )
    } else {
        // SAFETY: physical address was stored by allocate_and_link_bootstrap_table above.
        // - Precondition: entry is non-empty; we stored a BSS bootstrap table address.
        // - Invariant: INV-MEM-003 (entries validated before write).
        // - Evidence: only called on addresses we previously placed in page table entries.
        unsafe {
            retrieve_page_table_by_physical_address(page_directory_pointer_table[pdpt_index].addr())
        }
    }
}

/// Ensures the PD entry at the given index points to a PT.
fn ensure_page_table_exists(
    page_directory: &mut PageTable,
    page_directory_index: usize,
    intermediate_flags: PageTableFlags,
) -> &'static mut PageTable {
    if page_directory[page_directory_index].is_unused() {
        allocate_and_link_bootstrap_table(
            &mut page_directory[page_directory_index],
            intermediate_flags,
        )
    } else {
        // SAFETY: physical address was stored by allocate_and_link_bootstrap_table above.
        // - Precondition: entry is non-empty; we stored a BSS bootstrap table address.
        // - Invariant: INV-MEM-003 (entries validated before write).
        // - Evidence: only called on addresses we previously placed in page table entries.
        unsafe {
            retrieve_page_table_by_physical_address(page_directory[page_directory_index].addr())
        }
    }
}

/// Walks PML4 -> PDPT -> PD levels for a virtual address.
///
/// Returns a mutable reference to the page directory for the address.
fn resolve_page_directory_for_address(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
    intermediate_flags: PageTableFlags,
) -> &'static mut PageTable {
    let pml4_index = extract_page_map_level_4_index(virtual_address);
    let pdpt_index = extract_page_directory_pointer_table_index(virtual_address);
    let page_directory_pointer_table = ensure_page_directory_pointer_table_exists(
        page_map_level_4,
        pml4_index,
        intermediate_flags,
    );
    ensure_page_directory_exists(page_directory_pointer_table, pdpt_index, intermediate_flags)
}

/// Walks the full PML4 -> PDPT -> PD -> PT hierarchy for a virtual address.
///
/// Returns the leaf page table and the PT index for the given virtual address.
fn resolve_page_table_for_address(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
    intermediate_flags: PageTableFlags,
) -> (&'static mut PageTable, usize) {
    let page_directory =
        resolve_page_directory_for_address(page_map_level_4, virtual_address, intermediate_flags);
    let page_directory_index = extract_page_directory_index(virtual_address);
    let page_table_index = extract_page_table_index(virtual_address);
    let page_table =
        ensure_page_table_exists(page_directory, page_directory_index, intermediate_flags);
    (page_table, page_table_index)
}

/// Maps one 4KB page in the kernel page table with W^X validation.
///
/// Maps virtual_address -> physical_address with the given flags.
/// Returns an error if W^X validation fails.
fn map_single_page(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
    physical_address: PhysAddr,
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    validate_page_table_flags_enforce_write_xor_execute(flags)?;
    let intermediate_flags = compute_intermediate_flags_for_leaf(flags);
    let (page_table, page_table_index) =
        resolve_page_table_for_address(page_map_level_4, virtual_address, intermediate_flags);
    write_page_table_entry(page_table, page_table_index, physical_address, flags);
    Ok(())
}

/// Public wrapper around `map_single_page` for callers that need to map
/// into an arbitrary PML4 root (e.g., a per-process user page table).
///
/// # Safety
/// Caller must hold exclusive access to `page_map_level_4` (single-threaded
/// boot or process-creation hot path). Behaves identically to the private
/// `map_single_page` — W^X is validated; intermediate page-table pages are
/// allocated from the same BSS bootstrap pool the kernel side uses.
pub unsafe fn map_single_page_in_root(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
    physical_address: PhysAddr,
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    map_single_page(page_map_level_4, virtual_address, physical_address, flags)
}

/// Walks `page_map_level_4` for `virtual_address` and returns the physical
/// address of the 4 KiB page it maps. Returns `MappingError::InvalidAddress`
/// if the leaf entry is unused (the virtual address is not mapped).
///
/// # Safety
/// Caller must hold exclusive access to `page_map_level_4`.
pub unsafe fn resolve_mapped_physical_address(
    page_map_level_4: &mut PageTable,
    virtual_address: u64,
) -> Result<u64, MappingError> {
    // Read-only walk: the leaf was already mapped, so every table on the path
    // exists and ensure_* never allocates — these flags are inert here.
    let (page_table, page_table_index) = resolve_page_table_for_address(
        page_map_level_4,
        virtual_address,
        compute_intermediate_page_table_flags(),
    );
    let entry = &page_table[page_table_index];
    if entry.is_unused() {
        return Err(MappingError::InvalidAddress);
    }
    Ok(entry.addr().as_u64())
}

/// Allocates one bootstrap page-table page from BSS and returns a mutable
/// reference. Used by per-process user-page-table construction to obtain
/// a fresh user PML4 root that lives in long-lived BSS storage.
///
/// # Safety
/// Single-threaded boot only; concurrent calls would race the bootstrap
/// allocator's index counter.
pub unsafe fn allocate_user_page_map_level_4() -> &'static mut PageTable {
    allocate_bootstrap_page_table()
}

/// Writes a validated page table entry.
///
/// # Safety contract
/// Called only after validate_page_table_flags_enforce_write_xor_execute succeeds.
fn write_page_table_entry(
    page_table: &mut PageTable,
    page_table_index: usize,
    physical_address: PhysAddr,
    flags: PageTableFlags,
) {
    // SAFETY: page_table is a valid BSS-backed PageTable. page_table_index is in [0, 511].
    // physical_address was validated by the caller. Flags were W^X validated.
    // - Precondition: page_table allocated from BOOTSTRAP_PAGE_TABLE_BLOCK or KERNEL_PAGE_MAP_LEVEL_4.
    // - Invariant: INV-MEM-003 (W^X already validated by caller).
    // - Evidence: test_writable_and_executable_flags_are_rejected in page_table_flags_validator.
    page_table[page_table_index].set_addr(physical_address, flags);
}

/// Maps the kernel binary region (code and read-only data pages).
///
/// Maps virtual KERNEL_BINARY_VIRTUAL_ADDRESS -> physical KERNEL_PHYSICAL_LOAD_ADDRESS.
/// Code pages use PRESENT (no WRITABLE, no NO_EXECUTE = executable read-only).
fn map_kernel_binary_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    let code_flags = compute_kernel_code_page_flags();
    map_page_range(
        page_map_level_4,
        KERNEL_BINARY_VIRTUAL_ADDRESS,
        KERNEL_PHYSICAL_LOAD_ADDRESS,
        KERNEL_BINARY_PAGE_COUNT,
        code_flags,
    )
}

/// Maps a range of consecutive pages.
#[allow(clippy::arithmetic_side_effects)]
fn map_page_range(
    page_map_level_4: &mut PageTable,
    virtual_start: u64,
    physical_start: u64,
    page_count: u64,
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    for page_index in 0..page_count {
        let virtual_address = virtual_start + page_index * PAGE_SIZE_IN_BYTES as u64;
        let physical_address =
            PhysAddr::new(physical_start + page_index * PAGE_SIZE_IN_BYTES as u64);
        map_single_page(page_map_level_4, virtual_address, physical_address, flags)?;
    }
    Ok(())
}

/// Maps the kernel stack region, skipping the guard page.
///
/// Maps from INITIAL_KERNEL_STACK_BOTTOM to INITIAL_KERNEL_STACK_TOP.
/// INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS is NOT mapped (enforces INV-MEM-007).
#[allow(clippy::arithmetic_side_effects)]
fn map_kernel_stack_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    let data_flags = compute_kernel_data_page_flags();
    let stack_virtual_start = INITIAL_KERNEL_STACK_BOTTOM;
    let stack_size_in_bytes = INITIAL_KERNEL_STACK_TOP - INITIAL_KERNEL_STACK_BOTTOM;
    let page_count = stack_size_in_bytes / PAGE_SIZE_IN_BYTES as u64;
    let physical_start = compute_kernel_stack_physical_address(stack_virtual_start);
    map_page_range(
        page_map_level_4,
        stack_virtual_start,
        physical_start,
        page_count,
        data_flags,
    )
}

/// Computes the physical address corresponding to the kernel stack virtual address.
///
/// For Phase 2 (page table build only, no CR3 switch), physical addresses are
/// placeholders. Phase 4 handles correct physical allocation when loading CR3.
#[allow(clippy::arithmetic_side_effects)]
fn compute_kernel_stack_physical_address(stack_virtual_address: u64) -> u64 {
    let stack_region_offset = stack_virtual_address - KERNEL_STACK_REGION_START;
    KERNEL_PHYSICAL_LOAD_ADDRESS + 0x0010_0000 + stack_region_offset
}

/// Maps the pool region (placeholder -- no objects in Phase 2).
///
/// Maps one page at POOL_REGION_START as data (NO_EXECUTE | WRITABLE).
/// Phase 3+ will populate this region with object pools.
fn map_pool_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    let data_flags = compute_kernel_data_page_flags();
    let physical_address = PhysAddr::new(KERNEL_PHYSICAL_LOAD_ADDRESS + 0x0020_0000);
    map_single_page(
        page_map_level_4,
        POOL_REGION_START,
        physical_address,
        data_flags,
    )
}

/// Maps all kernel regions into the given PML4.
///
/// Enforces INV-MEM-003 (W^X) on every mapping.
/// Enforces INV-MEM-007 (guard page never mapped) via map_kernel_stack_region.
#[allow(clippy::expect_used)]
fn map_all_kernel_regions(page_map_level_4: &mut PageTable, boot_step_logger: &mut BootStepLogger) {
    map_kernel_binary_region(page_map_level_4).expect("kernel binary region mapping failed");
    map_kernel_stack_region(page_map_level_4).expect("kernel stack region mapping failed");
    map_boot_stack_identity_region(page_map_level_4).expect("boot stack identity mapping failed");
    map_pool_region(page_map_level_4).expect("pool region mapping failed");
    map_local_apic_mmio_region(page_map_level_4).expect("LAPIC MMIO region mapping failed");
    map_tpm_tis_mmio_region(page_map_level_4).expect("TPM TIS MMIO region mapping failed");
    map_direct_map_region(
        page_map_level_4,
        DIRECT_MAP_PHYSICAL_COVERAGE_IN_BYTES,
        boot_step_logger,
    );
}

/// Identity-maps the boot stack's physical region into the kernel PML4.
///
/// The bootloader's boot stack lives at physical 0x808000..0x810000 and the
/// kernel executes its whole boot sequence on it. `initialize_ipc_subsystem`
/// rebases RSP onto the direct-map view of this region at the CR3 swap, but
/// frame-pointer-relative locals and `&stack` references materialized before
/// the swap keep their low identity addresses. Without an identity mapping in
/// the kernel PML4 those pointers fault the instant the CR3 load retires the
/// bootloader's identity map. Mapping the region at its identity address keeps
/// every stack pointer -- low identity or direct-map -- valid across the swap.
fn map_boot_stack_identity_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    let data_flags = compute_kernel_data_page_flags();
    map_page_range(
        page_map_level_4,
        BOOT_STACK_PHYSICAL_BASE_ADDRESS,
        BOOT_STACK_PHYSICAL_BASE_ADDRESS,
        BOOT_STACK_PAGE_COUNT,
        data_flags,
    )
}

/// Identity-maps the local APIC MMIO page (0xFEE00000) into the kernel PML4.
///
/// The scheduler timer (`arch::timer`) writes to LAPIC registers using their
/// physical addresses (0xFEE00000-0xFEE00FFF) as virtual addresses. The
/// bootloader's identity map provided that mapping during early boot; the
/// kernel's KPTI PML4 must re-establish it before the CR3 swap, otherwise
/// the first APIC write page-faults.
///
/// Maps a single 4 KiB page with PRESENT | WRITABLE | NO_EXECUTE | NO_CACHE
/// | WRITE_THROUGH — strong-uncacheable semantics required for MMIO.
fn map_local_apic_mmio_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    const LOCAL_APIC_PHYSICAL_BASE_ADDRESS: u64 = 0xFEE0_0000;
    identity_map_strong_uncacheable_page(page_map_level_4, LOCAL_APIC_PHYSICAL_BASE_ADDRESS)
}

/// Identity-maps the TPM TIS MMIO page (0xFED40000) into the kernel PML4.
///
/// `hardware_security::pcr_measurement` reads/writes TPM TIS registers using
/// their physical addresses as virtual addresses. The bootloader's identity
/// map covered this during early boot; the kernel PML4 must re-establish it
/// before the CR3 swap.
fn map_tpm_tis_mmio_region(page_map_level_4: &mut PageTable) -> Result<(), MappingError> {
    const TPM_TIS_PHYSICAL_BASE_ADDRESS: u64 = 0xFED4_0000;
    identity_map_strong_uncacheable_page(page_map_level_4, TPM_TIS_PHYSICAL_BASE_ADDRESS)
}

/// Identity-maps a single 4 KiB page as strong-uncacheable MMIO.
///
/// PRESENT | WRITABLE | NO_EXECUTE | NO_CACHE | WRITE_THROUGH — the standard
/// flag set for memory-mapped device registers. The virtual address equals
/// the physical address so existing code paths that treat the physical
/// address as a virtual pointer continue to work after the KPTI CR3 swap.
fn identity_map_strong_uncacheable_page(
    page_map_level_4: &mut PageTable,
    physical_base_address: u64,
) -> Result<(), MappingError> {
    let mmio_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::NO_CACHE
        | PageTableFlags::WRITE_THROUGH;
    map_single_page(
        page_map_level_4,
        physical_base_address,
        PhysAddr::new(physical_base_address),
        mmio_flags,
    )
}

/// Identity-maps `page_count` strong-uncacheable MMIO pages starting at
/// `physical_base_address` into the live kernel PML4. Used to map a device's
/// register BAR (discovered at runtime via PCI) so the kernel can drive it.
///
/// # Safety
/// Single-core boot; `physical_base_address` must be a real device MMIO BAR.
/// Newly-present mappings need no TLB shootdown (x86 does not cache
/// not-present entries).
pub unsafe fn map_mmio_region_into_kernel(
    physical_base_address: u64,
    page_count: usize,
) -> Result<(), MappingError> {
    let page_map_level_4 = acquire_kernel_page_map_level_4_reference();
    for page_index in 0..page_count {
        let page_physical =
            physical_base_address.wrapping_add((page_index as u64).wrapping_mul(4096));
        identity_map_strong_uncacheable_page(page_map_level_4, page_physical)?;
    }
    Ok(())
}

/// Translates a kernel virtual address to its physical address by walking the
/// live kernel PML4. Robust to non-contiguous .bss placement (unlike the fixed
/// image-offset `compute_physical_address_of_bss_page`), so it gives the TRUE
/// physical address a device must DMA to. Returns `None` if unmapped.
///
/// # Safety-adjacent
/// Single-core boot; the kernel PML4 is the active address space.
pub fn kernel_virtual_to_physical(virtual_address: u64) -> Option<u64> {
    let page_map_level_4 = acquire_kernel_page_map_level_4_reference();
    // SAFETY: kernel PML4 is valid and active; resolve walks it read-only (the
    // address is already mapped, so no intermediate tables are allocated).
    let frame_base =
        unsafe { resolve_mapped_physical_address(page_map_level_4, virtual_address) }.ok()?;
    Some(frame_base | (virtual_address & 0xFFF))
}

/// Acquires a mutable reference to the kernel PML4 during single-threaded boot.
fn acquire_kernel_page_map_level_4_reference() -> &'static mut PageTable {
    // SAFETY: KERNEL_PAGE_MAP_LEVEL_4 is accessed only during single-threaded boot.
    // addr_of_mut! avoids mutable-static-reference UB (Pitfall 5 from RESEARCH.md).
    // - Precondition: called before scheduler starts; no concurrent access.
    // - Invariant: INV-MEM-003 enforced by W^X validator on every map_single_page call.
    // - Evidence: test_writable_and_executable_flags_are_rejected.
    unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_PAGE_MAP_LEVEL_4) }
}

/// Returns the physical address of the kernel PML4 for loading into CR3.
///
/// The PML4 lives in BSS (`KERNEL_PAGE_MAP_LEVEL_4`). Its physical address is
/// computed from the known VA-to-PA offset established by the linker script.
///
/// Call this after `build_kernel_page_table` and before `initialize_ipc_subsystem`
/// to obtain the address to pass to the CR3 load (D-09).
///
/// Enforces INV-MEM-001 and INV-MEM-002 indirectly: the page tables at this
/// address have KPTI-compliant structure by construction (Phase 2 invariant).
pub fn kernel_page_map_level_4_physical_address() -> u64 {
    let page_map_level_4 = acquire_kernel_page_map_level_4_reference();
    compute_page_table_physical_address(page_map_level_4).as_u64()
}

/// Constructs the kernel page table hierarchy.
///
/// Maps: kernel binary, kernel stack (skipping guard page), pool region, direct map.
/// Does NOT load into CR3 (deferred to Phase 4 per D-08).
pub fn build_kernel_page_table(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.step("Building kernel page table hierarchy");
    let page_map_level_4 = acquire_kernel_page_map_level_4_reference();
    map_all_kernel_regions(page_map_level_4, boot_step_logger);
    boot_step_logger.ok("Kernel page table constructed (CR3 switch deferred to Phase 4)");
}

/// Clears the writable flag (bit 1) in the level-one page table entry for a virtual page.
///
/// After this call, any write to the page generates a page fault. Called by
/// `kernel_write_protection::write_protect_page_range` to flip kernel `.text` and
/// `.rodata` pages to read-only after init (D-15).
///
/// # Safety
/// - `entry` must point to a valid, mapped level-1 page table entry.
/// - Caller must flush the TLB for this address after modification.
/// - Precondition: entry is a valid PTE reference obtained from a mapped page table walk.
/// - Invariant: INV-MEM-004 (kernel executable regions become immutable after init).
/// - Evidence: test_clear_writable_flag_removes_writable_bit
pub fn clear_writable_flag_in_level_one_page_table_entry(entry: &mut u64) {
    const PAGE_TABLE_ENTRY_WRITABLE_BIT: u64 = 1 << 1;
    let current_value = *entry;
    let updated_value = current_value & !PAGE_TABLE_ENTRY_WRITABLE_BIT;
    // SAFETY: Modifying a PTE to remove the writable bit. Non-destructive: makes page
    // read-only without unmapping it. Entry is a valid mapped PTE from a page table walk.
    // - Precondition: entry points to a valid mapped level-1 PTE.
    // - Invariant: INV-MEM-004 (kernel executable regions become immutable after init).
    // - Evidence: test_clear_writable_flag_removes_writable_bit
    unsafe { core::ptr::write_volatile(entry as *mut u64, updated_value) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies clearing the writable bit removes bit 1 from the entry value.
    ///
    /// Enforces INV-MEM-004: kernel executable regions become immutable after init.
    /// Verified by: test_clear_writable_flag_removes_writable_bit
    #[test]
    fn test_clear_writable_flag_removes_writable_bit() {
        const PRESENT_BIT: u64 = 1;
        const WRITABLE_BIT: u64 = 1 << 1;
        let mut entry_value: u64 = PRESENT_BIT | WRITABLE_BIT | 0x1000;
        clear_writable_flag_in_level_one_page_table_entry(&mut entry_value);
        let writable_bit_is_clear = (entry_value & WRITABLE_BIT) == 0;
        assert!(
            writable_bit_is_clear,
            "writable bit must be cleared after protection"
        );
    }

    /// Verifies clearing the writable bit preserves all other bits.
    #[test]
    fn test_clear_writable_flag_preserves_other_bits() {
        const WRITABLE_BIT: u64 = 1 << 1;
        let original_value: u64 = 0xFFFF_FFFF_FFFF_FFFF;
        let mut entry_value = original_value;
        clear_writable_flag_in_level_one_page_table_entry(&mut entry_value);
        let expected_value = original_value & !WRITABLE_BIT;
        assert_eq!(
            entry_value, expected_value,
            "only writable bit must be cleared"
        );
    }

    /// Verifies clearing writable bit on an already read-only entry is idempotent.
    #[test]
    fn test_clear_writable_flag_is_idempotent() {
        const PRESENT_BIT: u64 = 1;
        let mut entry_value: u64 = PRESENT_BIT | 0x1000;
        let value_after_first_call = {
            clear_writable_flag_in_level_one_page_table_entry(&mut entry_value);
            entry_value
        };
        clear_writable_flag_in_level_one_page_table_entry(&mut entry_value);
        assert_eq!(
            entry_value, value_after_first_call,
            "second call must not change value"
        );
    }
}
