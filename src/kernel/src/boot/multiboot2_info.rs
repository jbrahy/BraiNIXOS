//! Multiboot2 info pointer validation, memory map parsing, and physical
//! allocator population.
//!
//! Validates the multiboot2 magic value and info pointer at boot,
//! then parses the memory map to discover physical RAM regions and
//! populate the global physical allocator.
//!
//! Allowlist: `src/kernel/src/boot/` -- raw address manipulation for identity
//! mapping, multiboot2 info parsing, and global mutable state (addr_of_mut!).
#![allow(unsafe_code)]

use crate::arch::interrupts::halt::disable_interrupts_and_halt;
use crate::boot::logger::BootStepLogger;
use crate::memory::page_type::PageType;
use crate::memory::physical_allocator::PhysicalAllocator;
use crate::memory::virtual_address_layout::PAGE_SIZE_IN_BYTES;
use multiboot2::BootInformationHeader;

/// The multiboot2 bootloader magic value placed in eax by GRUB.
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D76289;

/// Physical addresses below this threshold are reserved for BIOS/bootloader.
const RESERVED_LOW_MEMORY_BOUNDARY: u64 = 0x100000;

/// Start of the kernel binary physical range (1 MB, standard multiboot2 load address).
const KERNEL_PHYSICAL_START: u64 = 0x100000;

/// End of the kernel binary physical range (conservative 2 MB upper bound).
/// The actual end is determined by linker symbols, but for Phase 2 this
/// conservative bound protects the kernel binary from being overwritten.
const KERNEL_PHYSICAL_END: u64 = 0x200000;

/// Global physical allocator instance. Lives in boot module because
/// addr_of_mut! is only allowlisted here (UNSAFE_CODE_POLICY.md).
static mut GLOBAL_PHYSICAL_ALLOCATOR: PhysicalAllocator = PhysicalAllocator::new();

/// Returns a mutable pointer to the global physical allocator.
///
/// # Safety
/// Single-core, no preemption during boot. Caller must ensure exclusive
/// access via the boot sequence's linear execution model (INV-BOOT-001).
pub unsafe fn global_physical_allocator_pointer() -> *mut PhysicalAllocator {
    core::ptr::addr_of_mut!(GLOBAL_PHYSICAL_ALLOCATOR)
}

/// Initializes the memory subsystem by validating multiboot2 info and
/// parsing the physical memory map.
pub fn initialize_memory_subsystem(
    multiboot2_magic_value: u32,
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    validate_multiboot2_magic(multiboot2_magic_value, multiboot2_info_address, boot_step_logger);
    log_memory_map_discovery(multiboot2_info_address, boot_step_logger);
}

/// Validates that the multiboot2 magic value and info address are correct.
///
/// Enforces decision D-03: wrong magic or null pointer is fatal halt.
/// Verified by: QEMU integration test observes serial output on valid boot.
fn validate_multiboot2_magic(
    multiboot2_magic_value: u32,
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    if multiboot2_magic_value != MULTIBOOT2_BOOTLOADER_MAGIC {
        halt_on_invalid_multiboot2_info(boot_step_logger);
    }
    if multiboot2_info_address == 0 {
        halt_on_invalid_multiboot2_info(boot_step_logger);
    }
    boot_step_logger.ok("Multiboot2 magic and info pointer validated");
}

/// Halts the system fatally when the multiboot2 info is invalid.
fn halt_on_invalid_multiboot2_info(boot_step_logger: &mut BootStepLogger) -> ! {
    boot_step_logger.line("[FATAL] Invalid multiboot2 info pointer -- halting (D-03)");
    disable_interrupts_and_halt()
}

/// Parses the multiboot2 boot information to discover physical memory regions.
///
/// Enforces invariant INV-MEM-005: memory ownership begins with discovery.
/// Verified by: QEMU integration test observes memory map log output.
fn log_memory_map_discovery(
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    let boot_information = load_boot_information(multiboot2_info_address, boot_step_logger);
    populate_allocator_from_boot_information(&boot_information, boot_step_logger);
}

/// Loads the multiboot2 boot information structure from the given address.
fn load_boot_information(
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) -> multiboot2::BootInformation<'static> {
    let header_pointer = multiboot2_info_address as *const BootInformationHeader;
    // SAFETY: multiboot2_info_address was validated as non-zero and is the
    // physical address passed by GRUB in rbx. The bootloader's identity map
    // (0x0..0x200000) makes this address accessible. GRUB is in the TCB.
    // - Precondition: address is non-zero and within identity-mapped region.
    // - Invariant: INV-MEM-005 (memory discovery requires valid boot info).
    // - Evidence: validate_multiboot2_magic confirmed non-zero address.
    let load_result = unsafe { multiboot2::BootInformation::load(header_pointer) };
    unwrap_boot_information_or_halt(load_result, boot_step_logger)
}

/// Unwraps the boot information load result, halting on failure.
fn unwrap_boot_information_or_halt(
    load_result: Result<multiboot2::BootInformation<'static>, multiboot2::LoadError>,
    boot_step_logger: &mut BootStepLogger,
) -> multiboot2::BootInformation<'static> {
    match load_result {
        Ok(boot_information) => boot_information,
        Err(_) => halt_on_invalid_multiboot2_info(boot_step_logger),
    }
}

/// Populates the physical allocator from multiboot2 boot information.
fn populate_allocator_from_boot_information(
    boot_information: &multiboot2::BootInformation<'_>,
    boot_step_logger: &mut BootStepLogger,
) {
    let memory_map_tag = boot_information.memory_map_tag();
    validate_memory_map_tag_present(memory_map_tag, boot_step_logger);
    register_memory_regions_from_map(memory_map_tag.unwrap());
    register_kernel_binary_pages();
    boot_step_logger.ok("Physical allocator initialized from memory map");
}

/// Halts fatally if the memory map tag is absent.
fn validate_memory_map_tag_present(
    memory_map_tag: Option<&multiboot2::MemoryMapTag>,
    boot_step_logger: &mut BootStepLogger,
) {
    if memory_map_tag.is_none() {
        boot_step_logger.line("[FATAL] No memory map tag in multiboot2 info -- halting");
        disable_interrupts_and_halt();
    }
}

/// Iterates all memory areas in the map and registers available regions.
fn register_memory_regions_from_map(memory_map_tag: &multiboot2::MemoryMapTag) {
    for memory_area in memory_map_tag.memory_areas() {
        let region_start = memory_area.start_address();
        let region_end = memory_area.end_address();
        register_available_memory_region(region_start, region_end);
    }
}

/// Registers all page-aligned free pages in the given physical region.
///
/// Skips pages in reserved low memory and kernel binary range.
fn register_available_memory_region(region_start: u64, region_end: u64) {
    let aligned_start = align_address_up_to_page_boundary(region_start);
    let mut current_address = aligned_start;
    while current_address.wrapping_add(PAGE_SIZE_IN_BYTES as u64) <= region_end {
        register_page_if_available(current_address);
        current_address = current_address.wrapping_add(PAGE_SIZE_IN_BYTES as u64);
    }
}

/// Registers a single page as Free if it is not in a reserved range.
fn register_page_if_available(physical_address: u64) {
    if page_is_in_reserved_low_memory(physical_address) {
        return;
    }
    if page_is_in_kernel_binary_range(physical_address) {
        return;
    }
    // SAFETY: Single-core boot, no concurrent access to GLOBAL_PHYSICAL_ALLOCATOR.
    // - Precondition: called only during boot sequence linear execution.
    // - Invariant: INV-MEM-005 (explicit ownership via page registration).
    // - Evidence: boot sequence is single-threaded (INV-BOOT-001).
    let allocator_pointer = unsafe { global_physical_allocator_pointer() };
    // SAFETY: pointer is valid and exclusively accessible during boot.
    unsafe { (*allocator_pointer).register_physical_page(physical_address, PageType::Free) };
}

/// Registers kernel binary physical pages as PageType::Kernel.
fn register_kernel_binary_pages() {
    let mut current_address = KERNEL_PHYSICAL_START;
    while current_address < KERNEL_PHYSICAL_END {
        register_single_kernel_page(current_address);
        current_address = current_address.wrapping_add(PAGE_SIZE_IN_BYTES as u64);
    }
}

/// Registers a single page as kernel-owned in the global allocator.
fn register_single_kernel_page(physical_address: u64) {
    // SAFETY: Single-core boot, exclusive access to GLOBAL_PHYSICAL_ALLOCATOR.
    // - Precondition: called only during boot sequence linear execution.
    // - Invariant: INV-MEM-005 (kernel pages explicitly tagged).
    // - Evidence: boot sequence is single-threaded (INV-BOOT-001).
    let allocator_pointer = unsafe { global_physical_allocator_pointer() };
    unsafe { (*allocator_pointer).register_physical_page(physical_address, PageType::Kernel) };
}

/// Returns true if the physical address is below the 1 MB reserved boundary.
fn page_is_in_reserved_low_memory(physical_address: u64) -> bool {
    physical_address < RESERVED_LOW_MEMORY_BOUNDARY
}

/// Returns true if the physical address is within the kernel binary range.
fn page_is_in_kernel_binary_range(physical_address: u64) -> bool {
    physical_address >= KERNEL_PHYSICAL_START && physical_address < KERNEL_PHYSICAL_END
}

/// Aligns a physical address up to the next page boundary.
#[allow(clippy::arithmetic_side_effects)]
fn align_address_up_to_page_boundary(address: u64) -> u64 {
    let page_size = PAGE_SIZE_IN_BYTES as u64;
    let remainder = address % page_size;
    if remainder == 0 {
        return address;
    }
    address.wrapping_add(page_size.wrapping_sub(remainder))
}
