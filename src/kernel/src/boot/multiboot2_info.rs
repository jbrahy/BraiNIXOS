//! Multiboot2 info pointer validation and memory map parsing entry.
//!
//! Validates the multiboot2 magic value and info pointer at boot,
//! then parses the memory map to discover physical RAM regions.
//!
//! Allowlist: `src/kernel/src/boot/` — raw address manipulation for identity
//! mapping and multiboot2 info parsing during early boot.
#![allow(unsafe_code)]

use crate::arch::interrupts::halt::disable_interrupts_and_halt;
use crate::boot::logger::BootStepLogger;
use multiboot2::BootInformationHeader;

/// The multiboot2 bootloader magic value placed in eax by GRUB.
const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D76289;

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
    extract_and_log_memory_map(&boot_information, boot_step_logger);
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

/// Extracts the memory map tag and logs that it was found.
fn extract_and_log_memory_map(
    boot_information: &multiboot2::BootInformation<'_>,
    boot_step_logger: &mut BootStepLogger,
) {
    let memory_map_tag = boot_information.memory_map_tag();
    validate_memory_map_tag_present(memory_map_tag, boot_step_logger);
    // TODO(Plan 02): iterate memory areas to populate page_type_table.
    boot_step_logger.ok("Physical memory map parsed from multiboot2 info");
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
