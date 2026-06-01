//! Extracts server binary byte slices from multiboot2 module tags for PCR[3] measurement.
//!
//! Falls under `src/kernel/src/boot/server_measurement.rs` allowlist entry in
//! `docs/security/UNSAFE_CODE_POLICY.md`: "PCR[3] measurement reads raw server
//! binary bytes from multiboot2 module physical addresses."
#![allow(unsafe_code)]

use multiboot2::BootInformation;
use multiboot2::BootInformationHeader;

use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;

/// Maximum number of server binary module slots.
const MAXIMUM_SERVER_MODULE_COUNT: usize = 8;

/// Loads BootInformation from the multiboot2 info address.
///
/// Mirrors the pattern in boot/multiboot2_info.rs load_boot_information.
/// Returns None if the address is zero or the structure cannot be parsed.
///
/// Enforces INV-BOOT-001: measured boot path integrity.
fn load_boot_information_for_measurement(
    multiboot2_info_address: u64,
) -> Option<BootInformation<'static>> {
    let header_pointer = multiboot2_info_address as *const BootInformationHeader;
    // SAFETY: multiboot2_info_address is the physical address passed by GRUB in rbx.
    // The bootloader identity map (0x0..0x200000) makes this address accessible.
    // GRUB is in the TCB. Address was validated by initialize_memory_subsystem earlier.
    // - Precondition: address is non-zero and within identity-mapped region.
    // - Invariant: INV-BOOT-001 (measured boot path integrity).
    // - Evidence: multiboot2_info.rs uses identical pattern at line 106.
    let load_result = unsafe { BootInformation::load(header_pointer) };
    load_result.ok()
}

/// Extracts a byte slice from a single module tag's physical address range,
/// re-based onto the kernel's direct-map region.
///
/// Returns an empty slice if end_address < start_address (malformed tag guard).
///
/// Module addresses reported by GRUB are physical. After the Phase 4 CR3
/// load this function is called from `measure_server_binaries_into_pcr3`
/// at a point where the bootloader's identity map is gone; the only
/// remaining virtual route to module bytes is the direct-map region
/// (`DIRECT_MAP_REGION_START + phys`).
///
/// Enforces INV-BOOT-001: measured boot path integrity.
fn extract_single_module_byte_slice(start_address: u32, end_address: u32) -> &'static [u8] {
    if end_address < start_address {
        return &[];
    }
    // The guard above guarantees end >= start, so this never wraps.
    let byte_count = end_address.wrapping_sub(start_address) as usize;
    let direct_map_pointer =
        DIRECT_MAP_REGION_START.wrapping_add(u64::from(start_address)) as *const u8;
    // SAFETY: GRUB-provided module addresses are within physical RAM and
    // therefore inside the kernel's direct-map coverage (128 MiB from
    // DIRECT_MAP_REGION_START). The re-based pointer resolves to the same
    // physical bytes the original phys address pointed to, now via the
    // kernel's KPTI page tables.
    // - Precondition: byte_count fits within the direct map region.
    // - Invariant: INV-BOOT-001 (measured boot path integrity).
    // - Evidence: direct_map.rs:188 maps 128 MiB at DIRECT_MAP_REGION_START.
    unsafe { core::slice::from_raw_parts(direct_map_pointer, byte_count) }
}

/// Collects up to 8 module byte slices from the multiboot2 boot information.
///
/// Iterates module_tags() and extracts byte slices from physical addresses.
/// Slots beyond the number of modules present receive empty references (correct
/// per success criterion: SHA-256(empty) for absent server slots).
///
/// Returns an array of 8 byte slice references.
pub fn extract_module_byte_slices_from_boot_information(
    multiboot2_info_address: u64,
) -> [&'static [u8]; MAXIMUM_SERVER_MODULE_COUNT] {
    let mut slices: [&[u8]; MAXIMUM_SERVER_MODULE_COUNT] = [&[]; MAXIMUM_SERVER_MODULE_COUNT];
    let boot_information = load_boot_information_for_measurement(multiboot2_info_address);
    fill_module_slices_from_boot_information(&mut slices, boot_information);
    slices
}

/// Fills the slice array from boot information module tags.
fn fill_module_slices_from_boot_information(
    slices: &mut [&'static [u8]; MAXIMUM_SERVER_MODULE_COUNT],
    boot_information: Option<BootInformation<'static>>,
) {
    let Some(boot_info) = boot_information else {
        return;
    };
    populate_slices_from_module_tags(slices, &boot_info);
}

/// Populates module slices from the module tag iterator.
fn populate_slices_from_module_tags(
    slices: &mut [&'static [u8]; MAXIMUM_SERVER_MODULE_COUNT],
    boot_information: &BootInformation<'static>,
) {
    for (index, module_tag) in boot_information.module_tags().enumerate() {
        if index >= MAXIMUM_SERVER_MODULE_COUNT {
            break;
        }
        slices[index] =
            extract_single_module_byte_slice(module_tag.start_address(), module_tag.end_address());
    }
}
