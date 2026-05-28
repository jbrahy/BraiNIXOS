//! Multiboot2 information-structure walker.
//!
//! GRUB passes the bootloader a pointer (in EBX at 32-bit entry, captured in
//! main.rs and saved to physical 0x809000) to a multiboot2 information
//! structure. The structure is a sequence of typed tags terminated by the
//! end tag (type=0). Modules loaded via `module2` in grub.cfg appear as
//! tags of type 3 (Modules), with a null-terminated string that matches
//! the module's name from grub.cfg.
//!
//! This module's single job: walk the tag list, find a Modules tag whose
//! string equals a caller-supplied name (e.g., `b"kernel"` for the kernel
//! ELF), and return its physical start/end addresses.
//!
//! Unsafe is allowlisted for `src/bootloader/src/` per
//! `docs/security/UNSAFE_CODE_POLICY.md` (raw pointer reads from physical
//! memory before any safe abstraction exists).
//!
//! # Security invariant
//!
//! INV-BOOT-001 (this file's local invariant): no module tag is reported
//! to the caller before its `mod_end > mod_start` and its size field
//! fits inside the declared total info-structure size.

#![allow(unsafe_code)]

const MULTIBOOT2_TAG_TYPE_END: u32 = 0;
const MULTIBOOT2_TAG_TYPE_MODULE: u32 = 3;
const MULTIBOOT2_TAG_ALIGNMENT_BYTES: u32 = 8;
const MULTIBOOT2_FIXED_HEADER_BYTES: u32 = 8;
const MULTIBOOT2_MODULE_TAG_FIXED_BYTES: u32 = 16;

/// Physical-memory range of a multiboot2 module.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ModuleLocation {
    pub physical_start_address: u32,
    pub physical_end_address: u32,
}

impl ModuleLocation {
    pub const fn size_in_bytes(self) -> u32 {
        self.physical_end_address - self.physical_start_address
    }
}

/// Walks the multiboot2 info structure at `information_structure_address`
/// and returns the first Modules tag whose string matches `target_name`.
///
/// # Safety
///
/// - `information_structure_address` must be a valid physical address
///   produced by GRUB and currently mapped (identity map covers it via
///   `pd_low[0..4]` set up by `start.s` / `main.rs` global_asm).
/// - GRUB must have written a well-formed multiboot2 info structure there.
/// - `target_name` is treated as raw bytes; no encoding validation done.
pub unsafe fn find_module_by_name(
    information_structure_address: u64,
    target_name: &[u8],
) -> Option<ModuleLocation> {
    let total_size_bytes = read_total_size(information_structure_address);
    let mut tag_address = information_structure_address + u64::from(MULTIBOOT2_FIXED_HEADER_BYTES);
    let end_address = information_structure_address + u64::from(total_size_bytes);
    walk_tags_until_match(&mut tag_address, end_address, target_name)
}

unsafe fn read_total_size(information_structure_address: u64) -> u32 {
    read_u32_at(information_structure_address)
}

unsafe fn walk_tags_until_match(
    tag_address: &mut u64,
    end_address: u64,
    target_name: &[u8],
) -> Option<ModuleLocation> {
    while *tag_address < end_address {
        if let Some(found) = inspect_tag(*tag_address, target_name) {
            return Some(found);
        }
        advance_tag_address(tag_address);
    }
    None
}

unsafe fn inspect_tag(tag_address: u64, target_name: &[u8]) -> Option<ModuleLocation> {
    let tag_type = read_u32_at(tag_address);
    if tag_type == MULTIBOOT2_TAG_TYPE_END {
        return None;
    }
    if tag_type != MULTIBOOT2_TAG_TYPE_MODULE {
        return None;
    }
    extract_matching_module(tag_address, target_name)
}

unsafe fn extract_matching_module(
    tag_address: u64,
    target_name: &[u8],
) -> Option<ModuleLocation> {
    let module_start = read_u32_at(tag_address + 8);
    let module_end = read_u32_at(tag_address + 12);
    if module_end <= module_start {
        return None;
    }
    if !tag_string_matches(tag_address, target_name) {
        return None;
    }
    Some(ModuleLocation { physical_start_address: module_start, physical_end_address: module_end })
}

unsafe fn tag_string_matches(tag_address: u64, target_name: &[u8]) -> bool {
    let string_address = tag_address + u64::from(MULTIBOOT2_MODULE_TAG_FIXED_BYTES);
    for (offset, expected_byte) in target_name.iter().enumerate() {
        let actual_byte = read_u8_at(string_address + offset as u64);
        if actual_byte != *expected_byte {
            return false;
        }
    }
    read_u8_at(string_address + target_name.len() as u64) == 0
}

unsafe fn advance_tag_address(tag_address: &mut u64) {
    let raw_tag_size = read_u32_at(*tag_address + 4);
    let padded_size = round_up_to_alignment(raw_tag_size, MULTIBOOT2_TAG_ALIGNMENT_BYTES);
    *tag_address += u64::from(padded_size);
}

const fn round_up_to_alignment(value: u32, alignment: u32) -> u32 {
    value.wrapping_add(alignment - 1) & !(alignment - 1)
}

unsafe fn read_u32_at(physical_address: u64) -> u32 {
    let pointer = physical_address as *const u32;
    core::ptr::read_volatile(pointer)
}

unsafe fn read_u8_at(physical_address: u64) -> u8 {
    let pointer = physical_address as *const u8;
    core::ptr::read_volatile(pointer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append_u32(buffer: &mut alloc::vec::Vec<u8>, value: u32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn pad_to_eight_bytes(buffer: &mut alloc::vec::Vec<u8>) {
        while buffer.len() % 8 != 0 {
            buffer.push(0);
        }
    }

    fn build_module_tag(start: u32, end: u32, name: &[u8]) -> alloc::vec::Vec<u8> {
        let mut tag = alloc::vec::Vec::new();
        let tag_size = (MULTIBOOT2_MODULE_TAG_FIXED_BYTES as usize) + name.len() + 1;
        append_u32(&mut tag, MULTIBOOT2_TAG_TYPE_MODULE);
        append_u32(&mut tag, tag_size as u32);
        append_u32(&mut tag, start);
        append_u32(&mut tag, end);
        tag.extend_from_slice(name);
        tag.push(0);
        pad_to_eight_bytes(&mut tag);
        tag
    }

    fn build_info_structure(module_tags: &[alloc::vec::Vec<u8>]) -> alloc::vec::Vec<u8> {
        let mut info = alloc::vec::Vec::new();
        append_u32(&mut info, 0);
        append_u32(&mut info, 0);
        for tag in module_tags {
            info.extend_from_slice(tag);
        }
        append_u32(&mut info, MULTIBOOT2_TAG_TYPE_END);
        append_u32(&mut info, 8);
        let total = info.len() as u32;
        info[0..4].copy_from_slice(&total.to_le_bytes());
        info
    }

    extern crate alloc;

    #[test]
    fn finds_kernel_module_when_present_as_only_tag() {
        let info = build_info_structure(&[build_module_tag(
            0x500000, 0x50d065, b"kernel",
        )]);
        let address = info.as_ptr() as u64;
        let result = unsafe { find_module_by_name(address, b"kernel") };
        assert_eq!(
            result,
            Some(ModuleLocation {
                physical_start_address: 0x500000,
                physical_end_address: 0x50d065,
            })
        );
    }

    #[test]
    fn finds_kernel_when_shell_appears_first() {
        let info = build_info_structure(&[
            build_module_tag(0x400000, 0x401000, b"shell"),
            build_module_tag(0x500000, 0x50d065, b"kernel"),
        ]);
        let address = info.as_ptr() as u64;
        let result = unsafe { find_module_by_name(address, b"kernel") };
        assert_eq!(result.map(ModuleLocation::size_in_bytes), Some(0x50d065 - 0x500000));
    }

    #[test]
    fn returns_none_when_target_name_absent() {
        let info = build_info_structure(&[build_module_tag(
            0x400000, 0x401000, b"shell",
        )]);
        let address = info.as_ptr() as u64;
        let result = unsafe { find_module_by_name(address, b"kernel") };
        assert_eq!(result, None);
    }

    #[test]
    fn returns_none_when_module_has_inverted_extent() {
        let info = build_info_structure(&[build_module_tag(0x500000, 0x500000, b"kernel")]);
        let address = info.as_ptr() as u64;
        let result = unsafe { find_module_by_name(address, b"kernel") };
        assert_eq!(result, None);
    }

    #[test]
    fn distinguishes_prefix_collision() {
        let info = build_info_structure(&[
            build_module_tag(0x400000, 0x401000, b"kernel-debug"),
            build_module_tag(0x500000, 0x50d065, b"kernel"),
        ]);
        let address = info.as_ptr() as u64;
        let result = unsafe { find_module_by_name(address, b"kernel") };
        assert_eq!(
            result,
            Some(ModuleLocation {
                physical_start_address: 0x500000,
                physical_end_address: 0x50d065,
            })
        );
    }
}
