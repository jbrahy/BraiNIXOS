#![no_std]
#![allow(unsafe_code)]

// Bootloader library module — shared types and constants used by the
// bootloader binary (main.rs) and potentially by fuzz targets.
// Unsafe is permitted in src/bootloader/src/ per UNSAFE_CODE_POLICY.md allowlist.

pub mod multiboot2_header;
pub mod multiboot2_info;
