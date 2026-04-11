#![no_std]
#![allow(unsafe_code)]

// Bootloader entry point and hardware initialization.
// Unsafe is permitted in src/bootloader/src/ per UNSAFE_CODE_POLICY.md allowlist.

pub mod multiboot2_header;
