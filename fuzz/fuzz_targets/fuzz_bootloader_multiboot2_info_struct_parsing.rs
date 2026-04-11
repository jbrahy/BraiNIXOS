//! Fuzz target: multiboot2 boot information struct parser.
//!
//! Feeds arbitrary bytes to the multiboot2 parser via the brainix-bootloader-verify
//! shim crate. Any panic or memory safety violation is caught by libfuzzer.
//!
//! Run with: cargo fuzz run fuzz_bootloader_multiboot2_info_struct_parsing
#![no_main]

use brainix_bootloader_verify::parse_multiboot2_information;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_multiboot2_information(data);
});
