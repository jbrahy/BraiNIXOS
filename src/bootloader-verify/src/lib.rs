//! Host-compilable shim crate for fuzz testing multiboot2 info struct parsing.
//!
//! This crate wraps the multiboot2 parser in a safe interface suitable for
//! libfuzzer. It uses std (NOT no_std) and is never compiled into the kernel
//! or bootloader. It is test infrastructure only.

use multiboot2::{BootInformation, BootInformationHeader};

/// Attempts to parse arbitrary bytes as a multiboot2 boot information struct.
///
/// Returns Ok if parsing succeeds, Err with a description if it fails or if
/// the input is too short for safe pointer casting. Any panic inside the
/// multiboot2 crate will be caught by the libfuzzer sanitizer.
///
/// Verified by: fuzz_bootloader_multiboot2_info_struct_parsing fuzz target
pub fn parse_multiboot2_information(raw_bytes: &[u8]) -> Result<(), &'static str> {
    let minimum_length = core::mem::size_of::<BootInformationHeader>();
    if raw_bytes.len() < minimum_length {
        return Err("input too short to contain a BootInformationHeader");
    }
    let aligned_copy = copy_bytes_into_aligned_buffer(raw_bytes);
    attempt_multiboot2_parse(&aligned_copy)
}

fn copy_bytes_into_aligned_buffer(raw_bytes: &[u8]) -> Vec<u64> {
    let word_count = raw_bytes.len().div_ceil(core::mem::size_of::<u64>());
    let mut aligned_buffer = vec![0u64; word_count];
    let byte_slice = bytemuck_aligned_buffer_as_bytes(&mut aligned_buffer);
    byte_slice[..raw_bytes.len()].copy_from_slice(raw_bytes);
    aligned_buffer
}

fn bytemuck_aligned_buffer_as_bytes(aligned_buffer: &mut Vec<u64>) -> &mut [u8] {
    let byte_count = core::mem::size_of_val(aligned_buffer.as_slice());
    let raw_pointer = aligned_buffer.as_mut_ptr() as *mut u8;
    // SAFETY: u64 is valid for any byte pattern; the pointer and length are
    // derived from a valid Vec<u64> allocation with known size.
    unsafe { core::slice::from_raw_parts_mut(raw_pointer, byte_count) }
}

fn attempt_multiboot2_parse(aligned_buffer: &[u64]) -> Result<(), &'static str> {
    let header_pointer = aligned_buffer.as_ptr() as *const BootInformationHeader;
    // SAFETY: header_pointer points to an 8-byte aligned heap allocation that
    // is at least size_of::<BootInformationHeader>() bytes. The load function
    // validates internal structure before dereferencing further. Any malformed
    // input is handled by the multiboot2 crate returning LoadError.
    let parse_result = unsafe { BootInformation::load(header_pointer) };
    match parse_result {
        Ok(_boot_information) => Ok(()),
        Err(_load_error) => Err("multiboot2 parsing returned LoadError"),
    }
}
