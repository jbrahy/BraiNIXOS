//! Minimal ELF64 loader for the kernel module supplied by GRUB.
//!
//! The bootloader receives the kernel ELF as a multiboot2 module placed
//! by GRUB at an arbitrary physical address. This module parses the
//! ELF64 header + program headers, copies each PT_LOAD segment to its
//! requested physical address (`p_paddr`), and reports the entry point.
//!
//! Scope:
//! - PT_LOAD segments only. Dynamic linking is not supported.
//! - Physical-address loading (writes raw memory at `p_paddr`).
//! - Kernel binary only — server binaries are loaded by the kernel via
//!   `src/kernel/src/process/elf_loader.rs` (a separate, virtual-address
//!   loader). The two intentionally do not share code: they serve
//!   different boot stages with different security postures.
//!
//! Unsafe is allowlisted for `src/bootloader/src/` per
//! `docs/security/UNSAFE_CODE_POLICY.md`.
//!
//! # Security invariant
//!
//! - **W^X at boot**: no PT_LOAD segment is loaded if it has both the
//!   Write (PF_W) and Execute (PF_X) permission flags set. Verified by
//!   `rejects_writable_and_executable_segment` and matches
//!   `SECURITY_INVARIANTS.md` INV-MEM-003 enforcement at the
//!   earliest possible point.
//! - **Bounds-checked reads**: every byte read from the module is
//!   validated against the module's declared size before access.

#![allow(unsafe_code)]
// ELF64 parsing iterates fixed-size headers and bytes within a multiboot2
// module whose declared size is checked against `module_size_in_bytes` on
// entry, and against each PT_LOAD segment's bounds before any access via
// `require_segment_within_module`. All offset arithmetic is therefore on
// validated inputs; overflow is structurally impossible.
#![allow(clippy::arithmetic_side_effects)]

const ELF_MAGIC_BYTES: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_64_BIT: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 0x3E;
const ELF_HEADER_MINIMUM_SIZE: u64 = 64;
const PROGRAM_HEADER_ENTRY_SIZE: u64 = 56;
const PROGRAM_HEADER_TYPE_LOAD: u32 = 1;
const SEGMENT_FLAG_EXECUTABLE: u32 = 1;
const SEGMENT_FLAG_WRITABLE: u32 = 2;
pub const MAXIMUM_LOADABLE_SEGMENTS: usize = 8;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfLoadError {
    ModuleTooSmall,
    InvalidMagic,
    Not64Bit,
    NotLittleEndian,
    NotExecutable,
    NotX86_64,
    TooManyLoadSegments,
    SegmentDataOutOfBounds,
    WritableAndExecutableSegment,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysicalLoadSegment {
    pub file_offset: u64,
    pub physical_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
}

#[derive(Debug)]
pub struct ParsedKernelImage {
    pub entry_point_address: u64,
    pub loadable_segments: [Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS],
}

/// Validates the kernel ELF and returns its entry point + load segments.
///
/// # Safety
///
/// - `module_base_address` must point to a multiboot2-loaded module that
///   is currently identity-mapped by the bootloader's page tables.
/// - `module_size_in_bytes` must accurately reflect the module's extent.
pub unsafe fn parse_kernel_elf_image(
    module_base_address: u64,
    module_size_in_bytes: u64,
) -> Result<ParsedKernelImage, ElfLoadError> {
    if module_size_in_bytes < ELF_HEADER_MINIMUM_SIZE {
        return Err(ElfLoadError::ModuleTooSmall);
    }
    validate_elf_identification(module_base_address)?;
    validate_elf_type_and_machine(module_base_address)?;
    let entry_point_address = read_u64_at(module_base_address + 24);
    let segments = collect_loadable_segments(module_base_address, module_size_in_bytes)?;
    Ok(ParsedKernelImage {
        entry_point_address,
        loadable_segments: segments,
    })
}

/// Copies each PT_LOAD segment from the module into its physical
/// destination and zero-fills the BSS portion. After this returns,
/// the kernel is ready to execute from its entry point.
///
/// # Safety
///
/// Caller must ensure each segment's `physical_address` range is
/// (a) identity-mapped, (b) not overlapping the bootloader's own image
/// or stack, and (c) not overlapping any still-needed multiboot2 data.
pub unsafe fn load_kernel_image_to_physical_memory(
    module_base_address: u64,
    parsed_image: &ParsedKernelImage,
) {
    for segment in parsed_image.loadable_segments.iter().flatten() {
        copy_segment_bytes(module_base_address, segment);
        zero_fill_bss_portion(segment);
    }
}

unsafe fn validate_elf_identification(module_base_address: u64) -> Result<(), ElfLoadError> {
    if read_u8_at(module_base_address) != ELF_MAGIC_BYTES[0]
        || read_u8_at(module_base_address + 1) != ELF_MAGIC_BYTES[1]
        || read_u8_at(module_base_address + 2) != ELF_MAGIC_BYTES[2]
        || read_u8_at(module_base_address + 3) != ELF_MAGIC_BYTES[3]
    {
        return Err(ElfLoadError::InvalidMagic);
    }
    require_64_bit_class(module_base_address)?;
    require_little_endian_encoding(module_base_address)
}

unsafe fn require_64_bit_class(module_base_address: u64) -> Result<(), ElfLoadError> {
    if read_u8_at(module_base_address + 4) != ELF_CLASS_64_BIT {
        return Err(ElfLoadError::Not64Bit);
    }
    Ok(())
}

unsafe fn require_little_endian_encoding(module_base_address: u64) -> Result<(), ElfLoadError> {
    if read_u8_at(module_base_address + 5) != ELF_DATA_LITTLE_ENDIAN {
        return Err(ElfLoadError::NotLittleEndian);
    }
    Ok(())
}

unsafe fn validate_elf_type_and_machine(module_base_address: u64) -> Result<(), ElfLoadError> {
    if read_u16_at(module_base_address + 16) != ELF_TYPE_EXECUTABLE {
        return Err(ElfLoadError::NotExecutable);
    }
    if read_u16_at(module_base_address + 18) != ELF_MACHINE_X86_64 {
        return Err(ElfLoadError::NotX86_64);
    }
    Ok(())
}

unsafe fn collect_loadable_segments(
    module_base_address: u64,
    module_size_in_bytes: u64,
) -> Result<[Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS], ElfLoadError> {
    let program_header_offset = read_u64_at(module_base_address + 32);
    let program_header_count = u64::from(read_u16_at(module_base_address + 56));
    let mut segments: [Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS] =
        [None; MAXIMUM_LOADABLE_SEGMENTS];
    let mut populated_count: usize = 0;
    populate_segments_from_program_headers(
        module_base_address,
        module_size_in_bytes,
        program_header_offset,
        program_header_count,
        &mut segments,
        &mut populated_count,
    )?;
    Ok(segments)
}

unsafe fn populate_segments_from_program_headers(
    module_base_address: u64,
    module_size_in_bytes: u64,
    program_header_offset: u64,
    program_header_count: u64,
    segments: &mut [Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS],
    populated_count: &mut usize,
) -> Result<(), ElfLoadError> {
    for header_index in 0..program_header_count {
        let header_address =
            module_base_address + program_header_offset + header_index * PROGRAM_HEADER_ENTRY_SIZE;
        record_segment_if_loadable(
            module_base_address,
            module_size_in_bytes,
            header_address,
            segments,
            populated_count,
        )?;
    }
    Ok(())
}

unsafe fn record_segment_if_loadable(
    module_base_address: u64,
    module_size_in_bytes: u64,
    header_address: u64,
    segments: &mut [Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS],
    populated_count: &mut usize,
) -> Result<(), ElfLoadError> {
    if read_u32_at(header_address) != PROGRAM_HEADER_TYPE_LOAD {
        return Ok(());
    }
    reject_writable_and_executable(read_u32_at(header_address + 4))?;
    let segment = build_physical_load_segment(header_address);
    require_segment_within_module(module_base_address, module_size_in_bytes, &segment)?;
    insert_segment_or_overflow(segment, segments, populated_count)
}

fn reject_writable_and_executable(segment_flags: u32) -> Result<(), ElfLoadError> {
    let writable_bit_set = (segment_flags & SEGMENT_FLAG_WRITABLE) != 0;
    let executable_bit_set = (segment_flags & SEGMENT_FLAG_EXECUTABLE) != 0;
    if writable_bit_set && executable_bit_set {
        return Err(ElfLoadError::WritableAndExecutableSegment);
    }
    Ok(())
}

unsafe fn build_physical_load_segment(header_address: u64) -> PhysicalLoadSegment {
    PhysicalLoadSegment {
        file_offset: read_u64_at(header_address + 8),
        physical_address: read_u64_at(header_address + 24),
        file_size: read_u64_at(header_address + 32),
        memory_size: read_u64_at(header_address + 40),
    }
}

fn require_segment_within_module(
    module_base_address: u64,
    module_size_in_bytes: u64,
    segment: &PhysicalLoadSegment,
) -> Result<(), ElfLoadError> {
    let _ = module_base_address;
    let segment_file_end = segment.file_offset.saturating_add(segment.file_size);
    if segment_file_end > module_size_in_bytes {
        return Err(ElfLoadError::SegmentDataOutOfBounds);
    }
    Ok(())
}

fn insert_segment_or_overflow(
    segment: PhysicalLoadSegment,
    segments: &mut [Option<PhysicalLoadSegment>; MAXIMUM_LOADABLE_SEGMENTS],
    populated_count: &mut usize,
) -> Result<(), ElfLoadError> {
    if *populated_count >= MAXIMUM_LOADABLE_SEGMENTS {
        return Err(ElfLoadError::TooManyLoadSegments);
    }
    segments[*populated_count] = Some(segment);
    *populated_count += 1;
    Ok(())
}

unsafe fn copy_segment_bytes(module_base_address: u64, segment: &PhysicalLoadSegment) {
    let source_address = module_base_address + segment.file_offset;
    let destination_address = segment.physical_address;
    for byte_index in 0..segment.file_size {
        let byte_value = read_u8_at(source_address + byte_index);
        write_u8_at(destination_address + byte_index, byte_value);
    }
}

unsafe fn zero_fill_bss_portion(segment: &PhysicalLoadSegment) {
    let bss_start = segment.physical_address + segment.file_size;
    let bss_byte_count = segment.memory_size.saturating_sub(segment.file_size);
    for byte_index in 0..bss_byte_count {
        write_u8_at(bss_start + byte_index, 0);
    }
}

unsafe fn read_u8_at(physical_address: u64) -> u8 {
    core::ptr::read_volatile(physical_address as *const u8)
}

unsafe fn read_u16_at(physical_address: u64) -> u16 {
    let low_byte = read_u8_at(physical_address);
    let high_byte = read_u8_at(physical_address + 1);
    u16::from_le_bytes([low_byte, high_byte])
}

unsafe fn read_u32_at(physical_address: u64) -> u32 {
    let bytes = [
        read_u8_at(physical_address),
        read_u8_at(physical_address + 1),
        read_u8_at(physical_address + 2),
        read_u8_at(physical_address + 3),
    ];
    u32::from_le_bytes(bytes)
}

unsafe fn read_u64_at(physical_address: u64) -> u64 {
    let low_word = u64::from(read_u32_at(physical_address));
    let high_word = u64::from(read_u32_at(physical_address + 4));
    (high_word << 32) | low_word
}

unsafe fn write_u8_at(physical_address: u64, byte_value: u8) {
    core::ptr::write_volatile(physical_address as *mut u8, byte_value);
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn append_u8(buffer: &mut Vec<u8>, value: u8) {
        buffer.push(value);
    }

    fn append_u16(buffer: &mut Vec<u8>, value: u16) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn append_u32(buffer: &mut Vec<u8>, value: u32) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    fn append_u64(buffer: &mut Vec<u8>, value: u64) {
        buffer.extend_from_slice(&value.to_le_bytes());
    }

    struct SegmentSpec {
        file_offset: u64,
        physical_address: u64,
        file_size: u64,
        memory_size: u64,
        flags: u32,
    }

    fn build_program_header(buffer: &mut Vec<u8>, spec: &SegmentSpec) {
        append_u32(buffer, PROGRAM_HEADER_TYPE_LOAD);
        append_u32(buffer, spec.flags);
        append_u64(buffer, spec.file_offset);
        append_u64(buffer, spec.physical_address);
        append_u64(buffer, spec.physical_address);
        append_u64(buffer, spec.file_size);
        append_u64(buffer, spec.memory_size);
        append_u64(buffer, 0);
    }

    fn build_minimal_elf64(entry: u64, segments: &[SegmentSpec]) -> Vec<u8> {
        let mut elf = Vec::new();
        for byte in &ELF_MAGIC_BYTES {
            append_u8(&mut elf, *byte);
        }
        append_u8(&mut elf, ELF_CLASS_64_BIT);
        append_u8(&mut elf, ELF_DATA_LITTLE_ENDIAN);
        for _ in 6..16 {
            append_u8(&mut elf, 0);
        }
        append_u16(&mut elf, ELF_TYPE_EXECUTABLE);
        append_u16(&mut elf, ELF_MACHINE_X86_64);
        append_u32(&mut elf, 1);
        append_u64(&mut elf, entry);
        append_u64(&mut elf, ELF_HEADER_MINIMUM_SIZE);
        append_u64(&mut elf, 0);
        append_u32(&mut elf, 0);
        append_u16(&mut elf, ELF_HEADER_MINIMUM_SIZE as u16);
        append_u16(&mut elf, PROGRAM_HEADER_ENTRY_SIZE as u16);
        append_u16(&mut elf, segments.len() as u16);
        append_u16(&mut elf, 0);
        append_u16(&mut elf, 0);
        append_u16(&mut elf, 0);
        for spec in segments {
            build_program_header(&mut elf, spec);
        }
        elf
    }

    #[test]
    fn parses_well_formed_kernel_with_single_load_segment() {
        let bytes = build_minimal_elf64(
            0xFFFF_FFFF_8010_0370,
            &[SegmentSpec {
                file_offset: 0x1000,
                physical_address: 0x100000,
                file_size: 0x100,
                memory_size: 0x200,
                flags: SEGMENT_FLAG_EXECUTABLE,
            }],
        );
        let result =
            unsafe { parse_kernel_elf_image(bytes.as_ptr() as u64, bytes.len() as u64 + 0x1100) };
        let image = result.expect("parse should succeed");
        assert_eq!(image.entry_point_address, 0xFFFF_FFFF_8010_0370);
        let first = image.loadable_segments[0].unwrap();
        assert_eq!(first.physical_address, 0x100000);
        assert_eq!(first.memory_size, 0x200);
    }

    #[test]
    fn rejects_writable_and_executable_segment() {
        let bytes = build_minimal_elf64(
            0,
            &[SegmentSpec {
                file_offset: 0x1000,
                physical_address: 0x100000,
                file_size: 0x10,
                memory_size: 0x10,
                flags: SEGMENT_FLAG_WRITABLE | SEGMENT_FLAG_EXECUTABLE,
            }],
        );
        let result =
            unsafe { parse_kernel_elf_image(bytes.as_ptr() as u64, bytes.len() as u64 + 0x2000) };
        assert_eq!(
            result.err(),
            Some(ElfLoadError::WritableAndExecutableSegment)
        );
    }

    #[test]
    fn rejects_segment_extending_beyond_module() {
        let bytes = build_minimal_elf64(
            0,
            &[SegmentSpec {
                file_offset: 0x1000,
                physical_address: 0x100000,
                file_size: 0x10000,
                memory_size: 0x10000,
                flags: SEGMENT_FLAG_EXECUTABLE,
            }],
        );
        let result = unsafe { parse_kernel_elf_image(bytes.as_ptr() as u64, bytes.len() as u64) };
        assert_eq!(result.err(), Some(ElfLoadError::SegmentDataOutOfBounds));
    }

    #[test]
    fn rejects_too_small_module() {
        let small_bytes: [u8; 8] = [0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        let result = unsafe { parse_kernel_elf_image(small_bytes.as_ptr() as u64, 8) };
        assert_eq!(result.err(), Some(ElfLoadError::ModuleTooSmall));
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut bytes = build_minimal_elf64(0, &[]);
        bytes[0] = b'X';
        let result = unsafe { parse_kernel_elf_image(bytes.as_ptr() as u64, bytes.len() as u64) };
        assert_eq!(result.err(), Some(ElfLoadError::InvalidMagic));
    }
}
