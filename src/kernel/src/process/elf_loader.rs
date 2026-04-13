//! Minimal ELF64 parser for static no_std Rust binaries (PT_LOAD only).
//!
//! This module validates the ELF64 header and program headers of a server binary
//! before the kernel loads any segments into the server's address space. Only
//! PT_LOAD segments are processed. Dynamic linking is not supported: all server
//! binaries must be statically linked position-dependent executables.
//!
//! # Security invariant
//!
//! No segment is mapped until `validate_elf_header` returns `Ok(())`.
//! The kernel must not execute any byte from the binary before validation passes.

const ELF_MAGIC_BYTES: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF_CLASS_64_BIT: u8 = 2;
const ELF_DATA_LITTLE_ENDIAN: u8 = 1;
const ELF_TYPE_EXECUTABLE: u16 = 2;
const ELF_MACHINE_X86_64: u16 = 0x3E;
const ELF_HEADER_MINIMUM_SIZE: usize = 64;
const PROGRAM_HEADER_TYPE_LOAD: u32 = 1;
const PROGRAM_HEADER_ENTRY_SIZE: usize = 56;
const SEGMENT_FLAG_EXECUTABLE: u32 = 1;
const SEGMENT_FLAG_WRITABLE: u32 = 2;
#[cfg(test)]
const SEGMENT_FLAG_READABLE: u32 = 4;
/// Errors that can occur when validating a server binary ELF header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ElfLoadError {
    /// The binary is shorter than the minimum ELF64 header size.
    BinaryTooSmall,
    /// The ELF magic bytes (`\x7fELF`) are absent or corrupted.
    InvalidMagic,
    /// The binary is not a 64-bit ELF file (EI_CLASS != ELFCLASS64).
    Not64Bit,
    /// The binary is not little-endian (EI_DATA != ELFDATA2LSB).
    NotLittleEndian,
    /// The binary is not an executable (e_type != ET_EXEC).
    NotExecutable,
    /// The binary targets an architecture other than x86-64 (e_machine != EM_X86_64).
    NotX86_64,
    /// A PT_LOAD segment's file offset or size extends beyond the binary length.
    SegmentOutOfBounds,
    /// A PT_LOAD segment has both the Write and Execute permission flags set (W^X violation).
    WritableAndExecutableSegment,
}

/// A loadable ELF64 segment extracted from a PT_LOAD program header.
#[derive(PartialEq, Eq, Debug)]
pub struct LoadableSegment {
    /// Byte offset within the ELF binary file where the segment data begins.
    pub file_offset: u64,
    /// Virtual address where this segment must be mapped in the process address space.
    pub virtual_address: u64,
    /// Number of bytes to copy from the file into the segment mapping.
    pub file_size: u64,
    /// Total size of the segment in memory (may exceed file_size; gap is zero-filled).
    pub memory_size: u64,
    /// Permission flags: bit 0 = executable, bit 1 = writable, bit 2 = readable.
    pub flags: u32,
}

fn extract_elf_class(binary_bytes: &[u8]) -> u8 {
    binary_bytes[4]
}

fn extract_elf_data_encoding(binary_bytes: &[u8]) -> u8 {
    binary_bytes[5]
}

#[allow(clippy::arithmetic_side_effects)]
fn extract_u16_little_endian_at(binary_bytes: &[u8], byte_offset: usize) -> u16 {
    let low_byte = binary_bytes[byte_offset];
    let high_byte = binary_bytes[byte_offset + 1];
    u16::from_le_bytes([low_byte, high_byte])
}

#[allow(clippy::arithmetic_side_effects)]
fn extract_u32_little_endian_at(binary_bytes: &[u8], byte_offset: usize) -> u32 {
    let byte_array = [
        binary_bytes[byte_offset],
        binary_bytes[byte_offset + 1],
        binary_bytes[byte_offset + 2],
        binary_bytes[byte_offset + 3],
    ];
    u32::from_le_bytes(byte_array)
}

#[allow(clippy::arithmetic_side_effects)]
fn extract_u64_little_endian_at(binary_bytes: &[u8], byte_offset: usize) -> u64 {
    let byte_array = [
        binary_bytes[byte_offset],
        binary_bytes[byte_offset + 1],
        binary_bytes[byte_offset + 2],
        binary_bytes[byte_offset + 3],
        binary_bytes[byte_offset + 4],
        binary_bytes[byte_offset + 5],
        binary_bytes[byte_offset + 6],
        binary_bytes[byte_offset + 7],
    ];
    u64::from_le_bytes(byte_array)
}

fn extract_elf_type(binary_bytes: &[u8]) -> u16 {
    extract_u16_little_endian_at(binary_bytes, 16)
}

fn extract_elf_machine(binary_bytes: &[u8]) -> u16 {
    extract_u16_little_endian_at(binary_bytes, 18)
}

fn extract_entry_point_address(binary_bytes: &[u8]) -> u64 {
    extract_u64_little_endian_at(binary_bytes, 24)
}

fn extract_program_header_table_offset(binary_bytes: &[u8]) -> u64 {
    extract_u64_little_endian_at(binary_bytes, 32)
}

fn extract_program_header_count(binary_bytes: &[u8]) -> u16 {
    extract_u16_little_endian_at(binary_bytes, 56)
}

fn validate_binary_is_large_enough(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    if binary_bytes.len() < ELF_HEADER_MINIMUM_SIZE {
        Err(ElfLoadError::BinaryTooSmall)
    } else {
        Ok(())
    }
}

fn validate_elf_magic(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let magic_matches = binary_bytes[0..4] == ELF_MAGIC_BYTES;
    if magic_matches {
        Ok(())
    } else {
        Err(ElfLoadError::InvalidMagic)
    }
}

fn validate_elf_class(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let class_field = extract_elf_class(binary_bytes);
    if class_field == ELF_CLASS_64_BIT {
        Ok(())
    } else {
        Err(ElfLoadError::Not64Bit)
    }
}

fn validate_elf_data_encoding(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let encoding_field = extract_elf_data_encoding(binary_bytes);
    if encoding_field == ELF_DATA_LITTLE_ENDIAN {
        Ok(())
    } else {
        Err(ElfLoadError::NotLittleEndian)
    }
}

fn validate_elf_type(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let type_field = extract_elf_type(binary_bytes);
    if type_field == ELF_TYPE_EXECUTABLE {
        Ok(())
    } else {
        Err(ElfLoadError::NotExecutable)
    }
}

fn validate_elf_machine(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let machine_field = extract_elf_machine(binary_bytes);
    if machine_field == ELF_MACHINE_X86_64 {
        Ok(())
    } else {
        Err(ElfLoadError::NotX86_64)
    }
}

/// Validates the ELF64 header of a server binary without loading any segments.
///
/// Returns `Ok(())` if the binary is a valid static x86-64 ELF64 executable.
/// Returns `Err(ElfLoadError)` describing the first validation failure.
pub fn validate_elf_header(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    validate_binary_is_large_enough(binary_bytes)?;
    validate_elf_magic(binary_bytes)?;
    validate_elf_class(binary_bytes)?;
    validate_elf_data_encoding(binary_bytes)?;
    validate_elf_type(binary_bytes)?;
    validate_elf_machine(binary_bytes)
}

/// Validates that the ELF header is correct then extracts the entry point virtual address.
pub fn extract_entry_point(binary_bytes: &[u8]) -> Result<u64, ElfLoadError> {
    validate_elf_header(binary_bytes)?;
    Ok(extract_entry_point_address(binary_bytes))
}

/// Enforces INV-MEM-003: a loaded segment may not be simultaneously writable and executable.
///
/// Returns `Err(WritableAndExecutableSegment)` if both the write and execute permission
/// bits are set in the segment flags field.
///
/// Verified by: tests::test_writable_and_executable_segment_is_rejected
fn validate_segment_is_not_writable_and_executable(flags: u32) -> Result<(), ElfLoadError> {
    let is_writable = flags & SEGMENT_FLAG_WRITABLE != 0;
    let is_executable = flags & SEGMENT_FLAG_EXECUTABLE != 0;
    if is_writable && is_executable {
        Err(ElfLoadError::WritableAndExecutableSegment)
    } else {
        Ok(())
    }
}

fn read_segment_type(binary_bytes: &[u8], header_offset: usize) -> u32 {
    extract_u32_little_endian_at(binary_bytes, header_offset)
}

#[allow(clippy::arithmetic_side_effects)]
fn read_segment_flags(binary_bytes: &[u8], header_offset: usize) -> u32 {
    extract_u32_little_endian_at(binary_bytes, header_offset + 4)
}

#[allow(clippy::arithmetic_side_effects)]
fn read_segment_file_offset(binary_bytes: &[u8], header_offset: usize) -> u64 {
    extract_u64_little_endian_at(binary_bytes, header_offset + 8)
}

#[allow(clippy::arithmetic_side_effects)]
fn read_segment_virtual_address(binary_bytes: &[u8], header_offset: usize) -> u64 {
    extract_u64_little_endian_at(binary_bytes, header_offset + 16)
}

#[allow(clippy::arithmetic_side_effects)]
fn read_segment_file_size(binary_bytes: &[u8], header_offset: usize) -> u64 {
    extract_u64_little_endian_at(binary_bytes, header_offset + 32)
}

#[allow(clippy::arithmetic_side_effects)]
fn read_segment_memory_size(binary_bytes: &[u8], header_offset: usize) -> u64 {
    extract_u64_little_endian_at(binary_bytes, header_offset + 40)
}

fn validate_segment_bounds(
    binary_bytes: &[u8],
    file_offset: u64,
    file_size: u64,
) -> Result<(), ElfLoadError> {
    let segment_end = file_offset.saturating_add(file_size);
    if segment_end as usize > binary_bytes.len() {
        Err(ElfLoadError::SegmentOutOfBounds)
    } else {
        Ok(())
    }
}

fn build_loadable_segment(
    binary_bytes: &[u8],
    header_offset: usize,
    flags: u32,
) -> Result<LoadableSegment, ElfLoadError> {
    let file_offset = read_segment_file_offset(binary_bytes, header_offset);
    let file_size = read_segment_file_size(binary_bytes, header_offset);
    validate_segment_bounds(binary_bytes, file_offset, file_size)?;
    Ok(LoadableSegment {
        file_offset,
        virtual_address: read_segment_virtual_address(binary_bytes, header_offset),
        file_size,
        memory_size: read_segment_memory_size(binary_bytes, header_offset),
        flags,
    })
}

fn extract_single_program_header(
    binary_bytes: &[u8],
    header_offset: usize,
) -> Result<Option<LoadableSegment>, ElfLoadError> {
    let segment_type = read_segment_type(binary_bytes, header_offset);
    if segment_type != PROGRAM_HEADER_TYPE_LOAD {
        return Ok(None);
    }
    let flags = read_segment_flags(binary_bytes, header_offset);
    validate_segment_is_not_writable_and_executable(flags)?;
    Ok(Some(build_loadable_segment(
        binary_bytes,
        header_offset,
        flags,
    )?))
}

#[allow(clippy::arithmetic_side_effects)]
fn validate_program_header_offset_is_in_bounds(
    binary_bytes: &[u8],
    header_offset: usize,
) -> Result<(), ElfLoadError> {
    let required_end = header_offset + PROGRAM_HEADER_ENTRY_SIZE;
    if required_end > binary_bytes.len() {
        Err(ElfLoadError::SegmentOutOfBounds)
    } else {
        Ok(())
    }
}

/// Extracts all PT_LOAD segments from the ELF binary, enforcing W^X on each.
///
/// Returns a fixed-size array of up to 8 loadable segments. Slots beyond the
/// segment count are `None`. Returns `Err` if any segment violates W^X or
/// if any offset falls outside the binary bounds.
pub fn extract_loadable_segments(
    binary_bytes: &[u8],
) -> Result<[Option<LoadableSegment>; 8], ElfLoadError> {
    validate_elf_header(binary_bytes)?;
    let table_offset = extract_program_header_table_offset(binary_bytes) as usize;
    let header_count = extract_program_header_count(binary_bytes) as usize;
    collect_loadable_segments(binary_bytes, table_offset, header_count)
}

#[allow(clippy::arithmetic_side_effects)]
fn collect_loadable_segments(
    binary_bytes: &[u8],
    table_offset: usize,
    header_count: usize,
) -> Result<[Option<LoadableSegment>; 8], ElfLoadError> {
    let mut segments: [Option<LoadableSegment>; 8] =
        [None, None, None, None, None, None, None, None];
    let mut load_segment_index = 0;
    let mut header_index = 0;
    while header_index < header_count {
        let header_offset = table_offset + header_index * PROGRAM_HEADER_ENTRY_SIZE;
        validate_program_header_offset_is_in_bounds(binary_bytes, header_offset)?;
        let maybe_segment = extract_single_program_header(binary_bytes, header_offset)?;
        if let Some(segment) = maybe_segment {
            if load_segment_index < 8 {
                segments[load_segment_index] = Some(segment);
                load_segment_index += 1;
            }
        }
        header_index += 1;
    }
    Ok(segments)
}

/// Computes the size of the zero-fill region for a loadable segment's BSS area.
///
/// Returns `segment.memory_size - segment.file_size`. When this value is greater
/// than zero, the kernel must zero-fill that many bytes after copying from the file
/// (per INV-MEM-006: freed/newly-mapped memory is sanitized before use by userspace).
#[allow(clippy::arithmetic_side_effects)]
pub fn compute_zero_fill_size(segment: &LoadableSegment) -> u64 {
    segment.memory_size - segment.file_size
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal valid ELF64 header byte array for use in tests.
    ///
    /// The header is exactly 64 bytes with correct magic, class, endianness,
    /// type (ET_EXEC = 2), and machine (EM_X86_64 = 0x3E).
    fn build_valid_elf64_header() -> [u8; 64] {
        let mut header = [0u8; 64];
        // Magic bytes
        header[0] = 0x7f;
        header[1] = b'E';
        header[2] = b'L';
        header[3] = b'F';
        // EI_CLASS = ELFCLASS64
        header[4] = 2;
        // EI_DATA = ELFDATA2LSB
        header[5] = 1;
        // EI_VERSION = EV_CURRENT
        header[6] = 1;
        // e_type = ET_EXEC (little-endian u16 at offset 16)
        header[16] = 2;
        header[17] = 0;
        // e_machine = EM_X86_64 = 0x3E (little-endian u16 at offset 18)
        header[18] = 0x3E;
        header[19] = 0;
        // e_entry = 0x400000 (little-endian u64 at offset 24)
        header[24] = 0x00;
        header[25] = 0x00;
        header[26] = 0x40;
        header[27] = 0x00;
        // e_phoff = 64 (program header table immediately after header, u64 at offset 32)
        header[32] = 64;
        // e_phentsize = 56 (u16 at offset 54)
        header[54] = 56;
        header[55] = 0;
        // e_phnum = 0 (u16 at offset 56)
        header[56] = 0;
        header[57] = 0;
        header
    }

    #[test]
    fn test_valid_elf64_header_passes_validation() {
        let header = build_valid_elf64_header();
        let result = validate_elf_header(&header);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_binary_shorter_than_64_bytes_returns_binary_too_small() {
        let short_binary = [0u8; 32];
        let result = validate_elf_header(&short_binary);
        assert_eq!(result, Err(ElfLoadError::BinaryTooSmall));
    }

    #[test]
    fn test_wrong_magic_returns_invalid_magic() {
        let mut header = build_valid_elf64_header();
        header[0] = 0x00;
        let result = validate_elf_header(&header);
        assert_eq!(result, Err(ElfLoadError::InvalidMagic));
    }

    #[test]
    fn test_class_not_64_bit_returns_not_64_bit() {
        let mut header = build_valid_elf64_header();
        header[4] = 1; // ELFCLASS32
        let result = validate_elf_header(&header);
        assert_eq!(result, Err(ElfLoadError::Not64Bit));
    }

    #[test]
    fn test_big_endian_encoding_returns_not_little_endian() {
        let mut header = build_valid_elf64_header();
        header[5] = 2; // ELFDATA2MSB (big-endian)
        let result = validate_elf_header(&header);
        assert_eq!(result, Err(ElfLoadError::NotLittleEndian));
    }

    #[test]
    fn test_machine_not_x86_64_returns_not_x86_64() {
        let mut header = build_valid_elf64_header();
        // e_machine at offset 18, set to EM_386 = 3
        header[18] = 3;
        header[19] = 0;
        let result = validate_elf_header(&header);
        assert_eq!(result, Err(ElfLoadError::NotX86_64));
    }

    #[test]
    fn test_shared_library_type_returns_not_executable() {
        let mut header = build_valid_elf64_header();
        // e_type at offset 16, set to ET_DYN = 3
        header[16] = 3;
        header[17] = 0;
        let result = validate_elf_header(&header);
        assert_eq!(result, Err(ElfLoadError::NotExecutable));
    }

    /// Builds a valid ELF binary with one PT_LOAD program header appended.
    ///
    /// The program header is placed at offset 64 (immediately after the ELF header).
    /// The header_flags parameter controls the segment permission flags.
    fn build_elf_with_one_load_segment(header_flags: u32) -> Vec<u8> {
        let mut binary = build_valid_elf64_header().to_vec();
        // Set e_phnum = 1 (one program header)
        binary[56] = 1;
        binary[57] = 0;
        // Append a 56-byte PT_LOAD program header
        // p_type = PT_LOAD = 1 (u32 LE at offset 0)
        binary.extend_from_slice(&1u32.to_le_bytes());
        // p_flags (u32 LE at offset 4)
        binary.extend_from_slice(&header_flags.to_le_bytes());
        // p_offset = 0 (u64 LE at offset 8) -- segment data starts at file offset 0
        binary.extend_from_slice(&0u64.to_le_bytes());
        // p_vaddr = 0x400000 (u64 LE at offset 16)
        binary.extend_from_slice(&0x0040_0000u64.to_le_bytes());
        // p_paddr = 0x400000 (u64 LE at offset 24)
        binary.extend_from_slice(&0x0040_0000u64.to_le_bytes());
        // p_filesz = 120 (u64 LE at offset 32) -- within binary bounds
        binary.extend_from_slice(&120u64.to_le_bytes());
        // p_memsz = 128 (u64 LE at offset 40) -- 8 bytes BSS
        binary.extend_from_slice(&128u64.to_le_bytes());
        // p_align = 0x1000 (u64 LE at offset 48)
        binary.extend_from_slice(&0x1000u64.to_le_bytes());
        // Pad to reach binary length of 128 bytes so p_filesz=120 is in bounds
        while binary.len() < 128 {
            binary.push(0u8);
        }
        binary
    }

    #[test]
    fn test_writable_and_executable_segment_is_rejected() {
        // PF_W | PF_X = 2 | 1 = 3
        let flags = SEGMENT_FLAG_WRITABLE | SEGMENT_FLAG_EXECUTABLE;
        let binary = build_elf_with_one_load_segment(flags);
        let result = extract_loadable_segments(&binary);
        assert_eq!(result, Err(ElfLoadError::WritableAndExecutableSegment));
    }

    #[test]
    fn test_segment_with_bss_region_reports_correct_zero_fill_size() {
        // PF_R | PF_W = 4 | 2 = 6 (readable and writable, not executable)
        let flags = SEGMENT_FLAG_READABLE | SEGMENT_FLAG_WRITABLE;
        let binary = build_elf_with_one_load_segment(flags);
        let segments = extract_loadable_segments(&binary).unwrap();
        let first_segment = segments[0].as_ref().unwrap();
        let zero_fill_size = compute_zero_fill_size(first_segment);
        // p_memsz (128) - p_filesz (120) = 8
        assert_eq!(zero_fill_size, 8);
    }

    #[test]
    fn test_program_header_offset_beyond_binary_length_returns_segment_out_of_bounds() {
        let mut header = build_valid_elf64_header();
        // Set e_phnum = 1 (one program header)
        header[56] = 1;
        header[57] = 0;
        // Set e_phoff to offset 9999 (far beyond the 64-byte binary)
        let out_of_bounds_offset: u64 = 9999;
        let offset_bytes = out_of_bounds_offset.to_le_bytes();
        header[32] = offset_bytes[0];
        header[33] = offset_bytes[1];
        header[34] = offset_bytes[2];
        header[35] = offset_bytes[3];
        header[36] = offset_bytes[4];
        header[37] = offset_bytes[5];
        header[38] = offset_bytes[6];
        header[39] = offset_bytes[7];
        let result = extract_loadable_segments(&header);
        assert_eq!(result, Err(ElfLoadError::SegmentOutOfBounds));
    }
}
