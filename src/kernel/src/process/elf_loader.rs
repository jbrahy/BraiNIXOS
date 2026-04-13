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

/// Validates the ELF64 header of a server binary without loading any segments.
///
/// Returns `Ok(())` if the binary is a valid static x86-64 ELF64 executable with no
/// W^X segments. Returns `Err(ElfLoadError)` describing the first validation failure.
///
/// # Stub
///
/// This is a placeholder that always returns `Err(BinaryTooSmall)`.
/// The real implementation is delivered in Phase 7 Plan 01.
pub fn validate_elf_header(binary_bytes: &[u8]) -> Result<(), ElfLoadError> {
    let _ = binary_bytes;
    Err(ElfLoadError::BinaryTooSmall)
}
