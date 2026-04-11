//! Mapping error type for page table construction failures.

use core::fmt;

/// Errors that can occur during page table entry mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingError {
    /// A page was mapped with both writable and executable flags set.
    /// Violates INV-MEM-003 (W^X is global).
    WritableAndExecutableViolation,
    /// A page table page could not be allocated from the physical allocator.
    AllocationFailure,
    /// The virtual address is not valid or not canonical.
    InvalidAddress,
}

impl fmt::Display for MappingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let description = describe_mapping_error(self);
        formatter.write_str(description)
    }
}

/// Returns a human-readable description for the given mapping error.
fn describe_mapping_error(error: &MappingError) -> &'static str {
    match error {
        MappingError::WritableAndExecutableViolation => {
            "page mapping rejected: writable and executable simultaneously violates W^X (INV-MEM-003)"
        }
        MappingError::AllocationFailure => {
            "page table page allocation failed: physical allocator exhausted"
        }
        MappingError::InvalidAddress => "page mapping rejected: virtual address is not canonical",
    }
}
