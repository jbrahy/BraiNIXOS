//! W^X page table flag validator.
//!
//! Enforces that no page is simultaneously writable and executable.
//! This is a structural enforcement of INV-MEM-003 and INV-X86-004.

use x86_64::structures::paging::PageTableFlags;

use crate::arch::paging::mapping_error::MappingError;

/// Validates that page table flags do not violate the W^X invariant.
///
/// Rejects any combination of flags where a page would be simultaneously
/// writable (WRITABLE set) and executable (NO_EXECUTE not set).
///
/// Enforces invariant INV-MEM-003: W^X is global.
/// Enforces invariant INV-X86-004: executable permission policy is coherent.
///
/// Verified by: test_writable_and_executable_flags_are_rejected
pub fn validate_page_table_flags_enforce_write_xor_execute(
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    let is_writable = check_writable_flag_is_set(flags);
    let is_executable = check_executable_flag_is_set(flags);
    reject_if_both_writable_and_executable(is_writable, is_executable)
}

/// Returns true if the WRITABLE flag is set in the given flags.
fn check_writable_flag_is_set(flags: PageTableFlags) -> bool {
    flags.contains(PageTableFlags::WRITABLE)
}

/// Returns true if the page is executable (NO_EXECUTE flag is NOT set).
fn check_executable_flag_is_set(flags: PageTableFlags) -> bool {
    !flags.contains(PageTableFlags::NO_EXECUTE)
}

/// Returns an error if both writable and executable flags are set simultaneously.
fn reject_if_both_writable_and_executable(
    is_writable: bool,
    is_executable: bool,
) -> Result<(), MappingError> {
    if is_writable && is_executable {
        return Err(MappingError::WritableAndExecutableViolation);
    }
    Ok(())
}

/// Computes page table flags for kernel code pages.
///
/// Kernel code is PRESENT and executable. It is NOT writable after boot.
/// This satisfies INV-MEM-003 (W^X) and INV-MEM-004 (kernel text immutable after init).
pub fn compute_kernel_code_page_flags() -> PageTableFlags {
    PageTableFlags::PRESENT
}

/// Computes page table flags for kernel data pages.
///
/// Kernel data is PRESENT, writable, and non-executable (NO_EXECUTE set).
/// This satisfies INV-MEM-003 (W^X is global).
pub fn compute_kernel_data_page_flags() -> PageTableFlags {
    let base_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    base_flags | PageTableFlags::NO_EXECUTE
}

/// Computes page table flags for kernel read-only data pages (e.g. .rodata).
///
/// Read-only data is PRESENT and non-executable. It is NOT writable.
pub fn compute_kernel_read_only_data_page_flags() -> PageTableFlags {
    PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_writable_and_executable_flags_are_rejected() {
        let writable_and_executable_flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        let result =
            validate_page_table_flags_enforce_write_xor_execute(writable_and_executable_flags);
        assert_eq!(result, Err(MappingError::WritableAndExecutableViolation));
    }

    #[test]
    fn test_writable_with_no_execute_is_accepted() {
        let writable_non_executable_flags =
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
        let result =
            validate_page_table_flags_enforce_write_xor_execute(writable_non_executable_flags);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_executable_without_writable_is_accepted() {
        let executable_read_only_flags = PageTableFlags::PRESENT;
        let result =
            validate_page_table_flags_enforce_write_xor_execute(executable_read_only_flags);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_kernel_code_flags_are_not_writable() {
        let code_flags = compute_kernel_code_page_flags();
        let is_writable = code_flags.contains(PageTableFlags::WRITABLE);
        assert!(!is_writable, "Kernel code flags must not include WRITABLE");
    }

    #[test]
    fn test_kernel_data_flags_have_no_execute() {
        let data_flags = compute_kernel_data_page_flags();
        let has_no_execute = data_flags.contains(PageTableFlags::NO_EXECUTE);
        assert!(has_no_execute, "Kernel data flags must include NO_EXECUTE");
    }
}
