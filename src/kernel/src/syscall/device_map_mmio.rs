//! sys_device_map_mmio handler for Phase 8 device isolation.
//!
//! Maps bounded device MMIO into the calling process's address space after
//! verifying the requested range lies within the CapDevice's assigned region.
//!
//! This file is allowlisted in docs/security/UNSAFE_CODE_POLICY.md for:
//! PTE manipulation for MMIO mapping, raw physical address to page table entry conversion.
//!
//! Enforces INV-DEV-001: devices do not imply universal memory authority.
#![allow(unsafe_code)]

/// Handles the sys_device_map_mmio system call.
///
/// Returns -1 (fail closed) until Phase 9 plumbs register arguments and the
/// process table required to look up the caller's CapDevice and call
/// validate_mmio_mapping_request. Failing closed prevents any false success
/// from being observed by callers before full validation is wired.
///
/// Mitigates T-DEV-011: non-Device capability cannot cause a mapping.
/// Enforces INV-DEV-001: devices do not imply universal memory authority.
/// Verified by: test_device_capability_is_scoped_to_specific_mmio_range
pub fn handle_device_map_mmio_syscall() -> i64 {
    -1
}
