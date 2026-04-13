//! Userspace process management for the Brainix microkernel.
//!
//! This module provides the scaffolding for loading and managing userspace server
//! processes. Server binaries are delivered as multiboot2 modules and loaded by
//! the kernel into isolated address spaces before control is transferred to init.
//!
//! # Module structure
//!
//! - `elf_loader` -- Validates and parses ELF64 server binaries (PT_LOAD only)
//! - `address_space` -- Creates per-process page tables with KPTI isolation
//! - `module_loader` -- Discovers multiboot2 modules and orchestrates loading

pub mod elf_loader;
pub mod address_space;
pub mod module_loader;

/// Re-export ProcessType so kernel code can reference it as `process::ProcessType`.
///
/// The canonical definition lives in brainix-libsyscall per D-09 (single ABI definition).
/// This re-export gives kernel modules a stable import path without duplicating the type.
pub use brainix_libsyscall::ProcessType;

#[cfg(test)]
mod tests {
    #[test]
    #[ignore = "Phase 7 Plan 05: init process exit and authority handoff"]
    fn test_init_process_exits_after_handing_off_authority() {}

    #[test]
    #[ignore = "Phase 7 Plan 03: spawnd whitelist enforcement"]
    fn test_spawnd_refuses_process_type_not_in_whitelist() {}

    #[test]
    #[ignore = "Phase 7 Plan 03: auditd read-only enforcement"]
    fn test_auditd_cannot_write_to_audit_log() {}

    #[test]
    #[ignore = "Phase 7 Plan 02: audit log write-to-prior-entry rejection"]
    fn test_audit_log_write_to_prior_entry_returns_error() {}

    #[test]
    #[ignore = "Phase 7 Plan 02: audit log page write-protection"]
    fn test_audit_log_pages_are_write_protected_after_initialization() {}

    #[test]
    #[ignore = "Phase 7 Plan 06: no privileged process after boot"]
    fn integration_no_privileged_process_exists_after_boot_sequence() {}
}
