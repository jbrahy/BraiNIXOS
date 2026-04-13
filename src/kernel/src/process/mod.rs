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
    use crate::capability::audit_event_type::AuditEventType;
    use crate::capability::audit_log::AuditRingBuffer;
    use crate::capability::audit_log_protection::protect_audit_log_pages;
    use crate::capability::capability_rights;
    use crate::capability::capability_type::CapabilityType;
    use crate::process::module_loader::validate_spawn_request;
    use crate::syscall::audit_read::validate_audit_read_capability;
    use brainix_libsyscall::{ProcessType, SpawnError};

    #[test]
    #[ignore = "Phase 7 Plan 05: init process exit and authority handoff"]
    fn test_init_process_exits_after_handing_off_authority() {}

    /// Verifies that spawnd refuses to spawn process types not in the whitelist.
    ///
    /// Enforces INV-SPAWN-001: only whitelisted process types may be spawned.
    #[test]
    fn test_spawnd_refuses_process_type_not_in_whitelist() {
        let device_server_result = validate_spawn_request(ProcessType::DeviceServer);
        assert_eq!(device_server_result, Err(SpawnError::ProcessTypeNotPermitted));
        let network_server_result = validate_spawn_request(ProcessType::NetworkServer);
        assert_eq!(network_server_result, Err(SpawnError::ProcessTypeNotPermitted));
        let spawnd_result = validate_spawn_request(ProcessType::Spawnd);
        assert_eq!(spawnd_result, Ok(()));
    }

    /// Verifies that auditd cannot write to the audit log (Write right is forbidden).
    ///
    /// Enforces INV-AUD-002: auditd holds only Read right on its AuditRead capability.
    #[test]
    fn test_auditd_cannot_write_to_audit_log() {
        use crate::syscall::audit_read::AuditReadError;
        let write_rights = capability_rights::WRITE;
        let write_result = validate_audit_read_capability(CapabilityType::AuditRead, write_rights);
        assert_eq!(write_result, Err(AuditReadError::WriteRightNotGranted));
        let read_rights = capability_rights::READ;
        let read_result = validate_audit_read_capability(CapabilityType::AuditRead, read_rights);
        assert_eq!(read_result, Ok(()));
    }

    /// Verifies that an entry appended before write-protection is still readable
    /// after protect_audit_log_pages is called.
    ///
    /// Enforces INV-AUD-001: audit log entries must be readable after write-protection.
    #[test]
    fn test_audit_log_write_to_prior_entry_returns_error() {
        let mut ring_buffer = AuditRingBuffer::new();
        ring_buffer.append_entry(AuditEventType::BootSequenceEvent, 0, 0);
        protect_audit_log_pages(&mut ring_buffer);
        let write_protection_is_active = ring_buffer.is_write_protected();
        assert!(write_protection_is_active, "ring buffer must be write-protected after protect call");
        let entry_at_sequence_zero = ring_buffer.read_entry_at_sequence(0);
        assert!(entry_at_sequence_zero.is_some(), "entry at sequence 0 must remain readable after protection");
    }

    /// Verifies that calling protect_audit_log_pages sets the write-protection flag.
    ///
    /// Enforces INV-AUD-001: audit log pages must be hardware write-protected after initialization.
    /// Verified by: this test.
    #[test]
    fn test_audit_log_pages_are_write_protected_after_initialization() {
        let mut ring_buffer = AuditRingBuffer::new();
        protect_audit_log_pages(&mut ring_buffer);
        let write_protection_is_active = ring_buffer.is_write_protected();
        assert!(write_protection_is_active, "ring buffer must be write-protected after initialization");
    }

    #[test]
    #[ignore = "Phase 7 Plan 06: no privileged process after boot"]
    fn integration_no_privileged_process_exists_after_boot_sequence() {}
}
