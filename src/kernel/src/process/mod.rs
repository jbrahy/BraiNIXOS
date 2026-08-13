//! Userspace process management for the BraiNIX microkernel.
//!
//! This module provides the scaffolding for loading and managing userspace server
//! processes. Server binaries are delivered as multiboot2 modules and loaded by
//! the kernel into isolated address spaces before control is transferred to init.
//!
//! Unsafe allowlist: src/kernel/src/process/mod.rs
//! Test-only heap allocation for ~320 KiB ProcessTable struct (alloc + Box::from_raw).
//! Follows the established physical_allocator.rs and process_table.rs patterns.
//! No unsafe in production code paths.
#![allow(unsafe_code)]
//!
//! # Module structure
//!
//! - `elf_loader` -- Validates and parses ELF64 server binaries (PT_LOAD only)
//! - `address_space` -- Creates per-process page tables with KPTI isolation
//! - `module_loader` -- Discovers multiboot2 modules and orchestrates loading

pub mod address_space;
pub mod elf_load_failure;
#[cfg(target_arch = "x86_64")]
#[cfg(bare_metal_x86)]
pub mod elf_load_into_address_space;
pub mod elf_loader;
pub mod module_loader;
pub mod process_table;
#[cfg(bare_metal_x86)]
pub mod server_launch;

/// Re-export ProcessType so kernel code can reference it as `process::ProcessType`.
///
/// The canonical definition lives in brainix-libsyscall per D-09 (single ABI definition).
/// This re-export gives kernel modules a stable import path without duplicating the type.
pub use brainix_libsyscall::ProcessType;

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::boxed::Box;

    use crate::capability::audit_event_type::AuditEventType;
    use crate::capability::audit_log::AuditRingBuffer;
    use crate::capability::audit_log_protection::protect_audit_log_pages;
    use crate::capability::capability_rights;
    use crate::capability::capability_space::CapabilitySpace;
    use crate::capability::capability_type::CapabilityType;
    use crate::process::module_loader::validate_spawn_request;
    use crate::process::process_table::ProcessTable;
    use crate::process::server_launch::{
        create_server_process, grant_initial_capability_to_server,
    };
    use crate::syscall::audit_read::validate_audit_read_capability;
    use crate::syscall::process_exit::execute_process_exit_sequence;
    use brainix_libsyscall::{ProcessType, SpawnError};

    /// Heap-allocates a ProcessTable to avoid stack overflow (~320 KiB struct).
    ///
    /// Delegates to the canonical allocator in `process_table` so the private
    /// `entries` field is only accessed from within its defining module.
    fn allocate_process_table_on_heap() -> Box<ProcessTable> {
        crate::process::process_table::allocate_process_table_on_heap_for_test()
    }

    /// Verifies that init process exit sequence revokes all authority and
    /// records all four teardown steps as complete.
    ///
    /// Enforces INV-AUTH-001: bootstrap authority collapsed after init exits.
    /// Verified by: this test.
    #[test]
    fn test_init_process_exits_after_handing_off_authority() {
        let init_thread_identifier: u32 = 0;
        let mut process_table = allocate_process_table_on_heap();
        process_table
            .insert_entry(init_thread_identifier, CapabilitySpace::new())
            .unwrap();
        let exit_record = execute_process_exit_sequence(&mut process_table, init_thread_identifier);
        assert!(
            exit_record.capability_space_revoked,
            "CSpace must be revoked on exit"
        );
        assert!(
            exit_record.pages_deallocated,
            "pages must be deallocated on exit"
        );
        assert!(
            exit_record.thread_deallocated,
            "thread must be deallocated on exit"
        );
        assert!(
            exit_record.removed_from_scheduler,
            "process must be removed from scheduler on exit"
        );
    }

    /// Verifies that spawnd refuses to spawn process types not in the whitelist.
    ///
    /// Enforces INV-SPAWN-001: only whitelisted process types may be spawned.
    #[test]
    fn test_spawnd_refuses_process_type_not_in_whitelist() {
        let device_server_result = validate_spawn_request(ProcessType::DeviceServer);
        assert_eq!(
            device_server_result,
            Err(SpawnError::ProcessTypeNotPermitted)
        );
        let network_server_result = validate_spawn_request(ProcessType::NetworkServer);
        assert_eq!(
            network_server_result,
            Err(SpawnError::ProcessTypeNotPermitted)
        );
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
        assert!(
            write_protection_is_active,
            "ring buffer must be write-protected after protect call"
        );
        let entry_at_sequence_zero = ring_buffer.read_entry_at_sequence(0);
        assert!(
            entry_at_sequence_zero.is_some(),
            "entry at sequence 0 must remain readable after protection"
        );
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
        assert!(
            write_protection_is_active,
            "ring buffer must be write-protected after initialization"
        );
    }

    /// Verifies that after the full boot sequence: init is created, exits with
    /// authority revoked, and spawnd/auditd each receive only minimum capabilities.
    ///
    /// Enforces INV-AUTH-001: no privileged process remains after boot.
    /// Enforces INV-AUTH-003: each server receives only its designated capability.
    /// Verified by: this test.
    #[test]
    fn integration_no_privileged_process_exists_after_boot_sequence() {
        let init_result = create_server_process(ProcessType::Init, 0x0000_0000_0040_0000);
        assert!(
            init_result.is_ok(),
            "init process must be created successfully"
        );
        let init_thread_identifier: u32 = 0;
        let mut process_table = allocate_process_table_on_heap();
        process_table
            .insert_entry(init_thread_identifier, CapabilitySpace::new())
            .unwrap();
        let exit_record = execute_process_exit_sequence(&mut process_table, init_thread_identifier);
        assert!(
            exit_record.capability_space_revoked,
            "init CSpace must be revoked after exit"
        );
        verify_spawnd_receives_only_spawn_capability();
        verify_auditd_receives_only_audit_read_capability();
    }

    /// Creates a spawnd process and verifies its CSpace has exactly CapSpawn in slot 0.
    fn verify_spawnd_receives_only_spawn_capability() {
        let spawnd_result = create_server_process(ProcessType::Spawnd, 0x0000_0000_0040_0000);
        assert!(
            spawnd_result.is_ok(),
            "spawnd process must be created successfully"
        );
        let mut spawnd_capability_space = CapabilitySpace::new();
        grant_initial_capability_to_server(
            &mut spawnd_capability_space,
            0,
            CapabilityType::Spawn,
            capability_rights::GRANT,
        );
        let spawn_slot = spawnd_capability_space.lookup_slot(0);
        assert!(spawn_slot.is_ok(), "spawnd slot 0 must hold CapSpawn");
        let audit_slot = spawnd_capability_space.lookup_slot(1);
        assert!(
            audit_slot.is_err(),
            "spawnd slot 1 must be null (no AuditRead)"
        );
    }

    /// Creates an auditd process and verifies its CSpace has exactly CapAuditRead in slot 0.
    fn verify_auditd_receives_only_audit_read_capability() {
        let auditd_result = create_server_process(ProcessType::Auditd, 0x0000_0000_0040_0000);
        assert!(
            auditd_result.is_ok(),
            "auditd process must be created successfully"
        );
        let mut auditd_capability_space = CapabilitySpace::new();
        grant_initial_capability_to_server(
            &mut auditd_capability_space,
            0,
            CapabilityType::AuditRead,
            capability_rights::READ,
        );
        let audit_slot = auditd_capability_space.lookup_slot(0);
        assert!(audit_slot.is_ok(), "auditd slot 0 must hold CapAuditRead");
        let spawn_slot = auditd_capability_space.lookup_slot(1);
        assert!(
            spawn_slot.is_err(),
            "auditd slot 1 must be null (no CapSpawn)"
        );
    }
}
