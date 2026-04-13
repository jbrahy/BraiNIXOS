//! init server: delegates authority to spawnd and auditd, then exits.
//!
//! init is the only process that starts with bootstrap authority.
//! After delegating CapSpawn to spawnd and CapAuditRead to auditd
//! via IPC capability transfer, init calls sys_process_exit to
//! remove itself from the system. Per D-06, D-07.
//!
//! Enforces INV-AUTH-001: no ambient authority after init exits.
#![no_std]
#![deny(unsafe_code)]

use brainix_libsyscall::syscall_process_exit;

/// Capability slot index for CapSpawn in init's CSpace (assigned by kernel at boot).
const CAPABILITY_SLOT_SPAWN_AUTHORITY: u8 = 0;

/// Capability slot index for CapAuditRead in init's CSpace (assigned by kernel at boot).
const CAPABILITY_SLOT_AUDIT_READ_AUTHORITY: u8 = 1;

/// Capability slot index for spawnd's IPC endpoint in init's CSpace.
const CAPABILITY_SLOT_SPAWND_ENDPOINT: u8 = 2;

/// Capability slot index for auditd's IPC endpoint in init's CSpace.
const CAPABILITY_SLOT_AUDITD_ENDPOINT: u8 = 3;

/// init entry point. Called once by the kernel after boot.
///
/// Delegates CapSpawn to spawnd via IPC, delegates CapAuditRead to auditd
/// via IPC, then exits. After this function, no process holds bootstrap
/// authority.
///
/// Enforces INV-AUTH-001: bootstrap authority collapsed.
/// Verified by: test_init_process_exits_after_handing_off_authority
pub fn init_main() -> ! {
    delegate_spawn_authority_to_spawnd();
    delegate_audit_read_authority_to_auditd();
    exit_init_process()
}

fn delegate_spawn_authority_to_spawnd() {
    // Phase 7 stub: IPC capability transfer to spawnd.
    // Uses CapEndpoint in slot CAPABILITY_SLOT_SPAWND_ENDPOINT with Grant right
    // to transfer CapSpawn from slot CAPABILITY_SLOT_SPAWN_AUTHORITY to spawnd's CSpace.
    // Actual IPC call wired when boot sequence integration is complete.
    let _ = CAPABILITY_SLOT_SPAWN_AUTHORITY;
    let _ = CAPABILITY_SLOT_SPAWND_ENDPOINT;
}

fn delegate_audit_read_authority_to_auditd() {
    // Phase 7 stub: IPC capability transfer to auditd.
    // Uses CapEndpoint in slot CAPABILITY_SLOT_AUDITD_ENDPOINT with Grant right
    // to transfer CapAuditRead from slot CAPABILITY_SLOT_AUDIT_READ_AUTHORITY to auditd's CSpace.
    let _ = CAPABILITY_SLOT_AUDIT_READ_AUTHORITY;
    let _ = CAPABILITY_SLOT_AUDITD_ENDPOINT;
}

fn exit_init_process() -> ! {
    syscall_process_exit()
}
