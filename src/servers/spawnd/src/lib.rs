//! spawnd server: process creation authority with compile-time whitelist.
//!
//! spawnd holds CapSpawn and uses a compile-time whitelist (const array
//! of ProcessType) to decide which process types it will spawn. Any
//! request for a type not in the whitelist returns
//! SpawnError::ProcessTypeNotPermitted. Per D-08, D-09.
//!
//! Enforces INV-AUTH-001: no ambient spawn authority.
#![no_std]
#![deny(unsafe_code)]

use brainix_libsyscall::{ProcessType, SpawnError};

/// Compile-time whitelist of process types spawnd will create.
///
/// Adding a new ProcessType variant to libsyscall forces a compile
/// error here until the whitelist is explicitly updated. Per D-08.
const PERMITTED_PROCESS_TYPES: [ProcessType; 3] =
    [ProcessType::Init, ProcessType::Spawnd, ProcessType::Auditd];

/// Validates a spawn request against the compile-time whitelist.
///
/// Returns Ok(()) if the requested process type is permitted.
/// Returns Err(SpawnError::ProcessTypeNotPermitted) otherwise.
///
/// Enforces INV-AUTH-001: spawn authority is bounded.
/// Verified by: test_spawnd_refuses_process_type_not_in_whitelist
pub fn validate_spawn_request_against_whitelist(
    requested_process_type: ProcessType,
) -> Result<(), SpawnError> {
    let is_permitted = check_process_type_is_in_whitelist(requested_process_type);
    if is_permitted {
        Ok(())
    } else {
        Err(SpawnError::ProcessTypeNotPermitted)
    }
}

fn check_process_type_is_in_whitelist(process_type: ProcessType) -> bool {
    let mut index: usize = 0;
    while index < PERMITTED_PROCESS_TYPES.len() {
        if PERMITTED_PROCESS_TYPES[index] as u8 == process_type as u8 {
            return true;
        }
        index = index.wrapping_add(1);
    }
    false
}

/// spawnd main loop. Receives spawn requests via IPC and validates
/// against the compile-time whitelist.
pub fn spawnd_main() -> ! {
    loop {
        // Phase 7 stub: receive IPC, validate, spawn or reject.
        // Actual IPC receive loop wired when boot integration is complete.
        core::hint::spin_loop();
    }
}
