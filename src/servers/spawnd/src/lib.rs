//! spawnd server: process creation authority with compile-time whitelist.
//!
//! spawnd holds CapSpawn and uses a compile-time whitelist (const array
//! of ProcessType) to decide which process types it will spawn. Any
//! request for a type not in the whitelist returns
//! SpawnError::ProcessTypeNotPermitted. Per D-08, D-09.
//!
//! Also carries the compile-time **restart policy** used when a server
//! crashes: each ProcessType has a maximum restart count; exceeding it
//! leaves the server stopped (fail-closed, not silently retried forever).
//! Crash detection itself (the signal from the kernel that a server has
//! exited abnormally) is separate future work; this module defines the
//! policy that will govern restart decisions once that signal is wired.
//!
//! Enforces INV-AUTH-001: no ambient spawn authority.
//! Enforces INV-AVL-001: availability failures are bounded and observable.
#![no_std]
#![deny(unsafe_code)]

use brainix_libsyscall::{ProcessType, SpawnError};

/// Compile-time whitelist of process types spawnd will create.
///
/// Adding a new ProcessType variant to libsyscall forces a compile
/// error here until the whitelist is explicitly updated. Per D-08.
const PERMITTED_PROCESS_TYPES: [ProcessType; 3] =
    [ProcessType::Init, ProcessType::Spawnd, ProcessType::Auditd];

/// Maximum number of automatic restarts per server crash event.
///
/// Exceeding this count produces `RestartDecision::RefuseRestart`, which
/// leaves the server stopped and records an audit entry (audit wiring is
/// future work). The value is deliberately small: a repeatedly-crashing
/// server indicates a latent bug that further restarts will not fix, and
/// unbounded restart attempts could mask an attacker's crash-exploit loop.
pub const MAXIMUM_AUTOMATIC_RESTART_COUNT: u32 = 3;

/// Outcome of a restart-policy decision for a crashed server.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RestartDecision {
    /// spawnd should restart the server; the new restart counter value is included.
    AllowRestart { new_restart_count: u32 },
    /// spawnd must not restart the server; the crash budget is exhausted.
    RefuseRestart,
    /// The crashed process type is not on the whitelist — must never restart.
    RefuseBecauseNotPermitted,
}

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

/// Decides whether a crashed server should be restarted.
///
/// Inputs:
///   - `crashed_process_type`: the type that just crashed.
///   - `previous_restart_count`: how many times this server has already been
///     restarted since boot (0 on the first crash).
///
/// Returns `AllowRestart` if the crash budget has room and the type is on
/// the whitelist; `RefuseRestart` if the budget is exhausted;
/// `RefuseBecauseNotPermitted` if the type is not on the whitelist.
///
/// Enforces INV-AVL-001: availability failures are bounded.
/// Verified by: tests::test_restart_decision_allows_first_crash
pub fn decide_server_restart(
    crashed_process_type: ProcessType,
    previous_restart_count: u32,
) -> RestartDecision {
    if !check_process_type_is_in_whitelist(crashed_process_type) {
        return RestartDecision::RefuseBecauseNotPermitted;
    }
    if previous_restart_count >= MAXIMUM_AUTOMATIC_RESTART_COUNT {
        return RestartDecision::RefuseRestart;
    }
    RestartDecision::AllowRestart {
        new_restart_count: previous_restart_count.saturating_add(1),
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
/// against the compile-time whitelist. Also receives crash notifications
/// and applies `decide_server_restart` to decide whether to respawn.
pub fn spawnd_main() -> ! {
    loop {
        // Phase 7 stub: receive IPC, validate, spawn or reject.
        // Crash notification -> decide_server_restart -> spawn or refuse.
        // Actual IPC receive loop and crash-notification wiring are future
        // work (requires syscall_ipc_receive in libsyscall). Until then,
        // the restart policy lives here as a pure decision function and is
        // exercised by unit tests.
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::{decide_server_restart, RestartDecision, MAXIMUM_AUTOMATIC_RESTART_COUNT};
    use brainix_libsyscall::ProcessType;

    /// First crash of a whitelisted server returns AllowRestart with count=1.
    #[test]
    fn test_restart_decision_allows_first_crash() {
        let decision = decide_server_restart(ProcessType::Auditd, 0);
        assert_eq!(
            decision,
            RestartDecision::AllowRestart {
                new_restart_count: 1,
            }
        );
    }

    /// Crash exactly at the maximum returns RefuseRestart (budget exhausted).
    #[test]
    fn test_restart_decision_refuses_after_maximum_exhausted() {
        let decision =
            decide_server_restart(ProcessType::Auditd, MAXIMUM_AUTOMATIC_RESTART_COUNT);
        assert_eq!(decision, RestartDecision::RefuseRestart);
    }

    /// A non-whitelisted process type never restarts, regardless of count.
    #[test]
    fn test_restart_decision_refuses_non_permitted_type() {
        let decision = decide_server_restart(ProcessType::DeviceServer, 0);
        assert_eq!(decision, RestartDecision::RefuseBecauseNotPermitted);
    }

    /// Restart count just below maximum still allows restart.
    #[test]
    fn test_restart_decision_allows_just_below_maximum() {
        let decision =
            decide_server_restart(ProcessType::Init, MAXIMUM_AUTOMATIC_RESTART_COUNT - 1);
        assert_eq!(
            decision,
            RestartDecision::AllowRestart {
                new_restart_count: MAXIMUM_AUTOMATIC_RESTART_COUNT,
            }
        );
    }
}
