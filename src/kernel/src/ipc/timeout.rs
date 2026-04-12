//! Timeout deadline computation and expiry helpers (IPC_SPEC.md §7).
//!
//! All blocking IPC operations have a mandatory timeout. The current_tick
//! is passed as a parameter (not read via RDTSC) for deterministic testing (D-12).
//!
//! Enforces INV-IPC-003: waiting is bounded or explicitly policy-controlled.
//! Enforces INV-SCHED-003: timeout processing is deterministic.

use crate::ipc::IpcError;

/// Reserved timeout value that is explicitly invalid (IPC_SPEC.md §7).
///
/// Callers passing u64::MAX as timeout_ticks are rejected immediately.
const RESERVED_INVALID_TIMEOUT: u64 = u64::MAX;

/// Computes the absolute tick deadline from `current_tick` and `timeout_ticks`.
///
/// Returns `Err(IpcError::InvalidTimeout)` if `timeout_ticks` is `u64::MAX`
/// (reserved) or if the addition would overflow.
///
/// Enforces INV-IPC-003: no infinite timeout.
/// Verified by: test_ipc_timeout_unblocks_sender_with_timeout_error (SC-03)
pub fn compute_timeout_deadline(
    current_tick: u64,
    timeout_ticks: u64,
) -> Result<u64, IpcError> {
    if timeout_ticks == RESERVED_INVALID_TIMEOUT {
        return Err(IpcError::InvalidTimeout);
    }
    current_tick.checked_add(timeout_ticks).ok_or(IpcError::InvalidTimeout)
}

/// Returns `true` if `current_tick` has reached or passed `deadline_tick`.
///
/// Enforces INV-SCHED-003: timeout check is deterministic per tick.
/// Verified by: test_ipc_timeout_unblocks_sender_with_timeout_error (SC-03)
pub fn has_thread_timed_out(deadline_tick: u64, current_tick: u64) -> bool {
    current_tick >= deadline_tick
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_deadline_adds_ticks_to_current() {
        let deadline = compute_timeout_deadline(0, 100).unwrap();
        assert_eq!(deadline, 100);
    }

    #[test]
    fn compute_deadline_with_nonzero_current_tick() {
        let deadline = compute_timeout_deadline(50, 100).unwrap();
        assert_eq!(deadline, 150);
    }

    #[test]
    fn compute_deadline_overflow_returns_invalid_timeout() {
        let result = compute_timeout_deadline(u64::MAX - 1, 2);
        assert_eq!(result, Err(IpcError::InvalidTimeout));
    }

    #[test]
    fn compute_deadline_reserved_value_returns_invalid_timeout() {
        let result = compute_timeout_deadline(0, u64::MAX);
        assert_eq!(result, Err(IpcError::InvalidTimeout));
    }

    #[test]
    fn has_timed_out_returns_false_before_deadline() {
        assert!(!has_thread_timed_out(100, 99));
    }

    #[test]
    fn has_timed_out_returns_true_at_deadline() {
        assert!(has_thread_timed_out(100, 100));
    }

    #[test]
    fn has_timed_out_returns_true_after_deadline() {
        assert!(has_thread_timed_out(100, 101));
    }
}
