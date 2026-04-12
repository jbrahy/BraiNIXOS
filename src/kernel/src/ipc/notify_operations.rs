//! CapNotification operations: signal, wait, poll (D-06, IPC_SPEC.md §2).
//!
//! Notifications are lightweight non-blocking signals. They do not transfer
//! capabilities or message registers. Used for upward event signaling from
//! lower architectural layers to upper layers without blocking IPC calls.
//!
//! Enforces IPC_SPEC.md §2: notifications distinct from synchronous endpoints.
//! Enforces INV-IPC-003: notify_wait has mandatory timeout.
//!
//! does not transfer capabilities or message registers — architectural constraint.

use crate::ipc::notification::Notification;
use crate::ipc::timeout::{compute_timeout_deadline, has_thread_timed_out};
use crate::ipc::IpcError;
use crate::thread::{Thread, ThreadState};

/// Signals `signal_mask` bits to `notification` (SYS_NOTIFY_SIGNAL, D-06).
///
/// Atomically ORs `signal_mask` into the notification bitmap.
/// Never blocks. Corresponds to the non-blocking sender side of notification.
pub fn notify_signal(notification: &Notification, signal_mask: u64) {
    notification.signal(signal_mask);
}

/// Reads and clears all pending signals without blocking (SYS_NOTIFY_POLL, D-06).
///
/// Returns the pending signal bitmap at the moment of the call.
/// If no signals are pending, returns 0 immediately.
pub fn notify_poll(notification: &Notification) -> u64 {
    notification.poll_and_clear()
}

/// Waits for at least one signal to be pending, with mandatory timeout (SYS_NOTIFY_WAIT, D-06).
///
/// If signals are already pending: reads, clears, and returns them immediately.
/// If no signals pending: blocks the thread until a signal arrives or the timeout fires.
///
/// Returns `Err(IpcError::InvalidTimeout)` if `timeout_ticks` is `u64::MAX`.
/// Returns `Err(IpcError::Timeout)` if the deadline fires before any signal arrives.
///
/// Enforces INV-IPC-003: no indefinite blocking.
pub fn notify_wait(
    notification: &Notification,
    waiting_thread: &mut Thread,
    timeout_ticks: u64,
    current_tick: u64,
) -> Result<u64, IpcError> {
    if notification.has_pending_signals() {
        return Ok(notification.poll_and_clear());
    }
    block_thread_for_notification_wait(waiting_thread, timeout_ticks, current_tick)
}

/// Blocks the thread until a notification signal arrives or the timeout fires.
///
/// In Phase 4 (no scheduler), this simulates blocking by checking the
/// timeout deadline immediately (tick injection makes tests deterministic).
/// Phase 5 will replace this with a real scheduler yield point.
fn block_thread_for_notification_wait(
    waiting_thread: &mut Thread,
    timeout_ticks: u64,
    current_tick: u64,
) -> Result<u64, IpcError> {
    let deadline = compute_timeout_deadline(current_tick, timeout_ticks)?;
    set_thread_to_blocked_with_deadline(waiting_thread, deadline);
    check_if_immediately_timed_out(waiting_thread, current_tick)
}

/// Sets thread state to Blocked and records the timeout deadline.
fn set_thread_to_blocked_with_deadline(thread: &mut Thread, deadline_tick: u64) {
    thread.timeout_deadline_tick = deadline_tick;
    thread.thread_state = ThreadState::Blocked;
}

/// If the timeout fires at or before current_tick, unblocks with Timeout error.
///
/// In Phase 4 with no scheduler, always returns Timeout when no signals are pending
/// at call time — no other thread can run to deliver a signal.
fn check_if_immediately_timed_out(
    thread: &mut Thread,
    current_tick: u64,
) -> Result<u64, IpcError> {
    if has_thread_timed_out(thread.timeout_deadline_tick, current_tick) {
        thread.thread_state = ThreadState::Ready;
        return Err(IpcError::Timeout);
    }
    Err(IpcError::Timeout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::notification::Notification;
    use crate::thread::{Thread, ThreadState};

    #[test]
    fn notify_signal_ors_bits_into_bitmap() {
        let notification = Notification::new();
        notify_signal(&notification, 0b0001);
        notify_signal(&notification, 0b0010);
        let pending = notify_poll(&notification);
        assert_eq!(pending, 0b0011);
    }

    #[test]
    fn notify_poll_clears_bitmap_and_returns_value() {
        let notification = Notification::new();
        notify_signal(&notification, 0b1100);
        let first_poll = notify_poll(&notification);
        let second_poll = notify_poll(&notification);
        assert_eq!(first_poll, 0b1100);
        assert_eq!(second_poll, 0);
    }

    #[test]
    fn notify_wait_returns_immediately_when_signals_pending() {
        let notification = Notification::new();
        let mut thread = Thread::new();
        notify_signal(&notification, 0b0101);
        let result = notify_wait(&notification, &mut thread, 100, 0);
        assert_eq!(result, Ok(0b0101));
        assert_eq!(thread.thread_state, ThreadState::Ready);
    }

    #[test]
    fn notify_wait_with_no_signals_and_expired_timeout_returns_timeout_error() {
        let notification = Notification::new();
        let mut thread = Thread::new();
        // timeout_ticks=0 means try only — fires immediately
        let result = notify_wait(&notification, &mut thread, 0, 100);
        assert_eq!(result, Err(IpcError::Timeout));
    }

    #[test]
    fn notify_wait_with_reserved_timeout_returns_invalid_timeout() {
        let notification = Notification::new();
        let mut thread = Thread::new();
        let result = notify_wait(&notification, &mut thread, u64::MAX, 0);
        assert_eq!(result, Err(IpcError::InvalidTimeout));
    }
}
