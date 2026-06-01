//! CapNotification lightweight signaling object (D-05, IPC_SPEC.md §2).
//!
//! A single AtomicU64 bitmap. Signal is non-blocking OR; poll is non-blocking
//! read-and-clear. Wait (blocking) is implemented in the IPC operation layer.
//! Does not transfer capabilities or message registers.

use core::sync::atomic::{AtomicU64, Ordering};

/// A lightweight non-blocking signal object backed by a single AtomicU64.
///
/// Enforces IPC_SPEC.md §2: notifications are distinct from synchronous
/// endpoints and do not support capability transfer.
pub struct Notification {
    /// Bitmap of pending signals. Each bit represents a distinct signal channel.
    signal_word: AtomicU64,
}

impl Default for Notification {
    fn default() -> Self {
        Self::new()
    }
}

impl Notification {
    /// Returns a new notification with no pending signals.
    pub const fn new() -> Self {
        Notification {
            signal_word: AtomicU64::new(0),
        }
    }

    /// Signals `signal_mask` bits into the notification word (non-blocking).
    ///
    /// Atomically ORs `signal_mask` into the signal word.
    /// Never blocks; corresponds to SYS_NOTIFY_SIGNAL (D-06).
    pub fn signal(&self, signal_mask: u64) {
        self.signal_word.fetch_or(signal_mask, Ordering::Release);
    }

    /// Reads and clears all pending signals (non-blocking poll).
    ///
    /// Returns the pending signal bitmap and resets it to zero atomically.
    /// Corresponds to SYS_NOTIFY_POLL (D-06).
    pub fn poll_and_clear(&self) -> u64 {
        self.signal_word.swap(0, Ordering::AcqRel)
    }

    /// Returns `true` if at least one signal bit is pending.
    pub fn has_pending_signals(&self) -> bool {
        self.signal_word.load(Ordering::Acquire) != 0
    }
}

/// Initializes a single `Notification` for use in array construction.
fn build_cleared_notification() -> Notification {
    Notification::new()
}

/// A fixed-size pool of notification objects backed by a BSS array.
pub struct NotificationPool {
    notifications: [Notification; crate::ipc::MAXIMUM_ENDPOINTS],
}

impl Default for NotificationPool {
    fn default() -> Self {
        Self::new()
    }
}

impl NotificationPool {
    /// Returns a new pool with all notifications in the cleared state.
    pub fn new() -> Self {
        NotificationPool {
            notifications: core::array::from_fn(|_| build_cleared_notification()),
        }
    }

    /// Returns a shared reference to the notification at `notification_index`.
    pub fn notification_at(&self, notification_index: usize) -> Option<&Notification> {
        self.notifications.get(notification_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_notification_has_no_pending_signals() {
        let notification = Notification::new();
        assert!(!notification.has_pending_signals());
    }

    #[test]
    fn signal_sets_bits_and_poll_clears_them() {
        let notification = Notification::new();
        notification.signal(0b0011);
        assert!(notification.has_pending_signals());
        let pending = notification.poll_and_clear();
        assert_eq!(pending, 0b0011);
        assert!(!notification.has_pending_signals());
    }

    #[test]
    fn multiple_signals_accumulate_via_bitwise_or() {
        let notification = Notification::new();
        notification.signal(0b0001);
        notification.signal(0b0010);
        let pending = notification.poll_and_clear();
        assert_eq!(pending, 0b0011);
    }
}
