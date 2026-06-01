//! Major frame tracking and current partition slot determination.
//!
//! The scheduler divides CPU time into a repeating major frame composed of
//! partition slots from the compile-time partition table. Only threads whose
//! domain_slot matches the currently active slot are eligible to run.
//! This eliminates covert timing channels between security domains (SCHED-04).

use core::sync::atomic::{AtomicU64, Ordering};

use super::partition_table::PARTITION_TABLE;
use super::SchedulerAction;

/// Global monotonic tick counter incremented by the APIC timer interrupt handler.
///
/// Used by the attestation gate timeout enforcement (D-22) to measure elapsed time
/// from boot without requiring a separate hardware counter.
/// Incremented once per APIC timer interrupt (each call to advance_partition_slot_if_expired).
static GLOBAL_MONOTONIC_TICK_COUNT: AtomicU64 = AtomicU64::new(0);

/// Number of APIC timer ticks per second (APIC initial count / divide factor).
///
/// APIC initial count = 10_000, divide factor = 16.
/// Ticks per APIC cycle is hardware-dependent; this constant is the scheduler's
/// logical tick rate as configured in arch/timer.rs.
pub const SCHEDULER_TICKS_PER_SECOND: u64 = 1_000;

/// Read the current value of the global monotonic tick counter.
///
/// Used by the attestation gate timeout enforcement to measure elapsed time (D-22).
/// The counter is incremented once per APIC timer interrupt.
pub fn read_current_apic_timer_tick_count() -> u64 {
    GLOBAL_MONOTONIC_TICK_COUNT.load(Ordering::Relaxed)
}

/// Increment the global monotonic tick counter by one.
///
/// Called once per APIC timer interrupt from advance_partition_slot_if_expired.
/// Uses Relaxed ordering: the counter is monotonically increasing and only
/// read for timeout comparison (no synchronization with other operations required).
pub fn increment_global_monotonic_tick_count() {
    GLOBAL_MONOTONIC_TICK_COUNT.fetch_add(1, Ordering::Relaxed);
}

/// Tracks the scheduler's position within the current major frame.
///
/// Enforces INV-SCHED-001: domains cannot execute outside their assigned slot.
/// Verified by: test_domain_does_not_run_outside_its_assigned_slot
#[derive(Debug, Clone, Copy)]
pub struct MajorFrameState {
    /// Index into PARTITION_TABLE for the currently active slot.
    pub current_slot_index: usize,
    /// Number of ticks elapsed within the current slot.
    pub ticks_elapsed_in_current_slot: u64,
    /// Total ticks elapsed across all slots in this major frame instance.
    pub total_ticks_in_major_frame: u64,
}

/// Returns a new MajorFrameState with all fields zeroed (slot 0, tick 0).
pub const fn new_major_frame_state() -> MajorFrameState {
    MajorFrameState {
        current_slot_index: 0,
        ticks_elapsed_in_current_slot: 0,
        total_ticks_in_major_frame: 0,
    }
}

/// Returns the domain identifier of the currently active partition slot.
fn current_active_domain_identifier(state: &MajorFrameState) -> u8 {
    PARTITION_TABLE[state.current_slot_index].domain_identifier
}

/// Returns the duration in ticks of the currently active partition slot.
fn current_slot_duration(state: &MajorFrameState) -> u64 {
    PARTITION_TABLE[state.current_slot_index].duration_in_ticks
}

/// Returns true if the given domain slot matches the currently active slot.
///
/// Enforces INV-SCHED-001: domains cannot execute outside their assigned slot.
/// Verified by: test_domain_does_not_run_outside_its_assigned_slot
pub fn is_thread_eligible_for_current_slot(
    thread_domain_slot: u8,
    state: &MajorFrameState,
) -> bool {
    thread_domain_slot == current_active_domain_identifier(state)
}

/// Returns the domain identifier of the currently active slot (public accessor).
pub fn current_active_domain(state: &MajorFrameState) -> u8 {
    current_active_domain_identifier(state)
}

/// Resets the elapsed tick count and advances the slot index, wrapping at table end.
#[allow(clippy::arithmetic_side_effects)]
fn advance_to_next_slot(state: &mut MajorFrameState) {
    state.ticks_elapsed_in_current_slot = 0;
    state.current_slot_index += 1;
    if state.current_slot_index >= PARTITION_TABLE.len() {
        state.current_slot_index = 0;
    }
}

/// Increments the tick counter and advances the slot if the current slot has expired.
///
/// Returns `SwitchToPartitionSlot` when the slot boundary is crossed;
/// `ContinueCurrentThread` otherwise.
///
/// Also increments the global monotonic tick counter (used by attestation gate D-22).
///
/// Enforces INV-SCHED-001: domains cannot execute outside their assigned slot.
/// Verified by: test_domain_does_not_run_outside_its_assigned_slot
#[allow(clippy::arithmetic_side_effects)]
pub fn advance_partition_slot_if_expired(state: &mut MajorFrameState) -> SchedulerAction {
    increment_global_monotonic_tick_count();
    state.ticks_elapsed_in_current_slot += 1;
    state.total_ticks_in_major_frame += 1;
    if state.ticks_elapsed_in_current_slot >= current_slot_duration(state) {
        advance_to_next_slot(state);
        return SchedulerAction::SwitchToPartitionSlot;
    }
    SchedulerAction::ContinueCurrentThread
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::partition_table::PARTITION_TABLE;

    #[test]
    fn test_is_thread_eligible_returns_true_when_domain_matches() {
        let state = new_major_frame_state();
        let active_domain = PARTITION_TABLE[0].domain_identifier;
        assert!(is_thread_eligible_for_current_slot(active_domain, &state));
    }

    #[test]
    fn test_is_thread_eligible_returns_false_when_domain_does_not_match() {
        let state = new_major_frame_state();
        let active_domain = PARTITION_TABLE[0].domain_identifier;
        let other_domain = active_domain.wrapping_add(1);
        assert!(!is_thread_eligible_for_current_slot(other_domain, &state));
    }

    #[test]
    fn test_advance_slot_returns_continue_before_expiry() {
        let mut state = new_major_frame_state();
        let slot_duration = PARTITION_TABLE[0].duration_in_ticks;
        // Advance one tick less than the full slot duration.
        for _ in 0..(slot_duration - 1) {
            let action = advance_partition_slot_if_expired(&mut state);
            assert_eq!(action, SchedulerAction::ContinueCurrentThread);
        }
    }

    #[test]
    fn test_advance_slot_returns_switch_when_slot_duration_elapses() {
        let mut state = new_major_frame_state();
        let slot_duration = PARTITION_TABLE[0].duration_in_ticks;
        for _ in 0..(slot_duration - 1) {
            advance_partition_slot_if_expired(&mut state);
        }
        let action = advance_partition_slot_if_expired(&mut state);
        assert_eq!(action, SchedulerAction::SwitchToPartitionSlot);
    }

    #[test]
    fn test_major_frame_wraps_to_slot_zero_after_last_slot() {
        let mut state = new_major_frame_state();
        let total_ticks: u64 = PARTITION_TABLE
            .iter()
            .map(|slot| slot.duration_in_ticks)
            .sum();
        for _ in 0..total_ticks {
            advance_partition_slot_if_expired(&mut state);
        }
        assert_eq!(
            state.current_slot_index, 0,
            "major frame must wrap to slot 0"
        );
    }
}
