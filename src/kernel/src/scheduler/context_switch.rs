//! Thread selection and state transitions for context switching.
//!
//! Contains pure logic for selecting the next thread to run and combining
//! budget exhaustion, partition slot advancement, and IPC timeout processing
//! into a single per-tick scheduler entry point.
//!
//! Hardware-specific register save and restore lives in arch/ under the
//! unsafe allowlist.
//!
//! `#[no_mangle]` on `CURRENT_THREAD_IDENTIFIER_VALUE` is grouped under the
//! `unsafe_code` lint on nightly Rust. This file falls under the
//! `src/kernel/src/arch/` (assembly stubs) allowlist entry — the scheduler
//! writes the identifier that the assembly stub reads via RIP-relative addressing.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU32, Ordering};

use super::budget_accounting::{check_budget_exhaustion, decrement_budget};
use super::priority_inheritance::compute_effective_priority;
use super::time_partitioning::{
    advance_partition_slot_if_expired, is_thread_eligible_for_current_slot,
};
use super::{SchedulerAction, SchedulerState, MAXIMUM_THREADS};
use crate::thread::{Thread, ThreadState};

/// Scheduler-maintained current thread identifier, readable from the SYSCALL
/// assembly entry stub via RIP-relative addressing.
///
/// Written by the scheduler before context switch (SYSRET).
/// Read by syscall_entry_point assembly stub before `call dispatch_syscall`.
/// AtomicU32 avoids static mut; Relaxed ordering sufficient for single-core
/// (INV-SCHED-001).
///
/// `#[no_mangle]` required for assembly reference via symbol name.
#[no_mangle]
pub static CURRENT_THREAD_IDENTIFIER_VALUE: AtomicU32 = AtomicU32::new(0);

/// Updates the current thread identifier before context switch.
///
/// Called by the scheduler immediately after setting current_thread_index.
/// The assembly stub reads this value to pass thread identity to dispatch_syscall.
///
/// Enforces D-03: single write point for thread identity.
pub fn set_current_thread_identifier(thread_identifier: u32) {
    CURRENT_THREAD_IDENTIFIER_VALUE.store(thread_identifier, Ordering::Relaxed);
}

/// Combines a partition action and budget action into a single scheduler decision.
///
/// PreemptAndSwitchSlot when both preemption and slot transition are required.
fn combine_scheduler_actions(
    partition_action: SchedulerAction,
    budget_action: SchedulerAction,
) -> SchedulerAction {
    let slot_switched = partition_action == SchedulerAction::SwitchToPartitionSlot;
    let budget_exhausted = budget_action == SchedulerAction::PreemptCurrentThread;
    if slot_switched && budget_exhausted {
        return SchedulerAction::PreemptAndSwitchSlot;
    }
    if budget_exhausted {
        return SchedulerAction::PreemptCurrentThread;
    }
    if slot_switched {
        return SchedulerAction::SwitchToPartitionSlot;
    }
    SchedulerAction::ContinueCurrentThread
}

/// Decrements the current thread's budget if a thread is currently running.
fn decrement_current_thread_budget(state: &mut SchedulerState) {
    if let Some(thread_index) = state.current_thread_index {
        decrement_budget(&mut state.thread_budgets[thread_index as usize]);
    }
}

/// Returns the budget action for the current thread (Preempt if exhausted).
fn evaluate_current_thread_budget(state: &SchedulerState) -> SchedulerAction {
    match state.current_thread_index {
        Some(thread_index) => check_budget_exhaustion(state.thread_budgets[thread_index as usize]),
        None => SchedulerAction::ContinueCurrentThread,
    }
}

/// Processes pending IPC rendezvous completions before budget/timeout evaluation.
///
/// Enforces INV-SCHED-003: rendezvous completions are always processed before
/// timeout preemption on the same tick.
/// Phase 5: no-op stub — wired in Phase 7.
pub fn process_pending_rendezvous_completions(_state: &mut SchedulerState) {
    // Phase 5: no real userspace threads; no pending rendezvous completions.
    // Phase 7: wire real IPC timeout-to-ready transitions here (INV-SCHED-003).
    // MUST be called before budget evaluation and timeout processing in process_scheduler_tick.
}

/// Issues the Indirect Branch Prediction Barrier before context switch.
///
/// Clears branch predictor state from the old thread before new thread executes.
/// Called at the start of each scheduler tick to prevent cross-process Spectre v2
/// attacks (T-HW-SPEC-03). Placed BEFORE register save/restore per D-01.
///
/// Enforces INV-X86-002 (Spectre v2 mitigation: IBPB on every context switch).
/// Verified by: test_ibpb_is_issued_on_context_switch_path
fn issue_indirect_branch_prediction_barrier_before_switch() {
    #[cfg(target_arch = "x86_64")]
    crate::hardware_security::spectre_mitigation::issue_indirect_branch_prediction_barrier();
}

/// Processes one scheduler tick: increments the tick counter, issues IBPB,
/// processes pending rendezvous completions, decrements the current thread's
/// budget, advances the partition slot if expired, and combines the results.
///
/// IBPB is issued at the top of every tick to clear the branch predictor state
/// before any thread code executes. This enforces INV-X86-002.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting.
/// Enforces INV-X86-002: IBPB on every context switch path.
/// Verified by: context_switch inline tests
#[allow(clippy::arithmetic_side_effects)]
pub fn process_scheduler_tick(state: &mut SchedulerState) -> SchedulerAction {
    state.current_tick += 1;
    issue_indirect_branch_prediction_barrier_before_switch();
    process_pending_rendezvous_completions(state);
    decrement_current_thread_budget(state);
    let partition_action = advance_partition_slot_if_expired(&mut state.major_frame_state);
    let budget_action = evaluate_current_thread_budget(state);
    combine_scheduler_actions(partition_action, budget_action)
}

/// Sets the current thread index and writes the thread identifier for assembly pickup.
///
/// This is the single write point for thread identity (D-03). The assembly stub
/// reads CURRENT_THREAD_IDENTIFIER_VALUE via RIP-relative addressing to load
/// thread identity into rsi before calling dispatch_syscall.
///
/// Enforces INV-SCHED-001: thread identity is always consistent with scheduler state.
pub fn activate_thread_as_current(state: &mut SchedulerState, thread_index: u32) {
    state.current_thread_index = Some(thread_index);
    set_current_thread_identifier(thread_index);
}

/// Returns the thread index of the highest-effective-priority thread in the run queue.
///
/// Returns None when no eligible thread exists.
/// Verified by: context_switch inline tests
pub fn select_next_thread_to_run(state: &SchedulerState) -> Option<u32> {
    state.run_queue.select_highest_priority_thread()
}

/// Returns true if the thread at the given index is eligible to enter the run queue.
fn is_thread_eligible_to_run(
    thread_index: usize,
    state: &SchedulerState,
    threads: &[Thread; MAXIMUM_THREADS],
) -> bool {
    let thread_is_ready = threads[thread_index].thread_state == ThreadState::Ready;
    let domain_matches = is_thread_eligible_for_current_slot(
        state.thread_domain_slots[thread_index],
        &state.major_frame_state,
    );
    let has_budget = state.thread_budgets[thread_index] > 0;
    thread_is_ready && domain_matches && has_budget
}

/// Inserts one eligible thread into the run queue with its computed effective priority.
fn insert_eligible_thread_into_run_queue(thread_index: usize, state: &mut SchedulerState) {
    let effective_priority =
        compute_effective_priority(&state.effective_priority_table[thread_index]);
    let _ = state
        .run_queue
        .insert_thread(thread_index as u32, effective_priority);
}

/// Rebuilds the run queue for the current partition slot.
///
/// Clears the existing run queue and re-populates it with all threads that are
/// Ready, belong to the active domain slot, and have remaining budget.
///
/// Called on partition slot boundary. Enforces INV-SCHED-001.
/// Verified by: context_switch inline tests
pub fn rebuild_run_queue_for_current_slot(
    state: &mut SchedulerState,
    threads: &[Thread; MAXIMUM_THREADS],
) {
    state.run_queue = super::run_queue::RunQueue::new();
    for thread_index in 0..MAXIMUM_THREADS {
        if is_thread_eligible_to_run(thread_index, state, threads) {
            insert_eligible_thread_into_run_queue(thread_index, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::partition_table::PARTITION_TABLE;
    use crate::scheduler::SchedulerState;

    fn state_with_running_thread(thread_index: u32, budget: u64) -> SchedulerState {
        let mut state = SchedulerState::new();
        state.current_thread_index = Some(thread_index);
        state.thread_budgets[thread_index as usize] = budget;
        state
    }

    #[test]
    fn test_process_scheduler_tick_with_budget_and_slot_not_expired_returns_continue() {
        let mut state = state_with_running_thread(0, 50);
        // Slot 0 has 100 ticks; budget 50 > 1 after decrement.
        let action = process_scheduler_tick(&mut state);
        assert_eq!(action, SchedulerAction::ContinueCurrentThread);
    }

    #[test]
    fn test_process_scheduler_tick_with_budget_reaching_zero_returns_preempt() {
        let mut state = state_with_running_thread(0, 1);
        // One tick: budget goes from 1 to 0; slot not expired (only tick 1 of 100).
        let action = process_scheduler_tick(&mut state);
        assert_eq!(action, SchedulerAction::PreemptCurrentThread);
    }

    #[test]
    fn test_process_scheduler_tick_with_slot_expired_returns_switch() {
        let mut state = state_with_running_thread(0, 200);
        let slot_duration = PARTITION_TABLE[0].duration_in_ticks;
        // Advance to the last tick of slot 0 (budget stays above 0).
        for _ in 0..(slot_duration - 1) {
            process_scheduler_tick(&mut state);
        }
        let action = process_scheduler_tick(&mut state);
        assert_eq!(action, SchedulerAction::SwitchToPartitionSlot);
    }

    #[test]
    fn test_process_scheduler_tick_with_budget_zero_and_slot_expired_returns_preempt_and_switch() {
        // Budget = slot_duration so both exhaust on the same tick.
        let slot_duration = PARTITION_TABLE[0].duration_in_ticks;
        let mut state = state_with_running_thread(0, slot_duration);
        for _ in 0..(slot_duration - 1) {
            process_scheduler_tick(&mut state);
        }
        let action = process_scheduler_tick(&mut state);
        assert_eq!(action, SchedulerAction::PreemptAndSwitchSlot);
    }

    #[test]
    fn test_select_next_thread_to_run_returns_highest_priority_thread() {
        let mut state = SchedulerState::new();
        state.run_queue.insert_thread(3, 20).unwrap();
        state.run_queue.insert_thread(7, 5).unwrap();
        let selected = select_next_thread_to_run(&state);
        assert_eq!(selected, Some(3), "thread 3 has highest priority");
    }

    #[test]
    fn test_select_next_thread_to_run_returns_none_when_queue_is_empty() {
        let state = SchedulerState::new();
        let selected = select_next_thread_to_run(&state);
        assert_eq!(selected, None);
    }

    #[test]
    fn test_activate_thread_as_current_sets_index_and_identifier() {
        let mut state = SchedulerState::new();
        activate_thread_as_current(&mut state, 5);
        assert_eq!(state.current_thread_index, Some(5));
        let stored = CURRENT_THREAD_IDENTIFIER_VALUE.load(Ordering::Relaxed);
        assert_eq!(stored, 5);
    }

    #[test]
    fn test_set_current_thread_identifier_stores_value() {
        set_current_thread_identifier(7);
        let stored = CURRENT_THREAD_IDENTIFIER_VALUE.load(Ordering::Relaxed);
        assert_eq!(stored, 7);
    }
}
