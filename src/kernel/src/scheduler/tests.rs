//! Security test stubs for the scheduler subsystem.
//!
//! All tests are #[ignore] in Wave 0. Wave 1+ implements the test bodies
//! alongside the corresponding scheduler logic.

use super::budget_accounting::{
    check_budget_exhaustion, decrement_budget, is_budget_exhausted, reset_budget,
};
use super::partition_table::{
    compute_major_frame_total_ticks, MAJOR_FRAME_TOTAL_TICKS, PARTITION_TABLE,
};
use super::priority_inheritance::{
    apply_priority_inheritance_boost, compute_effective_priority, new_effective_priority_record,
    restore_base_priority, EffectivePriorityRecord,
};
use super::run_queue::RunQueue;
use super::time_partitioning::{
    advance_partition_slot_if_expired, is_thread_eligible_for_current_slot, new_major_frame_state,
};
use super::{SchedulerAction, SchedulerError, MAXIMUM_THREADS};

// --- Partition table tests ---

#[test]
fn test_partition_table_has_at_least_two_domain_slots() {
    let slot_count = PARTITION_TABLE.len();
    assert!(
        slot_count >= 2,
        "partition table must have at least 2 slots"
    );
}

#[test]
fn test_partition_table_slots_have_nonzero_durations() {
    for slot in PARTITION_TABLE.iter() {
        assert!(
            slot.duration_in_ticks > 0,
            "every partition slot must have nonzero duration"
        );
    }
}

#[test]
fn test_compute_major_frame_total_ticks_sums_all_slot_durations() {
    let expected_sum = 250_u64;
    let computed_sum = compute_major_frame_total_ticks();
    assert_eq!(computed_sum, expected_sum);
}

#[test]
fn test_major_frame_total_ticks_constant_matches_computed() {
    let computed = compute_major_frame_total_ticks();
    assert_eq!(MAJOR_FRAME_TOTAL_TICKS, computed);
}

// --- Run queue tests ---

#[test]
fn test_run_queue_insert_and_select_highest_priority() {
    let mut run_queue = RunQueue::new();
    let insert_result = run_queue.insert_thread(5, 10);
    assert!(insert_result.is_ok());
    let selected = run_queue.select_highest_priority_thread();
    assert_eq!(selected, Some(5));
}

#[test]
fn test_run_queue_returns_threads_in_priority_order() {
    let mut run_queue = RunQueue::new();
    run_queue.insert_thread(1, 5).unwrap();
    run_queue.insert_thread(2, 20).unwrap();
    run_queue.insert_thread(3, 10).unwrap();
    let highest = run_queue.select_highest_priority_thread();
    assert_eq!(
        highest,
        Some(2),
        "thread with priority 20 should be selected first"
    );
}

#[test]
fn test_run_queue_remove_makes_thread_unselectable() {
    let mut run_queue = RunQueue::new();
    run_queue.insert_thread(7, 15).unwrap();
    run_queue.remove_thread(7);
    let selected = run_queue.select_highest_priority_thread();
    assert_eq!(selected, None, "removed thread must not be selectable");
}

#[test]
fn test_run_queue_rejects_insert_when_full() {
    let mut run_queue = RunQueue::new();
    for thread_index in 0..super::MAXIMUM_THREADS {
        let result = run_queue.insert_thread(thread_index as u32, 10);
        assert!(result.is_ok());
    }
    let overflow_result = run_queue.insert_thread(999, 10);
    assert_eq!(overflow_result, Err(SchedulerError::NoEligibleThread));
}

#[test]
fn test_run_queue_is_empty_initially() {
    let run_queue = RunQueue::new();
    assert!(run_queue.is_empty());
    assert_eq!(run_queue.entry_count(), 0);
}

// --- Budget accounting tests ---

#[test]
fn test_decrement_budget_reduces_by_one() {
    let mut budget: u64 = 5;
    let remaining = decrement_budget(&mut budget);
    assert_eq!(remaining, 4);
    assert_eq!(budget, 4);
}

#[test]
fn test_decrement_budget_to_zero_returns_zero() {
    let mut budget: u64 = 1;
    let remaining = decrement_budget(&mut budget);
    assert_eq!(remaining, 0);
    assert_eq!(budget, 0);
}

#[test]
fn test_decrement_budget_saturates_at_zero() {
    let mut budget: u64 = 0;
    let remaining = decrement_budget(&mut budget);
    assert_eq!(remaining, 0);
}

#[test]
fn test_check_budget_exhaustion_returns_preempt_when_zero() {
    let action = check_budget_exhaustion(0);
    assert_eq!(action, SchedulerAction::PreemptCurrentThread);
}

#[test]
fn test_check_budget_exhaustion_returns_continue_when_nonzero() {
    let action = check_budget_exhaustion(5);
    assert_eq!(action, SchedulerAction::ContinueCurrentThread);
}

#[test]
fn test_is_budget_exhausted_returns_true_when_zero() {
    assert!(is_budget_exhausted(0));
}

#[test]
fn test_is_budget_exhausted_returns_false_when_nonzero() {
    assert!(!is_budget_exhausted(1));
}

#[test]
fn test_reset_budget_sets_new_value() {
    let mut budget: u64 = 0;
    reset_budget(&mut budget, 100);
    assert_eq!(budget, 100);
}

/// SC-01: A thread with a finite CPU budget is preempted when the budget is exhausted.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting, rejection on exhaustion.
/// Enforces INV-SCHED-004: exhaustion is explicit, never silent.
#[test]
fn test_process_is_preempted_when_budget_is_exhausted() {
    // SCHED-01 / INV-SCHED-001 / INV-SCHED-004
    let mut budget: u64 = 3;
    decrement_budget(&mut budget);
    decrement_budget(&mut budget);
    decrement_budget(&mut budget);
    let action = check_budget_exhaustion(budget);
    assert_eq!(action, SchedulerAction::PreemptCurrentThread);
    assert_eq!(budget, 0);
}

/// SC-02: Priority inheritance raises holder effective priority to waiter level.
///
/// Enforces INV-SCHED-002: priority inversion is eliminated by boosting the
/// holder to the waiter's priority level.
#[test]
fn test_priority_inheritance_boosts_low_priority_thread_while_holding_resource() {
    // SCHED-02 / INV-SCHED-002
    let mut table: [EffectivePriorityRecord; MAXIMUM_THREADS] = {
        let mut records = [new_effective_priority_record(0); MAXIMUM_THREADS];
        records[0] = new_effective_priority_record(1);
        records[1] = new_effective_priority_record(5);
        records[2] = new_effective_priority_record(10);
        records
    };
    apply_priority_inheritance_boost(0, 10, &mut table);
    let boosted_priority = compute_effective_priority(&table[0]);
    assert_eq!(
        boosted_priority, 10,
        "holder must be boosted to waiter priority"
    );
    let medium_priority = table[1].base_priority;
    assert!(
        medium_priority < boosted_priority,
        "medium thread cannot preempt boosted holder"
    );
    restore_base_priority(0, &mut table);
    let restored_priority = compute_effective_priority(&table[0]);
    assert_eq!(
        restored_priority, 1,
        "holder returns to base priority after restore"
    );
}

/// SC-03: A domain does not execute outside its assigned time slot.
///
/// Enforces INV-SCHED-001: domains cannot execute outside their assigned slot.
/// Enforces T-SCHED-05: covert timing channel between domains is eliminated.
#[test]
fn test_domain_does_not_run_outside_its_assigned_slot() {
    // SCHED-04 / INV-SCHED-001
    let mut major_frame_state = new_major_frame_state();
    // Slot 0 is domain 0 with 100 ticks. Confirm domain 0 eligible, domain 1 not.
    assert!(
        is_thread_eligible_for_current_slot(0, &major_frame_state),
        "domain 0 must be eligible in slot 0"
    );
    assert!(
        !is_thread_eligible_for_current_slot(1, &major_frame_state),
        "domain 1 must not be eligible in slot 0"
    );
    // Advance 100 ticks to exhaust slot 0 and move to slot 1 (domain 1).
    for _ in 0..100 {
        advance_partition_slot_if_expired(&mut major_frame_state);
    }
    // Now in slot 1 (domain 1): domain 1 eligible, domain 0 not.
    assert!(
        is_thread_eligible_for_current_slot(1, &major_frame_state),
        "domain 1 must be eligible in slot 1"
    );
    assert!(
        !is_thread_eligible_for_current_slot(0, &major_frame_state),
        "domain 0 must not be eligible in slot 1"
    );
}

/// SC-05: A hostile CPU consumer in domain 0 cannot starve domain 1 threads.
///
/// Sets up two threads: Thread 0 in domain 0 with maximum budget (hostile consumer),
/// Thread 1 in domain 1 with budget 100. Simulates one full major frame (250 ticks).
/// Verifies that Thread 1 receives its full 100-tick slot regardless of Thread 0's
/// behavior, because domain isolation is structural (enforced by the partition table).
///
/// Enforces INV-SCHED-001: domains cannot execute outside their assigned slot.
/// Enforces T-SCHED-09: hostile consumer in one domain cannot starve another domain.
#[test]
fn integration_hostile_cpu_consumer_does_not_starve_other_domains() {
    // SCHED-01 / SCHED-04 / INV-SCHED-001 / INV-SCHED-002
    use super::context_switch::process_scheduler_tick;
    use super::time_partitioning::is_thread_eligible_for_current_slot;

    let mut state = super::SchedulerState::new();

    // Thread 0: domain 0, hostile consumer with effectively infinite budget.
    state.thread_domain_slots[0] = 0;
    state.thread_budgets[0] = 1000;
    state.current_thread_index = Some(0);

    // Thread 1: domain 1, legitimate thread with budget matching its slot duration.
    state.thread_domain_slots[1] = 1;
    state.thread_budgets[1] = 100;

    let mut domain_one_ticks_while_thread_zero_active: u64 = 0;
    let mut domain_one_eligible_tick_count: u64 = 0;

    for _ in 0..250 {
        let domain_one_eligible = is_thread_eligible_for_current_slot(1, &state.major_frame_state);
        if domain_one_eligible {
            domain_one_eligible_tick_count += 1;
        }
        let thread_zero_domain_eligible =
            is_thread_eligible_for_current_slot(0, &state.major_frame_state);
        if domain_one_eligible && thread_zero_domain_eligible {
            domain_one_ticks_while_thread_zero_active += 1;
        }
        process_scheduler_tick(&mut state);
    }

    // Domain 1 must receive exactly its assigned 100 ticks per major frame.
    assert_eq!(
        domain_one_eligible_tick_count, 100,
        "domain 1 must receive exactly 100 ticks in its partition slot"
    );

    // Domain 0 and domain 1 never overlap — structural isolation guarantees this.
    assert_eq!(
        domain_one_ticks_while_thread_zero_active, 0,
        "domain 1 and domain 0 must never be simultaneously eligible"
    );
}
