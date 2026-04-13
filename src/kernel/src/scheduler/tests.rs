//! Security test stubs for the scheduler subsystem.
//!
//! All tests are #[ignore] in Wave 0. Wave 1+ implements the test bodies
//! alongside the corresponding scheduler logic.

use super::partition_table::{
    compute_major_frame_total_ticks, PartitionSlot, MAJOR_FRAME_TOTAL_TICKS, PARTITION_TABLE,
};
use super::run_queue::RunQueue;
use super::SchedulerError;

// --- Partition table tests ---

#[test]
fn test_partition_table_has_at_least_two_domain_slots() {
    let slot_count = PARTITION_TABLE.len();
    assert!(slot_count >= 2, "partition table must have at least 2 slots");
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
    assert_eq!(highest, Some(2), "thread with priority 20 should be selected first");
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

// --- Budget accounting tests (Task 2 will enable these) ---

#[test]
#[ignore]
fn test_process_is_preempted_when_budget_is_exhausted() {
    // SCHED-01 / INV-SCHED-001 / INV-SCHED-004
}

#[test]
#[ignore]
fn test_priority_inheritance_boosts_low_priority_thread_while_holding_resource() {
    // SCHED-02 / INV-SCHED-002
}

#[test]
#[ignore]
fn test_domain_does_not_run_outside_its_assigned_slot() {
    // SCHED-04 / INV-SCHED-001
}

#[test]
#[ignore]
fn integration_hostile_cpu_consumer_does_not_starve_other_domains() {
    // SCHED-01 / SCHED-04 / INV-SCHED-001 / INV-SCHED-002
}
