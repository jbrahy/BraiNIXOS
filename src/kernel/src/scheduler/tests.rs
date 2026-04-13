//! Security test stubs for the scheduler subsystem.
//!
//! All tests are #[ignore] in Wave 0. Wave 1+ implements the test bodies
//! alongside the corresponding scheduler logic.

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
