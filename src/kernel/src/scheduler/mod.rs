//! Fixed-priority preemptive scheduler with time partitioning.
//!
//! Implements SCHED-01 through SCHED-05: CPU budgets, priority inheritance,
//! SMT isolation, compile-time partition table, and PCR[2] measurement.
//!
//! No cfg(target_arch) gate -- pure Rust logic, host-testable.

pub mod partition_table;
pub mod run_queue;
pub mod priority_inheritance;
pub mod budget_accounting;
pub mod time_partitioning;
pub mod context_switch;
pub mod measurement;
pub mod smt_isolation;

#[cfg(test)]
mod tests;

/// Re-export of the system-wide maximum thread count from the IPC subsystem.
pub use crate::ipc::MAXIMUM_THREADS;

/// Errors returned by scheduler operations.
///
/// Each variant corresponds to a specific security invariant violation
/// or scheduling constraint that prevents the requested operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerError {
    /// The thread's CPU budget has been fully consumed.
    /// Enforces INV-SCHED-001 and INV-SCHED-004.
    BudgetExhausted,
    /// The thread's domain is not assigned to the currently active partition slot.
    /// Enforces INV-SCHED-001.
    DomainNotInCurrentSlot,
    /// Scheduling the thread would violate SMT sibling isolation.
    /// Enforces SCHED-03.
    SmtIsolationViolation,
    /// No thread in the run queue is eligible to execute.
    NoEligibleThread,
}

/// Actions the scheduler can take after evaluating the current tick.
///
/// Returned by the tick handler to indicate what the caller must do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchedulerAction {
    /// The currently running thread continues executing.
    ContinueCurrentThread,
    /// The currently running thread must be preempted.
    PreemptCurrentThread,
    /// The active partition slot has changed; switch to the new slot's threads.
    SwitchToPartitionSlot,
    /// Both preemption and a slot transition are required.
    PreemptAndSwitchSlot,
}

/// Core scheduler state tracking all thread scheduling metadata.
///
/// This struct owns the scheduler's view of thread budgets, domain slots,
/// priorities, and the run queue. The Thread struct (Phase 4) is NOT modified;
/// this is the scheduler's own parallel tracking.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting.
pub struct SchedulerState {
    /// Index of the currently running thread, or None if idle.
    pub current_thread_index: Option<u32>,
    /// CPU budget remaining per thread (parallel array).
    pub thread_budgets: [u64; MAXIMUM_THREADS],
    /// Domain slot assignment per thread (parallel array).
    pub thread_domain_slots: [u8; MAXIMUM_THREADS],
    /// Base priority per thread (parallel array).
    pub thread_priorities: [u8; MAXIMUM_THREADS],
    /// The priority-sorted run queue of eligible threads.
    pub run_queue: run_queue::RunQueue,
    /// Current global tick counter.
    pub current_tick: u64,
}

impl SchedulerState {
    /// Creates a new scheduler state with all fields zeroed.
    pub const fn new() -> Self {
        SchedulerState {
            current_thread_index: None,
            thread_budgets: [0; MAXIMUM_THREADS],
            thread_domain_slots: [0; MAXIMUM_THREADS],
            thread_priorities: [0; MAXIMUM_THREADS],
            run_queue: run_queue::RunQueue::new(),
            current_tick: 0,
        }
    }
}
