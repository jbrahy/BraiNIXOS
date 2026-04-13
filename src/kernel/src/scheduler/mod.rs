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
