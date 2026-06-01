//! Per-thread CPU budget accounting and exhaustion detection.
//!
//! Each thread has a cpu_budget_ticks field that is decremented on every
//! scheduler tick while the thread is running. When the budget reaches zero
//! the thread is preempted with an explicit BudgetExhausted error
//! (INV-SCHED-001, INV-SCHED-004).

use super::SchedulerAction;

/// Decrements the given budget by one tick using saturating subtraction.
///
/// Returns the new budget value after decrement.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting.
/// Verified by: test_decrement_budget_reduces_by_one
pub fn decrement_budget(current_budget: &mut u64) -> u64 {
    *current_budget = current_budget.saturating_sub(1);
    *current_budget
}

/// Returns the scheduler action based on whether the budget is exhausted.
///
/// Returns `PreemptCurrentThread` if budget is zero, else `ContinueCurrentThread`.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting.
/// Enforces INV-SCHED-004: exhaustion is explicit, never silent.
/// Verified by: test_process_is_preempted_when_budget_is_exhausted
pub fn check_budget_exhaustion(current_budget: u64) -> SchedulerAction {
    if current_budget == 0 {
        return SchedulerAction::PreemptCurrentThread;
    }
    SchedulerAction::ContinueCurrentThread
}

/// Resets the budget to the specified number of ticks.
///
/// Used at the start of each scheduling period to replenish a thread's budget.
pub fn reset_budget(budget: &mut u64, new_budget_ticks: u64) {
    *budget = new_budget_ticks;
}

/// Returns true if the budget has been fully consumed.
///
/// Enforces INV-SCHED-004: exhaustion is explicit, never silent.
/// Verified by: test_is_budget_exhausted_returns_true_when_zero
pub fn is_budget_exhausted(current_budget: u64) -> bool {
    current_budget == 0
}
