//! Per-thread CPU budget accounting and exhaustion detection.
//!
//! Each thread has a cpu_budget_ticks field that is decremented on every
//! scheduler tick while the thread is running. When the budget reaches zero
//! the thread is preempted with an explicit BudgetExhausted error
//! (INV-SCHED-001, INV-SCHED-004).
