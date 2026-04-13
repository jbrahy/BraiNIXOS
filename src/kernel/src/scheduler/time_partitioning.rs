//! Major frame tracking and current partition slot determination.
//!
//! The scheduler divides CPU time into a repeating major frame composed of
//! partition slots from the compile-time partition table. Only threads whose
//! domain_slot matches the currently active slot are eligible to run.
//! This eliminates covert timing channels between security domains (SCHED-04).
