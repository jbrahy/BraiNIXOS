//! Domain compatibility check for simultaneous multithreading (SMT) siblings.
//!
//! The scheduler must not assign threads from different security domains to
//! sibling logical CPUs. In the single-core v1.0 configuration this guard
//! is always satisfied, but the architectural constraint must be present
//! for future SMP support (SCHED-03).
