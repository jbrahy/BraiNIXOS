//! Fixed-size priority-sorted run queue for eligible threads.
//!
//! Holds thread indices sorted by effective priority (highest first).
//! Only threads in the current domain slot and with remaining budget are eligible.
//! Bounded by MAXIMUM_THREADS to avoid dynamic allocation.
