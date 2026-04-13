//! Priority inheritance protocol for bounded priority inversion.
//!
//! When a high-priority thread blocks waiting for a resource held by a
//! low-priority thread, the holder's effective priority is temporarily raised
//! to the waiter's level. This prevents medium-priority threads from preempting
//! the holder and causing unbounded priority inversion (INV-SCHED-002).
