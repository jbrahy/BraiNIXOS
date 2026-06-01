//! Tick source abstraction for temporal capability validation.
//!
//! ## Design Decision: Parameter-Based Tick Injection
//!
//! Rather than reading RDTSC directly (which would require unsafe in the
//! capability module, violating the unsafe allowlist), the current kernel
//! tick is passed as a `current_tick: u64` parameter to `validate_capability`.
//!
//! This approach:
//! - Avoids all unsafe code in the capability module
//! - Makes temporal logic fully testable (tests pass explicit tick values)
//! - Enables Phase 5 to replace RDTSC with real timer interrupt ticks
//!   by changing only the syscall entry point (one-line change)
//!
//! ## Integration Path
//!
//! Phase 4 (syscall ABI): syscall handler reads RDTSC and passes to validate_capability
//! Phase 5 (scheduler): timer interrupt maintains a monotonic tick counter;
//!   syscall handler reads that counter instead of RDTSC
