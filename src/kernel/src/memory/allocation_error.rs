//! Allocation error types for the physical and pool allocators.
//!
//! Exhaustion is explicit, never silent (INV-SCHED-004).

/// Errors returned by the physical allocator and pool allocators.
///
/// Enforces invariant INV-SCHED-004: exhaustion is explicit, never silent.
/// No panic, no retry, no fallback on allocation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocationError {
    /// No free pages or slots remain in the system.
    OutOfMemory,
    /// The caller attempted to free a page that is already free.
    DoubleFree,
    /// The specific object pool is full (all slots occupied).
    PoolExhausted,
    /// The caller attempted to free a page whose type forbids deallocation
    /// (e.g., kernel pages that must never be freed).
    ForbiddenFree,
}

/// Returns a human-readable description for each allocation error variant.
fn error_description(error: &AllocationError) -> &'static str {
    match error {
        AllocationError::OutOfMemory => "out of memory: no free pages remain",
        AllocationError::DoubleFree => "double free: page is already free",
        AllocationError::PoolExhausted => "pool exhausted: all slots occupied",
        AllocationError::ForbiddenFree => "forbidden free: page type does not permit deallocation",
    }
}

impl core::fmt::Display for AllocationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let description = error_description(self);
        formatter.write_str(description)
    }
}
