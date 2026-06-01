//! Audit event type classification for the capability audit log.
//!
//! Defines all security-relevant event categories tracked by the audit ring buffer
//! in Phase 3 scope. IPC and syscall events are added in Phase 4 per D-06.

/// Classifies the type of security event recorded in an audit log entry.
///
/// Each variant corresponds to a distinct security-relevant operation in the
/// capability manager. The `#[repr(u8)]` encoding is fixed in the D-06 format
/// spec — do not reorder or renumber variants without updating D-06.
///
/// Enforces INV-AUD-001: every capability authority change produces a log entry.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AuditEventType {
    /// A new capability was derived from a parent capability.
    CapabilityDerived = 0,
    /// A capability and all its descendants were explicitly revoked.
    CapabilityRevoked = 1,
    /// A temporal capability reached its use-count limit and expired.
    CapabilityExpired = 2,
    /// A capability slot was deleted and zeroed.
    CapabilitySlotDeleted = 3,
    /// A kernel boot sequence phase completed.
    BootSequenceEvent = 4,
    /// A physical memory allocation was performed by the kernel allocator.
    MemoryAllocationEvent = 5,
    /// A page fault was raised (ring-0 or unexpected userspace fault).
    PageFaultEvent = 6,
}
