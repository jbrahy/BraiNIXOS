//! Capability type discriminant enumeration.
//!
//! Enforces invariant INV-AUTH-002: authority is explicit and typed.
//! Every capability has exactly one type tag checked on every invocation.
//! Type confusion returns `CapabilityError::TypeMismatch`.

/// Discriminant identifying the kernel object type a capability grants access to.
///
/// Enforces INV-AUTH-002: authority is explicit and typed.
/// The type tag is checked on every capability invocation.
///
/// Verified by: tests::test_new_capability_space_all_slots_read_as_null
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapabilityType {
    /// Authority over a physical memory region.
    Memory = 0,
    /// Authority to send to or receive from an IPC endpoint.
    Endpoint = 1,
    /// Authority over a thread's execution.
    Thread = 2,
    /// Authority over a capability space node.
    CNode = 3,
    /// Authority to bind and handle a specific hardware interrupt line.
    Irq = 4,
    /// Authority to access a specific hardware device's MMIO region.
    Device = 5,
    /// Authority over raw untyped memory that can be retyped into kernel objects.
    Untyped = 6,
    /// Single-use authority to reply to a specific IPC call.
    Reply = 7,
    /// Authority to create new processes from a compile-time whitelist.
    Spawn = 8,
    /// Authority to read (but not write) the kernel audit log.
    AuditRead = 9,
    /// Authority over a shared physical memory frame for inter-server packet exchange.
    Frame = 10,
}
