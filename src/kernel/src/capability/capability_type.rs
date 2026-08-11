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

    // -----------------------------------------------------------------------
    // Serving-era types (P2-T5).
    //
    // Discriminants are normative and their only normative home is
    // `docs/architecture/CAPABILITY_MODEL.md`. `NORTH_STAR.md` deliberately
    // carries no numeric capability IDs, so this enum and that table are the
    // pair that must agree.
    // -----------------------------------------------------------------------
    /// Authority over **one client session** on the serving path.
    ///
    /// Read and write that session's request/response stream, and reference
    /// that session's KV partition. **Cannot name any other session** — that is
    /// the structural basis of `INV-SERVE-001`, not a policy check.
    ///
    /// Per-session, never per-client-class: a capability covering "all sessions
    /// of this client" would reintroduce the cross-naming path INV-SERVE exists
    /// to eliminate. Granted per-connection by `servd`, frozen at grant, revoked
    /// at teardown.
    Serve = 11,

    /// Authority to invoke the served model within a session.
    ///
    /// Confers **compute, not authority**: a confined inference request against
    /// the read-only weights view and the caller's own KV slice, and nothing
    /// else. No spawn, no kernel mutation, no network, no reading another
    /// session (`INV-MODEL-001`).
    ///
    /// That asymmetry — all available compute, zero authority — is what makes
    /// prompt injection a bounded problem rather than an escalation path.
    Model = 12,

    /// Authority over an accelerator's bounded MMIO and DMA windows.
    ///
    /// Access device registers within the granted window and submit command
    /// buffers. **Cannot widen its own DMA window** (`INV-DEV-006`) — the
    /// control that makes running Apple's opaque, DMA-capable GPU firmware
    /// survivable, and which must be proven before that firmware is ever
    /// loaded (AS-5-T0).
    Gpu = 13,

    /// Authority over **one admin session** on the same serving transport.
    ///
    /// Invokes the six frozen administrative verbs and nothing else.
    /// Administration is a second session *type* on one authenticated,
    /// capability-gated transport — never a shell.
    ///
    /// **A separate grant, not a stronger [`CapabilityType::Serve`].** There is
    /// no derivation path from `Serve` to `Admin` or back: derivation preserves
    /// the parent's type, so the two are distinguished by capability and by
    /// nothing else. A session's type is decided at accept and frozen there.
    /// Proven in `src/capability-verify/`.
    Admin = 14,
}
