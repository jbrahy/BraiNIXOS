//! Synchronous rendezvous IPC subsystem.
//!
//! Implements IPC_SPEC.md: endpoint objects, send/receive/call semantics,
//! capability transfer, CapReply lifecycle, timeout enforcement, WaitForGraph
//! deadlock detection, and CapNotification lightweight signaling.
//!
//! No cfg(target_arch) gate — pure Rust, host-testable (D-12).

pub mod bounded_queue;
pub mod call;
pub mod cap_reply;
pub mod endpoint;
pub mod notification;
pub mod notify_operations;
pub mod receive;
pub mod rendezvous;
pub mod send;
pub mod timeout;
pub mod wait_for_graph;

#[cfg(test)]
mod tests;

/// Maximum number of threads in the system.
///
/// Bounds the WaitForGraph adjacency array (~32*32 = 1KB BSS) and the
/// thread fixture array in tests. Single-core only; SMP is out of scope.
pub const MAXIMUM_THREADS: usize = 32;

/// Maximum number of endpoints in the global endpoint pool.
pub const MAXIMUM_ENDPOINTS: usize = 16;

/// Maximum number of threads that can queue on a single endpoint side.
///
/// Applied separately to the sender queue and receiver queue of each endpoint.
pub const MAXIMUM_THREADS_PER_ENDPOINT: usize = 8;

/// Reserved CSpace slot index where the kernel places CapReply on SYS_IPC_RECEIVE.
///
/// Slot 255 is reserved: userspace must never place a non-Reply capability here.
/// The kernel validates this slot is null before installing CapReply (D-06).
pub const CAPABILITY_REPLY_DESIGNATED_SLOT: u8 = 255;

/// Syscall number for a blocking send (IPC_SPEC.md §4).
pub const SYSCALL_NUMBER_IPC_SEND: u64 = 1;

/// Syscall number for a blocking receive (IPC_SPEC.md §4).
pub const SYSCALL_NUMBER_IPC_RECEIVE: u64 = 2;

/// Syscall number for atomic send-then-receive (IPC_SPEC.md §4).
pub const SYSCALL_NUMBER_IPC_CALL: u64 = 3;

/// Syscall number for non-blocking notification signal (D-06).
pub const SYSCALL_NUMBER_NOTIFY_SIGNAL: u64 = 4;

/// Syscall number for blocking notification wait (D-06).
pub const SYSCALL_NUMBER_NOTIFY_WAIT: u64 = 5;

/// Syscall number for non-blocking notification poll (D-06).
pub const SYSCALL_NUMBER_NOTIFY_POLL: u64 = 6;

/// Sentinel CSlot value indicating no capability transfer in an IPC message.
pub const CAPABILITY_TRANSFER_NONE_SENTINEL: u8 = 0xFF;

/// Errors that can be returned from IPC operations.
///
/// Each variant maps to a specific negative rax return code on SYSRET.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcError {
    /// The blocking timeout expired before a rendezvous partner arrived.
    /// Enforces INV-IPC-003: waiting is bounded.
    Timeout,
    /// A call detected that granting it would form a cycle in the wait-for graph.
    /// Enforces INV-IPC-004 (defense-in-depth) — returned before the caller blocks.
    WouldDeadlock,
    /// The endpoint capability was revoked while the thread was queued.
    EndpointRevoked,
    /// The destination CSlot for a received capability is not null.
    SlotOccupied,
    /// A capability transfer was attempted by a thread without Grant right.
    GrantRightNotHeld,
    /// The transferred rights exceed the sender's own rights (rights amplification).
    /// Enforces INV-IPC-002 / INV-AUTH-003.
    RightsExceedSender,
    /// A CapReply was used a second time; the slot was zeroed on first use.
    /// Enforces INV-AUTH-006.
    ReplyCapabilityAlreadyUsed,
    /// The CapReply designated slot (255) is occupied when a server calls receive.
    ReplySlotOccupied,
    /// The server that held the matching CapReply crashed or timed out.
    ReplyRevoked,
    /// The timeout value was u64::MAX (reserved) or otherwise invalid.
    InvalidTimeout,
    /// The endpoint sender queue or receiver queue is full.
    QueueFull,
}

/// The four data words transferred in an IPC message (IPC_SPEC.md §3).
///
/// Transferred in registers r8-r11; no kernel buffer, no heap allocation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IpcMessage {
    /// Message Register 0 (r8).
    pub register_zero: u64,
    /// Message Register 1 (r9).
    pub register_one: u64,
    /// Message Register 2 (r10).
    pub register_two: u64,
    /// Message Register 3 (r11, saved by kernel on SYSCALL entry).
    pub register_three: u64,
    /// Badge stamped by the endpoint, identifying sender authority.
    pub badge: u64,
}
