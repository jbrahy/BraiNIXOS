//! Brainix system call ABI definitions shared between the kernel and userspace servers.
//!
//! This crate defines the stable ABI boundary (D-09): all types crossing the syscall
//! boundary are defined here once and imported by both the kernel and server crates.
//! No type is duplicated on either side of the boundary.
//!
//! The kernel imports this crate as a dependency. Server crates also import it.
//! This guarantees the kernel and all servers agree on the representation of every
//! shared type at compile time.
#![no_std]
#![deny(unsafe_code)]

/// The process type assigned to each userspace server.
///
/// This enum encodes the role of a process in the Brainix microkernel. The kernel
/// uses the process type to determine which capabilities may be granted at spawn time.
/// spawnd enforces that only whitelisted process types can be spawned (INV-SPAWN-001).
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProcessType {
    /// The init process. Bootstraps all other servers and exits after authority handoff.
    /// No privileged process exists at runtime after init exits (INV-INIT-001).
    Init = 0,
    /// The spawn daemon. Holds the CapSpawn capability and enforces the process type whitelist.
    Spawnd = 1,
    /// The audit daemon. Holds a read-only audit capability. Cannot write to the audit log.
    Auditd = 2,
    /// A device server. One server per hardware device (reserved for Phase 8).
    DeviceServer = 3,
    /// A network stack server. Isolated userspace network process (reserved for Phase 9).
    NetworkServer = 4,
}

/// Error returned when spawnd refuses to spawn a process.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum SpawnError {
    /// The requested process type is not in spawnd's compile-time whitelist.
    ProcessTypeNotPermitted,
}

/// Syscall number for the sys_process_exit system call.
///
/// Called by a server process to yield all capabilities and terminate.
/// After this call returns, the process is permanently gone from the system.
pub const SYSCALL_NUMBER_PROCESS_EXIT: u64 = 7;

/// Syscall number for the sys_audit_read system call.
///
/// Called by auditd to read audit log entries. Requires the AuditRead capability.
/// The kernel enforces read-only semantics: this syscall cannot write to the audit log.
pub const SYSCALL_NUMBER_AUDIT_READ: u64 = 8;

/// Virtual address where the kernel maps server binary code segments.
///
/// Server ELF PT_LOAD segments with executable permission are placed at this base.
/// All Brainix servers are position-dependent static binaries loaded at this address.
pub const SERVER_CODE_BASE_VIRTUAL_ADDRESS: u64 = 0x0000_0000_0040_0000;

/// Virtual address of the top of the server process stack.
///
/// The stack grows downward from this address. The kernel maps
/// SERVER_STACK_SIZE_IN_PAGES pages below this address for the initial stack.
pub const SERVER_STACK_TOP_VIRTUAL_ADDRESS: u64 = 0x0000_0000_0080_0000;

/// Number of pages allocated for the initial server process stack (64 KiB).
pub const SERVER_STACK_SIZE_IN_PAGES: usize = 16;

/// Virtual address of the stack guard page.
///
/// One page immediately below the bottom of the mapped stack region.
/// This page is mapped as non-present so that stack overflow generates a
/// page fault rather than silently corrupting adjacent memory.
pub const SERVER_STACK_GUARD_PAGE_VIRTUAL_ADDRESS: u64 = 0x0000_0000_007E_F000;
