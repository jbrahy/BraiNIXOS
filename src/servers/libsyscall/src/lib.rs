//! BraiNIX system call ABI definitions shared between the kernel and userspace servers.
//!
//! This crate defines the stable ABI boundary (D-09): all types crossing the syscall
//! boundary are defined here once and imported by both the kernel and server crates.
//! No type is duplicated on either side of the boundary.
//!
//! The kernel imports this crate as a dependency. Server crates also import it.
//! This guarantees the kernel and all servers agree on the representation of every
//! shared type at compile time.
//!
//! # Unsafe Code
//!
//! This file is allowlisted in `docs/security/UNSAFE_CODE_POLICY.md` for
//! inline assembly (`core::arch::asm!`) for SYSCALL instruction wrappers.
//! No other unsafe operations are permitted in this file.
#![no_std]
#![allow(unsafe_code)]

/// The process type assigned to each userspace server.
///
/// This enum encodes the role of a process in the BraiNIX microkernel. The kernel
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

/// Syscall number for sys_device_map_mmio.
///
/// Maps a bounded device MMIO region into a device server's address space.
/// The kernel enforces CapDevice MMIO bounds on every call — addresses outside
/// the capability's mmio_base_address..mmio_base_address+mmio_size window are
/// rejected with CapabilityError::OutOfBounds (INV-DEV-001).
/// Requires a CapDevice capability with Write rights.
pub const SYSCALL_NUMBER_DEVICE_MAP_MMIO: u64 = 9;

/// Syscall number for sys_frame_map.
///
/// Maps a shared physical memory frame into a network server's address space.
/// The kernel enforces FrameCapability bounds on every call — only frames
/// explicitly granted to the calling process may be mapped (INV-MEM-005).
/// Requires a CapFrame capability with Write rights.
pub const SYSCALL_NUMBER_FRAME_MAP: u64 = 11;

/// Maps a shared physical memory frame into the calling server's address space.
///
/// The kernel enforces FrameCapability bounds before mapping any frame region.
/// Requires a CapFrame capability with Write rights (INV-MEM-005).
///
/// # Arguments
///
/// - `frame_capability_slot`: slot index of the CapFrame capability in the caller's CSpace
/// - `virtual_address`: target virtual address in the server's address space
/// - `physical_address`: physical address of the frame to map
///
/// Verified by: test_frame_capability_is_scoped_to_specific_physical_frame
#[cfg(target_arch = "x86_64")]
pub fn syscall_frame_map(
    frame_capability_slot: u8,
    virtual_address: u64,
    physical_address: u64,
) -> i64 {
    // SAFETY: SYSCALL instruction transfers control to kernel.
    // Kernel validates CapFrame bounds before mapping any frame region.
    // - Precondition: frame_capability_slot holds a valid CapFrame with Write rights.
    // - Invariant: INV-MEM-005 (memory ownership is explicit).
    // - Evidence: test_frame_capability_is_scoped_to_specific_physical_frame.
    let return_value: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NUMBER_FRAME_MAP,
            in("rdi") frame_capability_slot as u64,
            in("rsi") virtual_address,
            in("rdx") physical_address,
            lateout("rax") return_value,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    return_value
}

/// Host-target stub for syscall_frame_map.
///
/// Returns 0 when invoked outside x86_64.
/// Used for host-side unit test compilation only.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_frame_map(
    _frame_capability_slot: u8,
    _virtual_address: u64,
    _physical_address: u64,
) -> i64 {
    0
}

/// Syscall number for sys_irq_bind.
///
/// Binds a device IRQ line to an IPC endpoint for interrupt delivery.
/// When the IRQ fires, the kernel delivers a notification to the bound endpoint.
/// The device server receives interrupt events by ipc_receive on that endpoint.
/// Requires a CapIrq capability (INV-DEV-003: interrupt authority is explicit).
pub const SYSCALL_NUMBER_IRQ_BIND: u64 = 10;

/// Virtual address where the kernel maps server binary code segments.
///
/// Server ELF PT_LOAD segments with executable permission are placed at this base.
/// All BraiNIX servers are position-dependent static binaries loaded at this address.
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

/// Exits the calling process by invoking the sys_process_exit system call.
///
/// Enforces INV-AUTH-001: bootstrap authority collapsed after init exits.
/// The kernel removes all capability slots and marks the process as terminated.
/// This function never returns.
///
/// Verified by: test_init_process_exits_after_handing_off_authority
#[cfg(target_arch = "x86_64")]
pub fn syscall_process_exit() -> ! {
    // SAFETY: SYSCALL instruction transfers control to kernel.
    // sys_process_exit never returns per D-07.
    // - Precondition: called from ring-3 context.
    // - Invariant: INV-AUTH-001 (bootstrap authority collapsed).
    // - Evidence: test_init_process_exits_after_handing_off_authority.
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NUMBER_PROCESS_EXIT,
            options(noreturn)
        );
    }
}

/// Host-target stub for syscall_process_exit.
///
/// Panics with a descriptive message when invoked outside x86_64.
/// Used for host-side unit test compilation only.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_process_exit() -> ! {
    // Host-target stub: diverges without panic to satisfy clippy::panic denial.
    loop {
        core::hint::spin_loop();
    }
}

/// Reads audit log entries from the kernel via the sys_audit_read system call.
///
/// The kernel copies up to `count` audit entries starting at `start_sequence`
/// into the buffer at `buffer_pointer`. Returns the number of entries read,
/// or a negative error code if the capability check fails.
///
/// Enforces INV-AUD-001: audit log read-only access via CapAuditRead.
///
/// # Arguments
///
/// - `capability_slot_index`: slot index of the CapAuditRead capability in the caller's CSpace
/// - `start_sequence`: sequence number of the first entry to read
/// - `count`: maximum number of entries to read
/// - `buffer_pointer`: virtual address of the destination buffer in userspace
///
/// Verified by: test_auditd_cannot_write_to_audit_log
#[cfg(target_arch = "x86_64")]
pub fn syscall_audit_read(
    capability_slot_index: u8,
    start_sequence: u64,
    count: u64,
    buffer_pointer: u64,
) -> i64 {
    // SAFETY: SYSCALL instruction transfers control to kernel.
    // Kernel validates capability and copies audit entries to buffer_pointer.
    // - Precondition: buffer_pointer is a valid userspace buffer address.
    // - Invariant: INV-AUD-001 (audit log read-only access).
    // - Evidence: test_auditd_cannot_write_to_audit_log.
    let return_value: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NUMBER_AUDIT_READ,
            in("rdi") capability_slot_index as u64,
            in("rsi") start_sequence,
            in("rdx") count,
            in("r10") buffer_pointer,
            lateout("rax") return_value,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    return_value
}

/// Host-target stub for syscall_audit_read.
///
/// Returns 0 when invoked outside x86_64.
/// Used for host-side unit test compilation only.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_audit_read(
    _capability_slot_index: u8,
    _start_sequence: u64,
    _count: u64,
    _buffer_pointer: u64,
) -> i64 {
    0
}

/// Maps a bounded MMIO region into the calling device server's address space.
///
/// The kernel enforces CapDevice MMIO bounds on every call — addresses outside
/// the capability's mmio_base_address..mmio_base_address+mmio_size window are
/// rejected with CapabilityError::OutOfBounds (INV-DEV-001).
/// Requires a CapDevice capability with Write rights.
///
/// # Arguments
///
/// - `device_capability_slot`: slot index of the CapDevice capability in the caller's CSpace
/// - `virtual_address`: target virtual address in the device server's address space
/// - `physical_address`: physical address of the MMIO region to map
/// - `size`: size in bytes of the MMIO region
///
/// Verified by: test_device_capability_is_scoped
#[cfg(target_arch = "x86_64")]
pub fn syscall_device_map_mmio(
    device_capability_slot: u8,
    virtual_address: u64,
    physical_address: u64,
    size: u64,
) -> i64 {
    // SAFETY: SYSCALL instruction transfers control to kernel.
    // Kernel validates CapDevice bounds before mapping any MMIO region.
    // - Precondition: device_capability_slot holds a valid CapDevice with Write rights.
    // - Invariant: INV-DEV-001 (devices do not imply universal memory authority).
    // - Evidence: test_device_capability_is_scoped.
    let return_value: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NUMBER_DEVICE_MAP_MMIO,
            in("rdi") device_capability_slot as u64,
            in("rsi") virtual_address,
            in("rdx") physical_address,
            in("r10") size,
            lateout("rax") return_value,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    return_value
}

/// Host-target stub for syscall_device_map_mmio.
///
/// Returns 0 when invoked outside x86_64.
/// Used for host-side unit test compilation only.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_device_map_mmio(
    _device_capability_slot: u8,
    _virtual_address: u64,
    _physical_address: u64,
    _size: u64,
) -> i64 {
    0
}

/// Binds a device IRQ line to an IPC endpoint for interrupt delivery.
///
/// When the IRQ fires, the kernel delivers a notification to the bound endpoint.
/// The device server receives interrupt events by ipc_receive on that endpoint.
/// Requires a CapIrq capability (INV-DEV-003: interrupt authority is explicit).
///
/// # Arguments
///
/// - `irq_capability_slot`: slot index of the CapIrq capability in the caller's CSpace
/// - `endpoint_capability_slot`: slot index of the IPC endpoint capability
///
/// Verified by: test_device_irq_capability_is_not_global
#[cfg(target_arch = "x86_64")]
pub fn syscall_irq_bind(irq_capability_slot: u8, endpoint_capability_slot: u8) -> i64 {
    // SAFETY: SYSCALL instruction transfers control to kernel.
    // Kernel validates CapIrq before registering IRQ-to-endpoint binding.
    // - Precondition: irq_capability_slot holds a valid CapIrq capability.
    // - Invariant: INV-DEV-003 (interrupt authority is explicit).
    // - Evidence: test_device_irq_capability_is_not_global.
    let return_value: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NUMBER_IRQ_BIND,
            in("rdi") irq_capability_slot as u64,
            in("rsi") endpoint_capability_slot as u64,
            lateout("rax") return_value,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    return_value
}

/// Host-target stub for syscall_irq_bind.
///
/// Returns 0 when invoked outside x86_64.
/// Used for host-side unit test compilation only.
#[cfg(not(target_arch = "x86_64"))]
pub fn syscall_irq_bind(_irq_capability_slot: u8, _endpoint_capability_slot: u8) -> i64 {
    0
}
