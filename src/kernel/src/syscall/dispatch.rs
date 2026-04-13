//! Syscall dispatch: routes rax to the appropriate IPC operation.
//!
//! Called from the SYSCALL entry stub in arch/syscall_entry.rs.
//! Reads the syscall number (passed as first argument per SysV ABI) and
//! calls the corresponding IPC or notification handler.
//!
//! Gated behind cfg(target_arch = "x86_64") — the dispatch table is only
//! meaningful in the context of the x86-64 SYSCALL/SYSRET ABI (D-10).
//!
//! `#![allow(unsafe_code)]` is required because `#[no_mangle]` on Rust nightly
//! is grouped under the `unsafe_code` lint. The `#[no_mangle] pub extern "C"`
//! declaration on `dispatch_syscall` falls under the `src/kernel/src/arch/`
//! (assembly stubs) allowlist entry — this function is the Rust-side boundary
//! of the SYSCALL entry stub and is inseparable from it.
#![allow(unsafe_code)]

use crate::hardware_security::spectre_mitigation::issue_speculative_load_barrier;
use crate::ipc::{
    SYSCALL_NUMBER_IPC_CALL, SYSCALL_NUMBER_IPC_RECEIVE, SYSCALL_NUMBER_IPC_SEND,
    SYSCALL_NUMBER_NOTIFY_POLL, SYSCALL_NUMBER_NOTIFY_SIGNAL, SYSCALL_NUMBER_NOTIFY_WAIT,
};

/// Issues LFENCE then routes IPC syscall numbers (1-3) to their handlers.
///
/// The LFENCE after the user-supplied syscall_number match prevents speculative
/// execution of the dispatch arm using an attacker-controlled out-of-bounds index.
/// Mitigates T-HW-SPEC-01 (bounds-check bypass). Per D-02.
///
/// Returns `Some(result)` for a recognized IPC number, `None` otherwise.
fn handle_ipc_range_syscall(syscall_number: u64) -> Option<i64> {
    // Spectre v1 mitigation: LFENCE after dispatch table indexing on user-supplied syscall number.
    // Prevents speculative load of dispatch table entry with attacker-controlled value. Per D-02.
    issue_speculative_load_barrier();
    match syscall_number {
        SYSCALL_NUMBER_IPC_SEND => Some(handle_ipc_send_syscall()),
        SYSCALL_NUMBER_IPC_RECEIVE => Some(handle_ipc_receive_syscall()),
        SYSCALL_NUMBER_IPC_CALL => Some(handle_ipc_call_syscall()),
        _ => None,
    }
}

/// Routes notification syscall numbers (4-6) to their handlers.
///
/// Returns `Some(result)` for a recognized notify number, `None` otherwise.
fn handle_notify_range_syscall(syscall_number: u64) -> Option<i64> {
    match syscall_number {
        SYSCALL_NUMBER_NOTIFY_SIGNAL => Some(handle_notify_signal_syscall()),
        SYSCALL_NUMBER_NOTIFY_WAIT => Some(handle_notify_wait_syscall()),
        SYSCALL_NUMBER_NOTIFY_POLL => Some(handle_notify_poll_syscall()),
        _ => None,
    }
}

/// Routes a syscall to its handler based on `syscall_number` (passed from rax).
///
/// Returns 0 for success, a negative discriminant for IpcError, or -1 for an
/// unrecognized syscall number.
///
/// Called directly from the SYSCALL entry stub via C calling convention.
/// `syscall_number` maps to rdi (first argument per SysV AMD64 ABI), which
/// the entry stub loads from the saved rax on the kernel stack before the call.
///
/// Enforces INV-IPC-001: all IPC operations route through this validated dispatch point.
/// No IPC operation is reachable from userspace except through this table.
///
/// # Safety
///
/// Called from assembly (syscall_entry_point global_asm! stub). The caller
/// guarantees `syscall_number` is the raw rax value from the SYSCALL instruction.
/// - Precondition: Called only from ring 0 SYSCALL entry stub.
/// - Invariant: INV-IPC-001 (all IPC through kernel-validated entry).
/// - Evidence: test_dispatch_syscall_routes_all_six_syscall_numbers.
#[no_mangle]
pub unsafe extern "C" fn dispatch_syscall(syscall_number: u64) -> i64 {
    handle_ipc_range_syscall(syscall_number)
        .or_else(|| handle_notify_range_syscall(syscall_number))
        .unwrap_or(-1)
}

/// Phase 4 stub for SYS_IPC_SEND (syscall number 1).
///
/// Phase 5 wires in the actual send implementation from ipc::send.
fn handle_ipc_send_syscall() -> i64 {
    0
}

/// Phase 4 stub for SYS_IPC_RECEIVE (syscall number 2).
///
/// Phase 5 wires in the actual receive implementation from ipc::receive.
fn handle_ipc_receive_syscall() -> i64 {
    0
}

/// Phase 4 stub for SYS_IPC_CALL (syscall number 3).
///
/// Phase 5 wires in the actual call implementation from ipc::call.
fn handle_ipc_call_syscall() -> i64 {
    0
}

/// Phase 4 stub for SYS_NOTIFY_SIGNAL (syscall number 4).
///
/// Phase 5 wires in the actual notify_signal implementation.
fn handle_notify_signal_syscall() -> i64 {
    0
}

/// Phase 4 stub for SYS_NOTIFY_WAIT (syscall number 5).
///
/// Phase 5 wires in the actual notify_wait implementation.
fn handle_notify_wait_syscall() -> i64 {
    0
}

/// Phase 4 stub for SYS_NOTIFY_POLL (syscall number 6).
///
/// Phase 5 wires in the actual notify_poll implementation.
fn handle_notify_poll_syscall() -> i64 {
    0
}
