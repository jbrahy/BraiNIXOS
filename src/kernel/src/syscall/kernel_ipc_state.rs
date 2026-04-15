//! Global kernel IPC state singletons accessed from the SYSCALL dispatch path.
//!
//! Each global is a separate `static mut` to allow simultaneous `&mut` borrows (D-02).
//! Single-core system prevents TOCTOU (T-10-03-02).
//! Falls under `src/kernel/src/syscall/kernel_ipc_state.rs` allowlist entry
//! in `docs/security/UNSAFE_CODE_POLICY.md`.
#![allow(unsafe_code)]

use core::mem::MaybeUninit;

use crate::ipc::endpoint::EndpointPool;
use crate::ipc::wait_for_graph::WaitForGraph;
use crate::ipc::MAXIMUM_THREADS;
use crate::process::process_table::{initialize_process_table_entries_in_place, ProcessTable};
use crate::thread::Thread;

/// Kernel-owned endpoint pool. Initialized at boot via `initialize_kernel_endpoint_pool`.
static mut KERNEL_ENDPOINT_POOL: MaybeUninit<EndpointPool> = MaybeUninit::uninit();

/// Kernel-owned wait-for graph for IPC deadlock detection (INV-IPC-004).
static mut KERNEL_WAIT_FOR_GRAPH: WaitForGraph = WaitForGraph::new();

/// Kernel-owned thread pool. Entries written by `create_server_process` at boot (D-03).
static mut KERNEL_THREAD_POOL: [Thread; MAXIMUM_THREADS] = [Thread::new(); MAXIMUM_THREADS];

/// Kernel-owned process table mapping ThreadIdentifier to CapabilitySpace.
static mut KERNEL_PROCESS_TABLE: MaybeUninit<ProcessTable> = MaybeUninit::uninit();

/// Initializes the kernel endpoint pool. Must be called once at boot.
///
/// # Safety
///
/// Must be called exactly once from the boot sequence before any IPC dispatch.
/// Precondition: single-core boot, no concurrent access.
/// Invariant: INV-IPC-001 (endpoint pool ready before IPC dispatch).
pub unsafe fn initialize_kernel_endpoint_pool() {
    let pool_pointer = core::ptr::addr_of_mut!(KERNEL_ENDPOINT_POOL);
    (*pool_pointer).write(EndpointPool::new());
}

/// Initializes the kernel process table in-place without a stack-allocated temporary.
///
/// Writes None into each entry directly via raw pointer to avoid constructing
/// a ~320 KiB ProcessTable on the stack (which overflows in test environments).
///
/// # Safety
///
/// Must be called exactly once from the boot sequence before any IPC dispatch.
/// Precondition: single-core boot, no concurrent access.
/// Invariant: INV-AUTH-001 (process table ready for CSpace insertion).
pub unsafe fn initialize_kernel_process_table() {
    let table_pointer = core::ptr::addr_of_mut!(KERNEL_PROCESS_TABLE);
    let raw_pointer = (*table_pointer).as_mut_ptr();
    initialize_process_table_entries_in_place(raw_pointer);
}

/// Returns a mutable reference to the kernel endpoint pool.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path. No concurrent access.
/// Precondition: `initialize_kernel_endpoint_pool` was called at boot.
/// Invariant: INV-IPC-001.
pub unsafe fn kernel_endpoint_pool_mut() -> &'static mut EndpointPool {
    let pool_pointer = core::ptr::addr_of_mut!(KERNEL_ENDPOINT_POOL);
    (*pool_pointer).assume_init_mut()
}

/// Returns a mutable reference to the kernel wait-for graph.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Invariant: INV-IPC-004 (deadlock detection).
pub unsafe fn kernel_wait_for_graph_mut() -> &'static mut WaitForGraph {
    &mut *core::ptr::addr_of_mut!(KERNEL_WAIT_FOR_GRAPH)
}

/// Returns a mutable reference to the Thread at `thread_index`.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Precondition: `thread_index < MAXIMUM_THREADS`.
/// Invariant: INV-AUTH-005 (bounds check required before call).
pub unsafe fn kernel_thread_at_mut(thread_index: usize) -> &'static mut Thread {
    let pool_pointer = core::ptr::addr_of_mut!(KERNEL_THREAD_POOL);
    &mut (*pool_pointer)[thread_index]
}

/// Returns a mutable reference to the kernel process table.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Precondition: `initialize_kernel_process_table` was called at boot.
/// Invariant: INV-AUTH-001.
pub unsafe fn kernel_process_table_mut() -> &'static mut ProcessTable {
    let table_pointer = core::ptr::addr_of_mut!(KERNEL_PROCESS_TABLE);
    (*table_pointer).assume_init_mut()
}
