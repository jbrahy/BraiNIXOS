//! IPC call operation: SYS_IPC_CALL semantics (IPC_SPEC.md §5).
//!
//! ipc_call atomically sends a message and blocks waiting for a reply via CapReply.
//! Before blocking, a WaitForGraph cycle check is performed — if a cycle would form,
//! WouldDeadlock is returned immediately without blocking (D-03, INV-IPC-004).
//!
//! Enforces INV-IPC-004: deadlock cycle detection before blocking (defense-in-depth).
//! Enforces INV-AUTH-005: CapReply is kernel-installed on the server's CSpace.

use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::endpoint::{EndpointPool, ThreadIdentifier};
use crate::ipc::send::ipc_send;
use crate::ipc::wait_for_graph::WaitForGraph;
use crate::ipc::{IpcError, IpcMessage};
use crate::thread::Thread;

/// Atomically sends a message and blocks waiting for a CapReply.
///
/// Performs a WaitForGraph cycle check before blocking. If a cycle would form,
/// returns WouldDeadlock immediately without enqueuing the caller.
///
/// Enforces INV-IPC-004: cycle check runs before blocking (D-03).
/// Verified by: integration_server_that_never_receives_does_not_hold_caller_indefinitely (SC-06)
pub fn ipc_call(
    caller_thread_index: u32,
    caller_message: &IpcMessage,
    caller_capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    endpoint_index: usize,
    timeout_ticks: u64,
    current_tick: u64,
    endpoint_pool: &mut EndpointPool,
    caller_thread: &mut Thread,
    caller_cspace: &mut CapabilitySpace,
    wait_for_graph: &mut WaitForGraph,
) -> Result<(), IpcError> {
    check_for_deadlock_before_blocking(caller_thread_index, endpoint_index, wait_for_graph)?;
    record_caller_wait_edge(caller_thread_index, endpoint_index, wait_for_graph);
    let send_result = ipc_send(
        caller_thread_index,
        caller_message,
        caller_capability_slot_index,
        receiver_capability_destination_slot,
        endpoint_index,
        timeout_ticks,
        current_tick,
        endpoint_pool,
        caller_thread,
        caller_cspace,
    );
    remove_caller_wait_edge_on_completion(caller_thread_index, wait_for_graph);
    send_result
}

/// Returns Err(WouldDeadlock) if recording this wait would form a cycle.
///
/// Enforces INV-IPC-004: cycle detection runs synchronously before blocking.
fn check_for_deadlock_before_blocking(
    caller_thread_index: ThreadIdentifier,
    endpoint_index: usize,
    wait_for_graph: &mut WaitForGraph,
) -> Result<(), IpcError> {
    let would_form_cycle = wait_for_graph.check_would_form_cycle(
        caller_thread_index,
        endpoint_index as u32,
    );
    if would_form_cycle { Err(IpcError::WouldDeadlock) } else { Ok(()) }
}

/// Records the caller's wait edge in the WaitForGraph before blocking.
fn record_caller_wait_edge(
    caller_thread_index: ThreadIdentifier,
    endpoint_index: usize,
    wait_for_graph: &mut WaitForGraph,
) {
    wait_for_graph.record_wait_edge(caller_thread_index, endpoint_index as u32);
}

/// Removes the caller's wait edge from the WaitForGraph after send completes or fails.
fn remove_caller_wait_edge_on_completion(
    caller_thread_index: ThreadIdentifier,
    wait_for_graph: &mut WaitForGraph,
) {
    wait_for_graph.remove_wait_edge(caller_thread_index);
}
