//! IPC receive operation: SYS_IPC_RECEIVE semantics (IPC_SPEC.md §4).
//!
//! A receiver blocks (queues on the endpoint) when no sender is waiting.
//! When a sender is already waiting, rendezvous occurs immediately.
//! If the sender was waiting via SYS_IPC_CALL, installs CapReply in server's CSpace.
//!
//! Enforces INV-IPC-001: receivers block until a matching sender arrives.
//! Enforces INV-AUTH-005: CapReply is kernel-created on SYS_IPC_RECEIVE rendezvous.

use crate::capability::capability_space::CapabilitySpace;
use crate::hardware_security::spectre_mitigation::issue_speculative_load_barrier;
use crate::ipc::cap_reply::install_cap_reply_in_server_cspace;
use crate::ipc::endpoint::{EndpointPool, ThreadIdentifier};
use crate::ipc::rendezvous::perform_rendezvous;
use crate::ipc::{IpcError, IpcMessage};
use crate::thread::{Thread, ThreadState};

/// Receives an IPC message from the endpoint, blocking until a sender arrives.
///
/// If a sender is already queued, rendezvous occurs immediately.
/// If no sender is present, enqueues receiver and sets thread state to Blocked.
/// If the sender was a CALL sender (is_call_sender), installs CapReply in server's CSpace.
///
/// Enforces INV-IPC-001: receiver blocks until rendezvous or timeout.
/// Enforces INV-AUTH-005: CapReply is kernel-created on IPC_CALL rendezvous.
/// Verified by: test_send_blocks_until_receiver_calls_receive (SC-01)
#[allow(clippy::too_many_arguments)]
pub fn ipc_receive(
    receiver_thread_index: u32,
    receiver_capability_destination_slot: u8,
    endpoint_index: usize,
    endpoint_pool: &mut EndpointPool,
    receiver_thread: &mut Thread,
    receiver_cspace: &mut CapabilitySpace,
    sender_message: Option<&IpcMessage>,
    sender_capability_slot_index: u8,
    sender_cspace: Option<&mut CapabilitySpace>,
    is_call_sender: bool,
    caller_thread_identifier: u32,
) -> Result<IpcMessage, IpcError> {
    let endpoint = endpoint_pool
        .endpoint_at_mut(endpoint_index)
        .ok_or(IpcError::EndpointRevoked)?;
    if endpoint.has_no_waiting_sender() {
        return handle_no_sender_present(receiver_thread_index, receiver_thread, endpoint);
    }
    let _sender_thread_index = endpoint.dequeue_sender().ok_or(IpcError::EndpointRevoked)?;
    let _ = endpoint;
    execute_receive_rendezvous(
        receiver_capability_destination_slot,
        endpoint_index,
        endpoint_pool,
        receiver_cspace,
        sender_message,
        sender_capability_slot_index,
        sender_cspace,
        is_call_sender,
        caller_thread_identifier,
    )
}

/// Handles the case where no sender is waiting — blocks the receiver.
fn handle_no_sender_present(
    receiver_thread_index: ThreadIdentifier,
    receiver_thread: &mut Thread,
    endpoint: &mut crate::ipc::endpoint::Endpoint,
) -> Result<IpcMessage, IpcError> {
    receiver_thread.thread_state = ThreadState::Blocked;
    endpoint.enqueue_receiver(receiver_thread_index)?;
    Ok(IpcMessage::default())
}

/// Executes the full rendezvous when a sender is available.
///
/// Retrieves the endpoint badge, performs rendezvous, and installs CapReply if needed.
#[allow(clippy::too_many_arguments)]
fn execute_receive_rendezvous(
    receiver_capability_destination_slot: u8,
    endpoint_index: usize,
    endpoint_pool: &mut EndpointPool,
    receiver_cspace: &mut CapabilitySpace,
    sender_message: Option<&IpcMessage>,
    sender_capability_slot_index: u8,
    sender_cspace: Option<&mut CapabilitySpace>,
    is_call_sender: bool,
    caller_thread_identifier: u32,
) -> Result<IpcMessage, IpcError> {
    let badge = read_endpoint_badge(endpoint_index, endpoint_pool);
    let delivered = perform_rendezvous_with_optional_sender(
        sender_message,
        sender_capability_slot_index,
        receiver_capability_destination_slot,
        sender_cspace,
        receiver_cspace,
        badge,
    )?;
    if is_call_sender {
        install_cap_reply_in_server_cspace(receiver_cspace, caller_thread_identifier)?;
    }
    Ok(delivered)
}

/// Returns the badge of the endpoint at `endpoint_index`.
///
/// Issues LFENCE before the endpoint array access to prevent Spectre v1
/// speculative overread of IPC buffer contents via user-controlled index.
/// Per D-02 (compile-time barrier on all identified speculative paths).
fn read_endpoint_badge(endpoint_index: usize, endpoint_pool: &mut EndpointPool) -> u64 {
    // Spectre v1 mitigation: LFENCE after IPC receive buffer length check.
    // Prevents speculative overread of IPC buffer contents. Per D-02.
    issue_speculative_load_barrier();
    endpoint_pool
        .endpoint_at_mut(endpoint_index)
        .map(|endpoint| endpoint.badge)
        .unwrap_or(0)
}

/// Performs rendezvous using either the provided sender cspace or a dummy.
fn perform_rendezvous_with_optional_sender(
    sender_message: Option<&IpcMessage>,
    sender_capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    sender_cspace: Option<&mut CapabilitySpace>,
    receiver_cspace: &mut CapabilitySpace,
    badge: u64,
) -> Result<IpcMessage, IpcError> {
    let default_message = IpcMessage::default();
    let message = sender_message.unwrap_or(&default_message);
    match sender_cspace {
        Some(cspace) => perform_rendezvous(
            message,
            sender_capability_slot_index,
            receiver_capability_destination_slot,
            cspace,
            receiver_cspace,
            badge,
        ),
        None => {
            let mut dummy_sender_cspace = CapabilitySpace::new();
            perform_rendezvous(
                message,
                sender_capability_slot_index,
                receiver_capability_destination_slot,
                &mut dummy_sender_cspace,
                receiver_cspace,
                badge,
            )
        }
    }
}
