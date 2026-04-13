//! IPC subsystem integration tests — SC-01 through SC-06.
//!
//! All tests use direct function calls with stub thread state (D-12).
//! Deterministic tick injection: current_tick passed as parameter, never RDTSC.
//! Fixture helpers provide minimal two-thread state for each scenario.

use crate::capability::capability_rights;
use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::ipc::cap_reply::{consume_cap_reply_and_zero_slot, install_cap_reply_in_server_cspace};
use crate::ipc::endpoint::EndpointPool;
use crate::ipc::receive::ipc_receive;
use crate::ipc::send::{check_and_apply_send_timeout, ipc_send};
use crate::ipc::wait_for_graph::WaitForGraph;
use crate::ipc::{IpcError, IpcMessage, CAPABILITY_TRANSFER_NONE_SENTINEL};
use crate::thread::{Thread, ThreadState};

/// Returns a default IpcMessage with all registers set to known test values.
fn build_test_message() -> IpcMessage {
    IpcMessage {
        register_zero: 111,
        register_one: 222,
        register_two: 333,
        register_three: 444,
        badge: 0,
    }
}

/// Installs a capability slot with Read+Grant rights in the sender's CSpace at slot 1.
fn install_grant_capable_read_slot(sender_cspace: &mut CapabilitySpace) {
    let slot = sender_cspace.lookup_slot_mut(1);
    *slot = CapabilitySlot {
        state: CapabilitySlotState::Valid,
        capability_type: CapabilityType::Memory,
        rights_bitmask: capability_rights::READ | capability_rights::GRANT,
        object_pointer: 0xDEAD_BEEF,
        generation_counter: 1,
        derivation_parent_index: u32::MAX,
        use_count_remaining: None,
        expiry_tick: None,
    };
}

/// Installs a capability slot with Read-only rights in the sender's CSpace at slot 1.
///
/// No Grant right is present — used to test that transfer is blocked.
fn install_read_only_slot(sender_cspace: &mut CapabilitySpace) {
    let slot = sender_cspace.lookup_slot_mut(1);
    *slot = CapabilitySlot {
        state: CapabilitySlotState::Valid,
        capability_type: CapabilityType::Memory,
        rights_bitmask: capability_rights::READ,
        object_pointer: 0xDEAD_BEEF,
        generation_counter: 1,
        derivation_parent_index: u32::MAX,
        use_count_remaining: None,
        expiry_tick: None,
    };
}

/// SC-01 / INV-IPC-001
///
/// Sender calls ipc_send with no receiver waiting — queued and Blocked.
/// Then receiver calls ipc_receive — rendezvous occurs, message delivered.
#[test]
fn test_send_blocks_until_receiver_calls_receive() {
    let mut endpoint_pool = EndpointPool::new();
    let mut sender_thread = Thread::new();
    let mut receiver_thread = Thread::new();
    let mut sender_cspace = CapabilitySpace::new();
    let mut receiver_cspace = CapabilitySpace::new();
    let test_message = build_test_message();

    ipc_send(
        0,
        &test_message,
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        0,
        0,
        100,
        0,
        &mut endpoint_pool,
        &mut sender_thread,
        &mut sender_cspace,
    )
    .unwrap();

    assert_eq!(sender_thread.thread_state, ThreadState::Blocked);

    let delivered = ipc_receive(
        1,
        0,
        0,
        &mut endpoint_pool,
        &mut receiver_thread,
        &mut receiver_cspace,
        Some(&test_message),
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        None,
        false,
        0,
    )
    .unwrap();

    assert_eq!(delivered.register_zero, 111);
    assert_eq!(delivered.register_one, 222);
    assert_eq!(delivered.register_two, 333);
    assert_eq!(delivered.register_three, 444);
}

/// SC-02 / INV-IPC-002 / INV-AUTH-003
///
/// Sender holds a cap with Read+Grant rights.
/// After rendezvous, receiver's destination slot has Read+Grant rights (same as sender).
/// Attempting transfer without Grant right fails with GrantRightNotHeld.
#[test]
fn test_transferred_capability_has_no_additional_rights() {
    use crate::ipc::rendezvous::perform_rendezvous;

    let mut sender_cspace = CapabilitySpace::new();
    let mut receiver_cspace = CapabilitySpace::new();
    install_grant_capable_read_slot(&mut sender_cspace);

    let message = IpcMessage::default();
    perform_rendezvous(&message, 1, 2, &mut sender_cspace, &mut receiver_cspace, 0).unwrap();

    let received_slot = receiver_cspace.lookup_slot_ref(2);
    assert!(!received_slot.is_null());
    let rights = received_slot.rights();
    assert!(rights.contains(capability_rights::READ));
    let has_write_right = rights.contains(capability_rights::WRITE);
    assert!(
        !has_write_right,
        "receiver must not gain Write right not held by sender"
    );

    let mut sender_cspace_no_grant = CapabilitySpace::new();
    let mut receiver_cspace_two = CapabilitySpace::new();
    install_read_only_slot(&mut sender_cspace_no_grant);
    let result = perform_rendezvous(
        &message,
        1,
        2,
        &mut sender_cspace_no_grant,
        &mut receiver_cspace_two,
        0,
    );
    assert_eq!(result, Err(IpcError::GrantRightNotHeld));
}

/// SC-03 / INV-IPC-003 / INV-SCHED-003
///
/// Sender calls ipc_send with timeout_ticks=10, current_tick=0 — queued Blocked.
/// check_and_apply_send_timeout at current_tick=10 fires timeout.
/// Sender thread_state returns to Ready; error is Timeout.
#[test]
fn test_ipc_timeout_unblocks_sender_with_timeout_error() {
    let mut endpoint_pool = EndpointPool::new();
    let mut sender_thread = Thread::new();
    let mut sender_cspace = CapabilitySpace::new();
    let test_message = build_test_message();

    ipc_send(
        0,
        &test_message,
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        0,
        0,
        10,
        0,
        &mut endpoint_pool,
        &mut sender_thread,
        &mut sender_cspace,
    )
    .unwrap();

    assert_eq!(sender_thread.thread_state, ThreadState::Blocked);
    assert_eq!(sender_thread.timeout_deadline_tick, 10);

    let timeout_result =
        check_and_apply_send_timeout(&mut sender_thread, 0, &mut endpoint_pool, 0, 10);

    assert_eq!(timeout_result, Some(IpcError::Timeout));
    assert_eq!(sender_thread.thread_state, ThreadState::Ready);
    assert_eq!(sender_thread.timeout_deadline_tick, 0);
}

/// SC-04 / INV-AUTH-006
///
/// CapReply is installed in server's CSpace at slot 255.
/// First consume returns Ok; slot is null after.
/// Second consume returns ReplyCapabilityAlreadyUsed.
#[test]
fn test_reply_capability_is_single_use() {
    let mut server_cspace = CapabilitySpace::new();

    install_cap_reply_in_server_cspace(&mut server_cspace, 0).unwrap();
    let reply_slot = server_cspace.lookup_slot_ref(255);
    assert!(
        !reply_slot.is_null(),
        "reply slot must be occupied after install"
    );

    let first_consume = consume_cap_reply_and_zero_slot(&mut server_cspace);
    assert_eq!(first_consume, Ok(()));
    let reply_slot_after = server_cspace.lookup_slot_ref(255);
    assert!(
        reply_slot_after.is_null(),
        "reply slot must be null after first consume"
    );

    let second_consume = consume_cap_reply_and_zero_slot(&mut server_cspace);
    assert_eq!(second_consume, Err(IpcError::ReplyCapabilityAlreadyUsed));
}

/// SC-05 / INV-IPC-002 / INV-AUTH-003
///
/// Prusti property in brainix-ipc-core covers this formally.
/// Unit-level evidence: rights monotonicity check returns error for amplification.
#[test]
fn property_ipc_cannot_increase_capability_rights() {
    use crate::ipc::rendezvous::perform_rendezvous;

    let mut sender_cspace = CapabilitySpace::new();
    let mut receiver_cspace = CapabilitySpace::new();
    install_read_only_slot(&mut sender_cspace);
    let message = IpcMessage::default();

    let result = perform_rendezvous(&message, 1, 2, &mut sender_cspace, &mut receiver_cspace, 0);
    assert_eq!(
        result,
        Err(IpcError::GrantRightNotHeld),
        "transfer without Grant right must be rejected — rights cannot be amplified"
    );
}

/// SC-06 / INV-IPC-003 / INV-SCHED-003
///
/// Caller calls ipc_send with timeout_ticks=5 — no server receives.
/// At current_tick=5 the timeout fires and caller is unblocked with Timeout error.
#[test]
fn integration_server_that_never_receives_does_not_hold_caller_indefinitely() {
    let mut endpoint_pool = EndpointPool::new();
    let mut caller_thread = Thread::new();
    let mut caller_cspace = CapabilitySpace::new();
    let test_message = build_test_message();

    ipc_send(
        0,
        &test_message,
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        0,
        0,
        5,
        0,
        &mut endpoint_pool,
        &mut caller_thread,
        &mut caller_cspace,
    )
    .unwrap();

    assert_eq!(caller_thread.thread_state, ThreadState::Blocked);

    let timeout_result =
        check_and_apply_send_timeout(&mut caller_thread, 0, &mut endpoint_pool, 0, 5);

    assert_eq!(timeout_result, Some(IpcError::Timeout));
    assert_eq!(
        caller_thread.thread_state,
        ThreadState::Ready,
        "caller must be unblocked after timeout — server cannot hold caller indefinitely"
    );
}

/// D-03 / INV-IPC-004 (defense-in-depth)
///
/// WaitForGraph iterative DFS detects a cycle — returns WouldDeadlock before blocking.
#[test]
fn test_cycle_detection_returns_would_deadlock() {
    use crate::ipc::call::ipc_call;

    let mut endpoint_pool = EndpointPool::new();
    let mut caller_thread = Thread::new();
    let mut caller_cspace = CapabilitySpace::new();
    let mut wait_for_graph = WaitForGraph::new();
    let test_message = build_test_message();

    wait_for_graph.record_wait_edge(1, 0);

    let result = ipc_call(
        1,
        &test_message,
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        0,
        0,
        100,
        0,
        &mut endpoint_pool,
        &mut caller_thread,
        &mut caller_cspace,
        &mut wait_for_graph,
    );

    assert_eq!(result, Err(IpcError::WouldDeadlock));
}
