//! IPC dispatch handler functions that wire SYSCALL argument globals to the real
//! ipc_send, ipc_receive, and ipc_call functions.
//!
//! Enforces INV-IPC-001: all IPC is explicit and kernel-mediated. Each handler reads
//! arguments from AtomicU64 globals (D-01), looks up the caller's CSpace from
//! KERNEL_PROCESS_TABLE, resolves the endpoint_index from CSlot.object_pointer, and
//! delegates to the real IPC function.
#![allow(unsafe_code)]

use core::sync::atomic::Ordering;

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::call::ipc_call;
use crate::ipc::receive::ipc_receive;
use crate::ipc::send::ipc_send;
use crate::ipc::{IpcError, IpcMessage, CAPABILITY_TRANSFER_NONE_SENTINEL};

use super::kernel_ipc_state;
use super::kernel_syscall_registers::{
    KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE, KERNEL_SYSCALL_CAP_SLOT_VALUE,
    KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE,
    KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE,
    KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE,
};

// --- IpcError encoding ---

/// Encodes an IpcError as a negative i64 return code per D-05.
///
/// Timeout(0) -> -1, WouldDeadlock(1) -> -2, EndpointRevoked(2) -> -3, etc.
/// The negation and subtraction are intentional: discriminants are small positive integers.
#[allow(clippy::arithmetic_side_effects)]
fn encode_ipc_error_as_return_code(error: IpcError) -> i64 {
    -(error as i64) - 1
}

/// Encodes a send/call Result as a syscall return code.
fn encode_ipc_result_send(result: Result<(), IpcError>) -> i64 {
    match result {
        Ok(()) => 0,
        Err(error) => encode_ipc_error_as_return_code(error),
    }
}

/// Encodes a receive Result as a syscall return code.
fn encode_ipc_result_receive(result: Result<IpcMessage, IpcError>) -> i64 {
    match result {
        Ok(_) => 0,
        Err(error) => encode_ipc_error_as_return_code(error),
    }
}

// --- Syscall register loaders ---

fn load_endpoint_slot_index() -> u64 {
    KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE.load(Ordering::Relaxed)
}

fn load_capability_slot_index() -> u64 {
    KERNEL_SYSCALL_CAP_SLOT_VALUE.load(Ordering::Relaxed)
}

fn load_timeout_ticks() -> u64 {
    KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE.load(Ordering::Relaxed)
}

fn load_message_register_zero() -> u64 {
    KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.load(Ordering::Relaxed)
}

fn load_message_register_one() -> u64 {
    KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE.load(Ordering::Relaxed)
}

fn load_message_register_two() -> u64 {
    KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE.load(Ordering::Relaxed)
}

fn load_capability_register() -> u64 {
    KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE.load(Ordering::Relaxed)
}

// --- IpcMessage construction ---

/// Constructs an IpcMessage from syscall argument globals.
///
/// register_three is 0: r11 is clobbered by SYSCALL with RFLAGS.
fn build_ipc_message_from_syscall_registers() -> IpcMessage {
    IpcMessage {
        register_zero: load_message_register_zero(),
        register_one: load_message_register_one(),
        register_two: load_message_register_two(),
        register_three: 0,
        badge: 0,
    }
}

// --- Endpoint index resolution ---

/// Maps a CapabilityError to IpcError::EndpointRevoked for dispatch use.
fn map_capability_error_to_ipc_error(_error: CapabilityError) -> IpcError {
    IpcError::EndpointRevoked
}

/// Resolves the endpoint pool index from a CSlot's object_pointer.
///
/// Enforces INV-AUTH-002: capability type checked at lookup_slot (Valid state required).
fn resolve_endpoint_index_from_capability_space(
    capability_space: &CapabilitySpace,
    endpoint_slot_index: u8,
) -> Result<usize, IpcError> {
    let slot = capability_space
        .lookup_slot(endpoint_slot_index)
        .map_err(map_capability_error_to_ipc_error)?;
    Ok(slot.object_pointer as usize)
}

// --- Argument bundles ---

struct IpcSendArguments {
    endpoint_slot_index: u8,
    capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    timeout_ticks: u64,
}

fn load_ipc_send_arguments() -> IpcSendArguments {
    IpcSendArguments {
        endpoint_slot_index: load_endpoint_slot_index() as u8,
        capability_slot_index: load_capability_slot_index() as u8,
        receiver_capability_destination_slot: load_capability_register() as u8,
        timeout_ticks: load_timeout_ticks(),
    }
}

struct IpcReceiveArguments {
    endpoint_slot_index: u8,
    receiver_capability_destination_slot: u8,
}

fn load_ipc_receive_arguments() -> IpcReceiveArguments {
    IpcReceiveArguments {
        endpoint_slot_index: load_endpoint_slot_index() as u8,
        receiver_capability_destination_slot: load_capability_register() as u8,
    }
}

struct IpcCallArguments {
    endpoint_slot_index: u8,
    capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    timeout_ticks: u64,
}

fn load_ipc_call_arguments() -> IpcCallArguments {
    IpcCallArguments {
        endpoint_slot_index: load_endpoint_slot_index() as u8,
        capability_slot_index: load_capability_slot_index() as u8,
        receiver_capability_destination_slot: load_capability_register() as u8,
        timeout_ticks: load_timeout_ticks(),
    }
}

// --- dispatch_ipc_send ---

/// Dispatches SYS_IPC_SEND by reading globals and calling ipc_send.
///
/// Enforces INV-IPC-001: IPC is explicit and kernel-mediated.
/// Enforces INV-AUTH-002: endpoint resolved via CSpace capability lookup.
pub fn dispatch_ipc_send(thread_identifier: u32) -> i64 {
    let arguments = load_ipc_send_arguments();
    let message = build_ipc_message_from_syscall_registers();
    // SAFETY: Single-core dispatch. Globals initialized at boot. INV-IPC-001.
    let result = unsafe { perform_ipc_send(thread_identifier, &message, &arguments) };
    encode_ipc_result_send(result)
}

/// Acquires kernel state and calls ipc_send.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table called.
/// Invariant: INV-IPC-001 (kernel-mediated IPC).
/// Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn perform_ipc_send(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcSendArguments,
) -> Result<(), IpcError> {
    let endpoint_pool = kernel_ipc_state::kernel_endpoint_pool_mut();
    let process_table = kernel_ipc_state::kernel_process_table_mut();
    let caller_cspace = process_table
        .lookup_entry_mut(thread_identifier)
        .ok_or(IpcError::EndpointRevoked)?;
    let endpoint_index =
        resolve_endpoint_index_from_capability_space(caller_cspace, arguments.endpoint_slot_index)?;
    call_ipc_send(
        thread_identifier,
        message,
        arguments,
        endpoint_index,
        endpoint_pool,
        caller_cspace,
    )
}

/// Calls ipc_send with all resolved parameters.
///
/// # Safety
///
/// Precondition: thread_identifier < MAXIMUM_THREADS (checked before calling).
/// Invariant: INV-IPC-001.
unsafe fn call_ipc_send(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcSendArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    caller_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let sender_thread = kernel_ipc_state::kernel_thread_at_mut(thread_identifier as usize);
    ipc_send(
        thread_identifier,
        message,
        arguments.capability_slot_index,
        arguments.receiver_capability_destination_slot,
        endpoint_index,
        arguments.timeout_ticks,
        0,
        endpoint_pool,
        sender_thread,
        caller_cspace,
    )
}

// --- dispatch_ipc_receive ---

/// Dispatches SYS_IPC_RECEIVE by reading globals and calling ipc_receive.
///
/// Enforces INV-IPC-001: IPC is explicit and kernel-mediated.
/// Enforces INV-AUTH-002: endpoint resolved via CSpace capability lookup.
pub fn dispatch_ipc_receive(thread_identifier: u32) -> i64 {
    let arguments = load_ipc_receive_arguments();
    // SAFETY: Single-core dispatch. Globals initialized at boot. INV-IPC-001.
    let result = unsafe { perform_ipc_receive(thread_identifier, &arguments) };
    encode_ipc_result_receive(result)
}

/// Acquires kernel state and calls ipc_receive.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table called.
/// Invariant: INV-IPC-001 (kernel-mediated IPC).
/// Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn perform_ipc_receive(
    thread_identifier: u32,
    arguments: &IpcReceiveArguments,
) -> Result<IpcMessage, IpcError> {
    let endpoint_pool = kernel_ipc_state::kernel_endpoint_pool_mut();
    let process_table = kernel_ipc_state::kernel_process_table_mut();
    let receiver_cspace = process_table
        .lookup_entry_mut(thread_identifier)
        .ok_or(IpcError::EndpointRevoked)?;
    let endpoint_index = resolve_endpoint_index_from_capability_space(
        receiver_cspace,
        arguments.endpoint_slot_index,
    )?;
    call_ipc_receive(
        thread_identifier,
        arguments,
        endpoint_index,
        endpoint_pool,
        receiver_cspace,
    )
}

/// Calls ipc_receive with all resolved parameters.
///
/// # Safety
///
/// Precondition: thread_identifier < MAXIMUM_THREADS (checked before calling).
/// Invariant: INV-IPC-001.
unsafe fn call_ipc_receive(
    thread_identifier: u32,
    arguments: &IpcReceiveArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    receiver_cspace: &mut CapabilitySpace,
) -> Result<IpcMessage, IpcError> {
    let receiver_thread = kernel_ipc_state::kernel_thread_at_mut(thread_identifier as usize);
    ipc_receive(
        thread_identifier,
        arguments.receiver_capability_destination_slot,
        endpoint_index,
        endpoint_pool,
        receiver_thread,
        receiver_cspace,
        None,
        CAPABILITY_TRANSFER_NONE_SENTINEL,
        None,
        false,
        0,
    )
}

// --- dispatch_ipc_call ---

/// Dispatches SYS_IPC_CALL by reading globals and calling ipc_call.
///
/// Enforces INV-IPC-001: IPC is explicit and kernel-mediated.
/// Enforces INV-IPC-004: deadlock check runs inside ipc_call before blocking.
/// Enforces INV-AUTH-002: endpoint resolved via CSpace capability lookup.
pub fn dispatch_ipc_call(thread_identifier: u32) -> i64 {
    let arguments = load_ipc_call_arguments();
    let message = build_ipc_message_from_syscall_registers();
    // SAFETY: Single-core dispatch. Globals initialized at boot. INV-IPC-001, INV-IPC-004.
    let result = unsafe { perform_ipc_call(thread_identifier, &message, &arguments) };
    encode_ipc_result_send(result)
}

/// Acquires kernel state and calls ipc_call.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table called.
/// Invariant: INV-IPC-001 (kernel-mediated IPC), INV-IPC-004 (deadlock detection).
/// Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn perform_ipc_call(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcCallArguments,
) -> Result<(), IpcError> {
    let endpoint_pool = kernel_ipc_state::kernel_endpoint_pool_mut();
    let process_table = kernel_ipc_state::kernel_process_table_mut();
    let caller_cspace = process_table
        .lookup_entry_mut(thread_identifier)
        .ok_or(IpcError::EndpointRevoked)?;
    let endpoint_index =
        resolve_endpoint_index_from_capability_space(caller_cspace, arguments.endpoint_slot_index)?;
    call_ipc_call(
        thread_identifier,
        message,
        arguments,
        endpoint_index,
        endpoint_pool,
        caller_cspace,
    )
}

/// Calls ipc_call with all resolved parameters.
///
/// # Safety
///
/// Precondition: thread_identifier < MAXIMUM_THREADS (checked before calling).
/// Invariant: INV-IPC-001, INV-IPC-004.
unsafe fn call_ipc_call(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcCallArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    caller_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let caller_thread = kernel_ipc_state::kernel_thread_at_mut(thread_identifier as usize);
    let wait_for_graph = kernel_ipc_state::kernel_wait_for_graph_mut();
    ipc_call(
        thread_identifier,
        message,
        arguments.capability_slot_index,
        arguments.receiver_capability_destination_slot,
        endpoint_index,
        arguments.timeout_ticks,
        0,
        endpoint_pool,
        caller_thread,
        caller_cspace,
        wait_for_graph,
    )
}
