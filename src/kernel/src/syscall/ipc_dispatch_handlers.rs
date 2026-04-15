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
use crate::capability::capability_type::CapabilityType;
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
///
/// The IpcMessage payload is intentionally discarded here. In Phase 11,
/// message data is conveyed to userspace through the receiver Thread's
/// register_save_area (written by ipc_receive before returning Ok), not
/// through this return code. The return code signals success (0) or
/// an IpcError discriminant only. Phase 12 will wire register_save_area
/// back into the SYSRET path so the values reach userspace registers.
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
/// Enforces INV-AUTH-002: capability must be Endpoint-typed. Any non-Endpoint
/// slot index (CapFrame, CapDevice, CapSpawn, etc.) returns EndpointRevoked,
/// preventing type confusion on the endpoint pool index.
fn resolve_endpoint_index_from_capability_space(
    capability_space: &CapabilitySpace,
    endpoint_slot_index: u8,
) -> Result<usize, IpcError> {
    let slot = capability_space
        .lookup_slot(endpoint_slot_index)
        .map_err(map_capability_error_to_ipc_error)?;
    if slot.capability_type() != CapabilityType::Endpoint {
        return Err(IpcError::EndpointRevoked);
    }
    Ok(slot.object_pointer as usize)
}

// --- Slot index validation ---

/// Validates that a u64 register value fits in u8 (slot indices are 0-255).
///
/// Returns EndpointRevoked if the value exceeds u8::MAX, preventing silent
/// truncation that could address a different slot than the caller named.
fn validate_slot_index_fits_u8(raw_value: u64) -> Result<u8, IpcError> {
    u8::try_from(raw_value).map_err(|_| IpcError::EndpointRevoked)
}

fn load_endpoint_slot_index_as_u8() -> Result<u8, IpcError> {
    validate_slot_index_fits_u8(load_endpoint_slot_index())
}

fn load_capability_slot_index_as_u8() -> Result<u8, IpcError> {
    validate_slot_index_fits_u8(load_capability_slot_index())
}

fn load_capability_register_as_u8() -> Result<u8, IpcError> {
    validate_slot_index_fits_u8(load_capability_register())
}

// --- Argument bundles ---

struct IpcSendArguments {
    endpoint_slot_index: u8,
    capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    timeout_ticks: u64,
}

fn load_ipc_send_arguments() -> Result<IpcSendArguments, IpcError> {
    Ok(IpcSendArguments {
        endpoint_slot_index: load_endpoint_slot_index_as_u8()?,
        capability_slot_index: load_capability_slot_index_as_u8()?,
        receiver_capability_destination_slot: load_capability_register_as_u8()?,
        timeout_ticks: load_timeout_ticks(),
    })
}

struct IpcReceiveArguments {
    endpoint_slot_index: u8,
    receiver_capability_destination_slot: u8,
}

fn load_ipc_receive_arguments() -> Result<IpcReceiveArguments, IpcError> {
    Ok(IpcReceiveArguments {
        endpoint_slot_index: load_endpoint_slot_index_as_u8()?,
        receiver_capability_destination_slot: load_capability_register_as_u8()?,
    })
}

struct IpcCallArguments {
    endpoint_slot_index: u8,
    capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    timeout_ticks: u64,
}

fn load_ipc_call_arguments() -> Result<IpcCallArguments, IpcError> {
    Ok(IpcCallArguments {
        endpoint_slot_index: load_endpoint_slot_index_as_u8()?,
        capability_slot_index: load_capability_slot_index_as_u8()?,
        receiver_capability_destination_slot: load_capability_register_as_u8()?,
        timeout_ticks: load_timeout_ticks(),
    })
}

// --- dispatch_ipc_send ---

/// Dispatches SYS_IPC_SEND by reading globals and calling ipc_send.
///
/// Enforces INV-IPC-001: IPC is explicit and kernel-mediated.
/// Enforces INV-AUTH-002: endpoint resolved via CSpace capability lookup.
pub fn dispatch_ipc_send(thread_identifier: u32) -> i64 {
    let arguments = match load_ipc_send_arguments() {
        Ok(arguments) => arguments,
        Err(error) => return encode_ipc_error_as_return_code(error),
    };
    let message = build_ipc_message_from_syscall_registers();
    // SAFETY: Called only from single-core SYSCALL dispatch path.
    // - Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table
    //   called at boot before any SYSCALL can reach this point (single-core, no TOCTOU).
    // - Invariant: INV-IPC-001 (kernel-mediated IPC), T-10-03-02 (single-core prevents TOCTOU).
    // - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
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

/// Resolves a mutable Thread reference for `thread_identifier`, or EndpointRevoked if OOB.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path.
/// - Precondition: Kernel thread pool initialized at boot before any SYSCALL can reach
///   this point. kernel_thread_at_mut performs the bounds check internally.
/// - Invariant: INV-AUTH-005 (bounds check performed inside kernel_thread_at_mut).
/// - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn resolve_thread_for_identifier(
    thread_identifier: u32,
) -> Result<&'static mut crate::thread::Thread, IpcError> {
    kernel_ipc_state::kernel_thread_at_mut(thread_identifier as usize)
        .ok_or(IpcError::EndpointRevoked)
}

/// Calls ipc_send with all resolved parameters.
///
/// # Safety
///
/// Called only from single-core SYSCALL dispatch path via perform_ipc_send.
/// - Precondition: Called from perform_ipc_send, which is called only from
///   single-core SYSCALL dispatch. kernel_thread_at_mut enforces bounds internally
///   (returns None -> Err on out-of-bounds — callers need not pre-check).
/// - Invariant: INV-IPC-001.
/// - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn call_ipc_send(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcSendArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    caller_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let sender_thread = resolve_thread_for_identifier(thread_identifier)?;
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
    let arguments = match load_ipc_receive_arguments() {
        Ok(arguments) => arguments,
        Err(error) => return encode_ipc_error_as_return_code(error),
    };
    // SAFETY: Called only from single-core SYSCALL dispatch path.
    // - Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table
    //   called at boot before any SYSCALL can reach this point (single-core, no TOCTOU).
    // - Invariant: INV-IPC-001 (kernel-mediated IPC), T-10-03-02 (single-core prevents TOCTOU).
    // - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
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
/// Called only from single-core SYSCALL dispatch path via perform_ipc_receive.
/// - Precondition: Called from perform_ipc_receive, which is called only from
///   single-core SYSCALL dispatch. kernel_thread_at_mut enforces bounds internally
///   (returns None -> Err on out-of-bounds — callers need not pre-check).
/// - Invariant: INV-IPC-001.
/// - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn call_ipc_receive(
    thread_identifier: u32,
    arguments: &IpcReceiveArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    receiver_cspace: &mut CapabilitySpace,
) -> Result<IpcMessage, IpcError> {
    let receiver_thread = resolve_thread_for_identifier(thread_identifier)?;
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
    let arguments = match load_ipc_call_arguments() {
        Ok(arguments) => arguments,
        Err(error) => return encode_ipc_error_as_return_code(error),
    };
    let message = build_ipc_message_from_syscall_registers();
    // SAFETY: Called only from single-core SYSCALL dispatch path.
    // - Precondition: initialize_kernel_endpoint_pool and initialize_kernel_process_table
    //   called at boot before any SYSCALL can reach this point (single-core, no TOCTOU).
    // - Invariant: INV-IPC-001 (kernel-mediated IPC), INV-IPC-004 (deadlock detection),
    //   T-10-03-02 (single-core prevents TOCTOU).
    // - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
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
/// Called only from single-core SYSCALL dispatch path via perform_ipc_call.
/// - Precondition: Called from perform_ipc_call, which is called only from
///   single-core SYSCALL dispatch. kernel_thread_at_mut enforces bounds internally
///   (returns None -> Err on out-of-bounds — callers need not pre-check).
/// - Invariant: INV-IPC-001, INV-IPC-004.
/// - Evidence: integration_ipc_round_trip_through_syscall_dispatch_layer.
unsafe fn call_ipc_call(
    thread_identifier: u32,
    message: &IpcMessage,
    arguments: &IpcCallArguments,
    endpoint_index: usize,
    endpoint_pool: &mut crate::ipc::endpoint::EndpointPool,
    caller_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let caller_thread = resolve_thread_for_identifier(thread_identifier)?;
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

// These tests modify kernel IPC globals (static mut). Run with --test-threads=1.
#[cfg(test)]
mod tests {
    use core::sync::atomic::Ordering;

    use super::*;
    use crate::capability::capability_rights;
    use crate::capability::capability_slot::CapabilitySlotState;
    use crate::capability::capability_space::CapabilitySpace;
    use crate::capability::capability_type::CapabilityType;
    use crate::ipc::receive::ipc_receive;
    use crate::ipc::CAPABILITY_TRANSFER_NONE_SENTINEL;
    use crate::syscall::kernel_ipc_state;
    use crate::syscall::kernel_syscall_registers::{
        KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE, KERNEL_SYSCALL_CAP_SLOT_VALUE,
        KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE,
        KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE,
        KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE,
    };

    /// Stores IPC send argument values into the AtomicU64 syscall globals.
    fn set_ipc_send_globals(
        endpoint_slot: u64,
        cap_slot: u64,
        timeout: u64,
        mr0: u64,
        mr1: u64,
        mr2: u64,
        cap_reg: u64,
    ) {
        KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE.store(endpoint_slot, Ordering::Relaxed);
        KERNEL_SYSCALL_CAP_SLOT_VALUE.store(cap_slot, Ordering::Relaxed);
        KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE.store(timeout, Ordering::Relaxed);
        KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.store(mr0, Ordering::Relaxed);
        KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE.store(mr1, Ordering::Relaxed);
        KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE.store(mr2, Ordering::Relaxed);
        KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE.store(cap_reg, Ordering::Relaxed);
    }

    /// Initializes the kernel endpoint pool and process table globals.
    ///
    /// # Safety
    ///
    /// Must be called at the start of each test that exercises dispatch functions.
    /// Single-threaded test execution (--test-threads=1) ensures no concurrent access.
    unsafe fn initialize_test_kernel_state() {
        kernel_ipc_state::initialize_kernel_endpoint_pool();
        kernel_ipc_state::initialize_kernel_process_table();
    }

    /// Builds a CapabilitySpace with a Valid Endpoint capability at slot 0.
    ///
    /// The object_pointer is set to `endpoint_index` so dispatch can resolve it.
    fn build_cspace_with_endpoint_capability(endpoint_index: u64) -> CapabilitySpace {
        let mut capability_space = CapabilitySpace::new();
        let slot = capability_space.lookup_slot_mut(0);
        slot.state = CapabilitySlotState::Valid;
        slot.capability_type = CapabilityType::Endpoint;
        slot.rights_bitmask = capability_rights::GRANT;
        slot.object_pointer = endpoint_index;
        capability_space
    }

    /// Inserts a CSpace with an Endpoint capability at slot 0 into the process table.
    ///
    /// # Safety
    ///
    /// Requires initialize_test_kernel_state to have been called first.
    unsafe fn register_thread_with_endpoint_capability(
        thread_identifier: u32,
        endpoint_index: u64,
    ) {
        let capability_space = build_cspace_with_endpoint_capability(endpoint_index);
        let process_table = kernel_ipc_state::kernel_process_table_mut();
        process_table
            .insert_entry(thread_identifier, capability_space)
            .expect("register_thread_with_endpoint_capability: insert must succeed");
    }

    /// Enqueues thread 1 as a receiver on endpoint 0 by calling ipc_receive directly.
    ///
    /// When no sender is present, ipc_receive blocks the receiver and returns Ok(default).
    ///
    /// # Safety
    ///
    /// Requires initialize_test_kernel_state and register_thread_with_endpoint_capability
    /// for thread 1 to have been called first.
    unsafe fn enqueue_thread_as_receiver_on_endpoint(
        receiver_thread_identifier: u32,
        endpoint_index: usize,
    ) {
        let endpoint_pool = kernel_ipc_state::kernel_endpoint_pool_mut();
        let process_table = kernel_ipc_state::kernel_process_table_mut();
        let receiver_cspace = process_table
            .lookup_entry_mut(receiver_thread_identifier)
            .expect("enqueue_thread_as_receiver: thread must be registered");
        let receiver_thread =
            kernel_ipc_state::kernel_thread_at_mut(receiver_thread_identifier as usize)
                .expect("enqueue_thread_as_receiver: thread_index must be in bounds");
        let receive_result = ipc_receive(
            receiver_thread_identifier,
            0xFF,
            endpoint_index,
            endpoint_pool,
            receiver_thread,
            receiver_cspace,
            None,
            CAPABILITY_TRANSFER_NONE_SENTINEL,
            None,
            false,
            0,
        );
        assert!(
            receive_result.is_ok(),
            "enqueue_thread_as_receiver: ipc_receive must succeed when no sender present"
        );
    }

    /// Verifies that IpcError discriminants encode as expected negative return codes.
    ///
    /// Enforces D-05: Timeout(0) -> -1, WouldDeadlock(1) -> -2, EndpointRevoked(2) -> -3.
    #[test]
    fn test_ipc_error_encoding_produces_correct_negative_codes() {
        assert_eq!(
            encode_ipc_error_as_return_code(IpcError::Timeout),
            -1,
            "Timeout must encode as -1"
        );
        assert_eq!(
            encode_ipc_error_as_return_code(IpcError::WouldDeadlock),
            -2,
            "WouldDeadlock must encode as -2"
        );
        assert_eq!(
            encode_ipc_error_as_return_code(IpcError::EndpointRevoked),
            -3,
            "EndpointRevoked must encode as -3"
        );
    }

    /// Verifies that dispatch_ipc_send returns a negative error code when the calling
    /// thread has no registered CSpace in the process table.
    ///
    /// Exercises the CSpace lookup failure path (lookup_entry_mut returns None -> EndpointRevoked).
    #[test]
    fn test_dispatch_ipc_send_returns_error_for_unregistered_thread() {
        // SAFETY: Single-threaded test (--test-threads=1). No concurrent access.
        unsafe { initialize_test_kernel_state() };
        set_ipc_send_globals(0, 0xFF, 0, 0, 0, 0, 0xFF);
        // Thread 99 is not registered in the process table.
        let return_code = dispatch_ipc_send(99);
        assert!(
            return_code < 0,
            "unregistered thread must return negative error code, got {}",
            return_code
        );
    }

    /// Verifies that dispatch_ipc_send returns 0 (success) when timeout=0 and no receiver.
    ///
    /// A timeout=0 send is a non-blocking try: returns immediately Ok(()) when no receiver
    /// is present, per ipc_send semantics (handle_no_receiver_present returns Ok if timeout=0).
    #[test]
    fn test_dispatch_ipc_send_returns_success_for_nonblocking_try() {
        // SAFETY: Single-threaded test (--test-threads=1). No concurrent access.
        unsafe { initialize_test_kernel_state() };
        // Register thread 0 with Endpoint capability at slot 0 pointing to endpoint 0.
        unsafe { register_thread_with_endpoint_capability(0, 0) };
        set_ipc_send_globals(0, 0xFF, 0, 0xDEAD, 0xBEEF, 0xCAFE, 0xFF);
        // timeout=0 and no receiver -> non-blocking try returns Ok(()) -> 0.
        let return_code = dispatch_ipc_send(0);
        assert_eq!(
            return_code, 0,
            "non-blocking send with no receiver must return 0 (Ok), got {}",
            return_code
        );
    }

    /// Integration test: full IPC send->receive round-trip through the dispatch layer.
    ///
    /// Sets up two threads with CSpaces, enqueues thread 1 as receiver on endpoint 0,
    /// then dispatches send from thread 0. Rendezvous with the waiting receiver must
    /// succeed, returning 0.
    ///
    /// Exercises the full dispatch_ipc_send -> ipc_send -> rendezvous path.
    /// Enforces INV-IPC-001: IPC is kernel-mediated end-to-end through dispatch.
    /// Evidence for: perform_ipc_send SAFETY doc (INV-IPC-001).
    #[test]
    fn integration_ipc_round_trip_through_syscall_dispatch_layer() {
        // SAFETY: Single-threaded test (--test-threads=1). No concurrent access.
        unsafe { initialize_test_kernel_state() };
        // Register thread 0 (sender) and thread 1 (receiver) each with Endpoint cap at slot 0.
        unsafe { register_thread_with_endpoint_capability(0, 0) };
        unsafe { register_thread_with_endpoint_capability(1, 0) };
        // Enqueue thread 1 as receiver on endpoint 0 before the send.
        unsafe { enqueue_thread_as_receiver_on_endpoint(1, 0) };
        // Set send globals: endpoint_slot=0, cap_slot=0xFF, timeout=10, MR0-2 with test values.
        set_ipc_send_globals(0, 0xFF, 10, 0xDEAD, 0xBEEF, 0xCAFE, 0xFF);
        // Dispatch send from thread 0. Thread 1 is waiting -> rendezvous -> returns 0.
        let return_code = dispatch_ipc_send(0);
        assert_eq!(
            return_code, 0,
            "round-trip send with waiting receiver must return 0 (rendezvous success), got {}",
            return_code
        );
    }
}
