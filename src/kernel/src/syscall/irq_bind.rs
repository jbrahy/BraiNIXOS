//! sys_irq_bind handler.
//!
//! Binds a hardware IRQ line to an IPC endpoint. When the IRQ fires,
//! the future IRQ dispatcher will deliver an IPC notification to the bound
//! endpoint, allowing the owning device server to receive interrupts via
//! ipc_receive.
//!
//! Argument passing (via kernel syscall register globals):
//!   MESSAGE_REGISTER_ZERO -> irq_number  (low 8 bits)
//!   MESSAGE_REGISTER_ONE  -> device_capability_slot_index  (low 8 bits)
//!   CAP_SLOT              -> endpoint_capability_slot_index  (low 8 bits)
//!
//! Return value:
//!   0  -> bind succeeded
//!   -1 -> bind failed (any validation or table-full error). Fail closed.
//!
//! Falls under `src/kernel/src/syscall/irq_bind.rs` allowlist entry in
//! `docs/security/UNSAFE_CODE_POLICY.md`: unsafe is required to read
//! syscall register atomics and dereference the object_pointer of a
//! validated CapDevice slot (which points at a static DeviceCapabilityData).
//!
//! Enforces INV-DEV-003: interrupt authority is explicit and typed.
//! Enforces INV-AUTH-002: authority is explicit and typed (slot type tags).
#![allow(unsafe_code)]

use core::sync::atomic::Ordering;

use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::capability::device_capability::DeviceCapabilityData;
use crate::capability::irq_capability::{
    bind_irq_to_endpoint, is_irq_in_device_set, IrqBindingTable,
};
use crate::syscall::kernel_ipc_state::{kernel_irq_binding_table_mut, kernel_process_table_mut};
use crate::syscall::kernel_syscall_registers::{
    KERNEL_SYSCALL_CAP_SLOT_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE,
    KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE,
};

/// Success return value for sys_irq_bind.
const IRQ_BIND_RETURN_OK: i64 = 0;

/// Fail-closed return value for sys_irq_bind (any validation or binding failure).
const IRQ_BIND_RETURN_FAIL: i64 = -1;

/// Tuple of caller-supplied arguments read from syscall register globals.
struct IrqBindArguments {
    irq_number: u8,
    device_capability_slot_index: u8,
    endpoint_capability_slot_index: u8,
}

/// Handles the sys_irq_bind system call.
///
/// Returns 0 on successful bind, -1 on any failure (fail closed).
///
/// Mitigates T-DEV-012: IRQ not in device's irq_set cannot be bound.
/// Mitigates T-14-01..06 per `.planning/phases/14-non-critical-wiring-gaps/14-01-PLAN.md`.
/// Enforces INV-DEV-003: interrupt authority is explicit and typed.
/// Verified by: tests::test_irq_bind_rejects_irq_not_in_device_set
pub fn handle_irq_bind_syscall(thread_identifier: u32) -> i64 {
    let arguments = read_irq_bind_arguments();
    let caller_cspace = match look_up_caller_capability_space(thread_identifier) {
        Some(cspace) => cspace,
        None => return IRQ_BIND_RETURN_FAIL,
    };
    validate_and_install_irq_binding(caller_cspace, &arguments, thread_identifier)
}

/// Reads IRQ number, device slot, and endpoint slot from the syscall register globals.
///
/// Each value is truncated from u64 to u8; higher bits are discarded. This matches the
/// ABI contract: sys_irq_bind arguments are u8-sized, so the userspace syscall wrapper
/// writes them into the low byte of each register.
fn read_irq_bind_arguments() -> IrqBindArguments {
    let irq_register_value = KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.load(Ordering::Relaxed);
    let device_register_value = KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE.load(Ordering::Relaxed);
    let endpoint_register_value = KERNEL_SYSCALL_CAP_SLOT_VALUE.load(Ordering::Relaxed);
    build_irq_bind_arguments(
        irq_register_value,
        device_register_value,
        endpoint_register_value,
    )
}

/// Packs three register values into an IrqBindArguments struct.
fn build_irq_bind_arguments(
    irq_register_value: u64,
    device_register_value: u64,
    endpoint_register_value: u64,
) -> IrqBindArguments {
    IrqBindArguments {
        irq_number: irq_register_value as u8,
        device_capability_slot_index: device_register_value as u8,
        endpoint_capability_slot_index: endpoint_register_value as u8,
    }
}

/// Resolves the caller's CapabilitySpace via the kernel process table.
///
/// Returns None if `thread_identifier` is unknown (mitigates T-14-04: forged tid).
fn look_up_caller_capability_space(thread_identifier: u32) -> Option<&'static CapabilitySpace> {
    // SAFETY: kernel_process_table_mut is only called from the single-core
    // SYSCALL dispatch path. Precondition: initialize_kernel_process_table was
    // called at boot. Invariant: INV-AUTH-001 (process table ready).
    // Evidence: identical pattern in ipc_dispatch_handlers::perform_ipc_send.
    unsafe { kernel_process_table_mut().lookup_entry(thread_identifier) }
}

/// Validates the caller's capabilities and installs the IRQ binding on success.
///
/// Returns IRQ_BIND_RETURN_OK on successful bind, IRQ_BIND_RETURN_FAIL on any
/// validation or table-full error.
fn validate_and_install_irq_binding(
    caller_cspace: &CapabilitySpace,
    arguments: &IrqBindArguments,
    thread_identifier: u32,
) -> i64 {
    if !caller_holds_irq_on_device(caller_cspace, arguments) {
        return IRQ_BIND_RETURN_FAIL;
    }
    if !caller_holds_endpoint(caller_cspace, arguments.endpoint_capability_slot_index) {
        return IRQ_BIND_RETURN_FAIL;
    }
    install_irq_binding(arguments, thread_identifier)
}

/// Returns true iff the caller holds a CapDevice at device_capability_slot_index whose
/// irq_set contains irq_number. Mitigates T-14-01 (forged bind) and T-14-02 (unauthorized IRQ).
fn caller_holds_irq_on_device(
    caller_cspace: &CapabilitySpace,
    arguments: &IrqBindArguments,
) -> bool {
    let device_data =
        match read_device_capability_data(caller_cspace, arguments.device_capability_slot_index) {
            Some(data) => data,
            None => return false,
        };
    is_irq_in_device_set(arguments.irq_number, device_data)
}

/// Resolves a &'static DeviceCapabilityData from the slot at `slot_index`, or None.
///
/// Returns None if the slot is null, if the capability type is not Device, or if
/// the object_pointer is zero.
fn read_device_capability_data(
    caller_cspace: &CapabilitySpace,
    slot_index: u8,
) -> Option<&'static DeviceCapabilityData> {
    let slot = caller_cspace.lookup_slot(slot_index).ok()?;
    if slot.capability_type != CapabilityType::Device || slot.object_pointer == 0 {
        return None;
    }
    dereference_device_capability_data(slot.object_pointer)
}

/// Dereferences a validated object_pointer as a &'static DeviceCapabilityData.
///
/// # Safety
///
/// The caller MUST have validated that the slot's capability_type is Device and
/// that the object_pointer is non-zero. Device capabilities are granted at boot
/// with object_pointer set to the address of a `'static DeviceCapabilityData`
/// (see boot/phases.rs grant_nic_device_capability_to_devd_nic).
/// - Precondition: capability_type == Device && object_pointer != 0.
/// - Invariant: INV-AUTH-002 (authority is explicit and typed).
/// - Evidence: boot/phases.rs:332,369 populate object_pointer from &STATIC.
fn dereference_device_capability_data(
    object_pointer: u64,
) -> Option<&'static DeviceCapabilityData> {
    let data_pointer = object_pointer as *const DeviceCapabilityData;
    unsafe { data_pointer.as_ref() }
}

/// Returns true iff the caller holds a CapEndpoint at endpoint_capability_slot_index.
/// Mitigates T-14-03 (binding to an endpoint the caller does not hold).
fn caller_holds_endpoint(
    caller_cspace: &CapabilitySpace,
    endpoint_capability_slot_index: u8,
) -> bool {
    let slot = match caller_cspace.lookup_slot(endpoint_capability_slot_index) {
        Ok(slot) => slot,
        Err(_) => return false,
    };
    slot.capability_type == CapabilityType::Endpoint
}

/// Installs the binding in the kernel IRQ binding table.
///
/// Returns IRQ_BIND_RETURN_OK on success, IRQ_BIND_RETURN_FAIL on
/// BindingTableFull or IrqAlreadyBound (both mapped to -1).
fn install_irq_binding(arguments: &IrqBindArguments, thread_identifier: u32) -> i64 {
    let owning_process_index = compute_owning_process_index(thread_identifier);
    // SAFETY: kernel_irq_binding_table_mut is only called from the single-core
    // SYSCALL dispatch path. Precondition: IrqBindingTable::new() is const and
    // the static is zero-initialized to all-inactive at BSS load time.
    // Invariant: INV-DEV-003 (interrupt authority is explicit and typed).
    let table = unsafe { kernel_irq_binding_table_mut() };
    translate_bind_result(table_bind_call(table, arguments, owning_process_index))
}

/// Performs the actual bind_irq_to_endpoint call.
fn table_bind_call(
    table: &mut IrqBindingTable,
    arguments: &IrqBindArguments,
    owning_process_index: u8,
) -> Result<(), crate::capability::irq_capability::IrqBindingError> {
    bind_irq_to_endpoint(
        table,
        arguments.irq_number,
        arguments.endpoint_capability_slot_index,
        owning_process_index,
    )
}

/// Maps thread_identifier (u32) to owning_process_index (u8).
///
/// Safe because MAXIMUM_THREADS = 32, so any valid thread_identifier fits in u8.
/// The ProcessTable's `lookup_entry` was already called and returned Some, which
/// establishes that this thread_identifier is within bounds.
fn compute_owning_process_index(thread_identifier: u32) -> u8 {
    (thread_identifier & 0xFF) as u8
}

/// Maps a bind_irq_to_endpoint Result into the syscall return discriminant.
fn translate_bind_result(
    result: Result<(), crate::capability::irq_capability::IrqBindingError>,
) -> i64 {
    match result {
        Ok(()) => IRQ_BIND_RETURN_OK,
        Err(_) => IRQ_BIND_RETURN_FAIL,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::capability_rights;
    use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
    use crate::capability::device_capability::{DeviceType, IRQ_NONE};

    const DEVICE_SLOT_INDEX: u8 = 0;
    const ENDPOINT_SLOT_INDEX: u8 = 1;

    static TEST_DEVICE_DATA_WITH_IRQ_ELEVEN: DeviceCapabilityData = DeviceCapabilityData {
        device_type: DeviceType::NetworkInterface,
        mmio_base_address: 0x1000_0000,
        mmio_size: 0x1000,
        irq_set: [11, IRQ_NONE, IRQ_NONE, IRQ_NONE],
    };

    fn build_valid_capability_slot(
        capability_type: CapabilityType,
        object_pointer: u64,
    ) -> CapabilitySlot {
        CapabilitySlot {
            state: CapabilitySlotState::Valid,
            capability_type,
            rights_bitmask: capability_rights::READ,
            object_pointer,
            generation_counter: 0,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        }
    }

    fn install_device_capability_in_slot(cspace: &mut CapabilitySpace, slot_index: u8) {
        let device_pointer =
            &TEST_DEVICE_DATA_WITH_IRQ_ELEVEN as *const DeviceCapabilityData as u64;
        let slot_reference = cspace.lookup_slot_mut(slot_index);
        *slot_reference = build_valid_capability_slot(CapabilityType::Device, device_pointer);
    }

    fn install_endpoint_capability_in_slot(cspace: &mut CapabilitySpace, slot_index: u8) {
        let slot_reference = cspace.lookup_slot_mut(slot_index);
        *slot_reference = build_valid_capability_slot(CapabilityType::Endpoint, 0xDEAD_BEEF);
    }

    fn build_cspace_with_device_and_endpoint() -> CapabilitySpace {
        let mut cspace = CapabilitySpace::new();
        install_device_capability_in_slot(&mut cspace, DEVICE_SLOT_INDEX);
        install_endpoint_capability_in_slot(&mut cspace, ENDPOINT_SLOT_INDEX);
        cspace
    }

    /// T-14-02 mitigation: IRQ 10 is not in the device's irq_set {11} — bind must fail.
    #[test]
    fn test_irq_bind_rejects_irq_not_in_device_set() {
        let cspace = build_cspace_with_device_and_endpoint();
        let arguments = IrqBindArguments {
            irq_number: 10,
            device_capability_slot_index: DEVICE_SLOT_INDEX,
            endpoint_capability_slot_index: ENDPOINT_SLOT_INDEX,
        };
        let device_check = caller_holds_irq_on_device(&cspace, &arguments);
        assert!(
            !device_check,
            "IRQ 10 is not in device irq_set {{11}}; bind must fail"
        );
    }

    /// T-14-01 mitigation: slot contains Endpoint, not Device — bind must fail.
    #[test]
    fn test_irq_bind_rejects_non_device_capability_at_device_slot() {
        let mut cspace = CapabilitySpace::new();
        install_endpoint_capability_in_slot(&mut cspace, DEVICE_SLOT_INDEX);
        install_endpoint_capability_in_slot(&mut cspace, ENDPOINT_SLOT_INDEX);
        let arguments = IrqBindArguments {
            irq_number: 11,
            device_capability_slot_index: DEVICE_SLOT_INDEX,
            endpoint_capability_slot_index: ENDPOINT_SLOT_INDEX,
        };
        assert!(!caller_holds_irq_on_device(&cspace, &arguments));
    }

    /// T-14-03 mitigation: endpoint slot contains Device, not Endpoint — bind must fail.
    #[test]
    fn test_irq_bind_rejects_non_endpoint_capability_at_endpoint_slot() {
        let mut cspace = CapabilitySpace::new();
        install_device_capability_in_slot(&mut cspace, DEVICE_SLOT_INDEX);
        install_device_capability_in_slot(&mut cspace, ENDPOINT_SLOT_INDEX);
        let endpoint_check = caller_holds_endpoint(&cspace, ENDPOINT_SLOT_INDEX);
        assert!(
            !endpoint_check,
            "slot 1 holds Device, not Endpoint; bind must fail"
        );
    }

    /// T-14-01 mitigation: null (ungranted) device slot — bind must fail.
    #[test]
    fn test_irq_bind_rejects_null_device_slot() {
        let cspace = CapabilitySpace::new();
        let arguments = IrqBindArguments {
            irq_number: 11,
            device_capability_slot_index: DEVICE_SLOT_INDEX,
            endpoint_capability_slot_index: ENDPOINT_SLOT_INDEX,
        };
        assert!(!caller_holds_irq_on_device(&cspace, &arguments));
    }
}
