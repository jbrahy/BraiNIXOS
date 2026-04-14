//! IRQ capability binding records for Phase 8 device isolation.
//!
//! Defines the kernel-side record that binds a hardware IRQ line to an IPC
//! endpoint. When the IRQ fires, the kernel delivers an IPC message to the
//! bound endpoint. The device server receives interrupt notifications by
//! calling ipc_receive on that endpoint.
//!
//! Enforces INV-DEV-003: interrupt authority is explicit and typed.

use crate::capability::device_capability::{DeviceCapabilityData, IRQ_NONE};

/// Sentinel value for empty IRQ binding records.
///
/// An irq_number field containing IRQ_BINDING_EMPTY_SENTINEL indicates
/// this binding slot is unoccupied.
pub const IRQ_BINDING_EMPTY_SENTINEL: u8 = 0xFF;

/// Maximum number of simultaneous IRQ bindings the kernel supports.
pub const MAXIMUM_IRQ_BINDINGS: usize = 16;

/// Kernel-side record linking one hardware IRQ line to one IPC endpoint.
///
/// When the IRQ fires, the kernel looks up the binding record and delivers
/// an IPC message to bound_endpoint_slot_index in owning_process_index's
/// capability space.
///
/// Enforces INV-DEV-003: interrupt authority is explicit and typed.
/// Verified by: test_device_irq_capability_is_not_global
#[derive(Copy, Clone)]
pub struct IrqBindingRecord {
    /// The hardware IRQ number this record binds. IRQ_BINDING_EMPTY_SENTINEL if unoccupied.
    pub irq_number: u8,
    /// Index of the endpoint capability slot in the owning process's CSpace.
    pub bound_endpoint_slot_index: u8,
    /// Thread pool index of the process that owns this IRQ binding.
    pub owning_process_index: u8,
    /// True if this binding is currently active and will receive IRQ deliveries.
    pub is_active: bool,
}

impl IrqBindingRecord {
    /// Returns an empty IrqBindingRecord with the sentinel irq_number and is_active = false.
    pub const fn empty() -> Self {
        IrqBindingRecord {
            irq_number: IRQ_BINDING_EMPTY_SENTINEL,
            bound_endpoint_slot_index: 0,
            owning_process_index: 0,
            is_active: false,
        }
    }
}

/// Errors returned when an IRQ bind request fails validation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IrqBindingError {
    /// The requested IRQ number is not in the device's assigned irq_set.
    IrqNotInDeviceSet,
    /// The endpoint capability slot index is not a valid endpoint in the caller's CSpace.
    EndpointSlotInvalid,
    /// The kernel IRQ binding table is full and cannot accept new entries.
    BindingTableFull,
    /// The requested IRQ number is already bound to another endpoint.
    IrqAlreadyBound,
}

/// Fixed-size kernel table holding all active IRQ-to-endpoint bindings.
///
/// Backed by a BSS-static array. No dynamic allocation. Maximum capacity
/// is MAXIMUM_IRQ_BINDINGS (16) entries.
pub struct IrqBindingTable {
    bindings: [IrqBindingRecord; MAXIMUM_IRQ_BINDINGS],
}

impl IrqBindingTable {
    /// Returns a new IrqBindingTable with all entries inactive and empty.
    pub const fn new() -> Self {
        IrqBindingTable {
            bindings: [IrqBindingRecord::empty(); MAXIMUM_IRQ_BINDINGS],
        }
    }
}

/// Returns true if irq_number appears in the device's irq_set and is not IRQ_NONE.
///
/// Enforces INV-DEV-003: interrupt authority is explicit — the IRQ number must
/// appear in the device's assigned irq_set before any binding is permitted.
/// Verified by: test_device_irq_capability_is_not_global
pub fn is_irq_in_device_set(irq_number: u8, device_data: &DeviceCapabilityData) -> bool {
    let first_slot_matches = check_irq_slot_matches(irq_number, device_data.irq_set[0]);
    let second_slot_matches = check_irq_slot_matches(irq_number, device_data.irq_set[1]);
    let third_slot_matches = check_irq_slot_matches(irq_number, device_data.irq_set[2]);
    let fourth_slot_matches = check_irq_slot_matches(irq_number, device_data.irq_set[3]);
    first_slot_matches || second_slot_matches || third_slot_matches || fourth_slot_matches
}

/// Returns true if the slot value equals irq_number and is not IRQ_NONE.
fn check_irq_slot_matches(irq_number: u8, slot_value: u8) -> bool {
    let slot_is_occupied = slot_value != IRQ_NONE;
    let slot_matches_irq = slot_value == irq_number;
    slot_is_occupied && slot_matches_irq
}

/// Binds irq_number to endpoint_slot_index for the process at process_index.
///
/// Returns Err(IrqAlreadyBound) if the IRQ is already active in the table.
/// Returns Err(BindingTableFull) if no inactive slot is available.
/// Returns Ok(()) on success.
///
/// Enforces INV-DEV-003: interrupt authority is explicit.
/// Verified by: test_bind_irq_to_endpoint_succeeds_for_valid_irq
pub fn bind_irq_to_endpoint(
    table: &mut IrqBindingTable,
    irq_number: u8,
    endpoint_slot_index: u8,
    process_index: u8,
) -> Result<(), IrqBindingError> {
    let irq_is_already_bound = find_active_binding_index(table, irq_number).is_some();
    if irq_is_already_bound {
        return Err(IrqBindingError::IrqAlreadyBound);
    }
    let inactive_slot_index = find_inactive_slot_index(table);
    let slot_index = inactive_slot_index.ok_or(IrqBindingError::BindingTableFull)?;
    write_binding_record(table, slot_index, irq_number, endpoint_slot_index, process_index);
    Ok(())
}

/// Returns the index of the first active binding for irq_number, or None.
fn find_active_binding_index(table: &IrqBindingTable, irq_number: u8) -> Option<usize> {
    let mut found_index: Option<usize> = None;
    let mut slot_index: usize = 0;
    while slot_index < MAXIMUM_IRQ_BINDINGS {
        let binding = table.bindings[slot_index];
        let is_active_match = binding.is_active && binding.irq_number == irq_number;
        if is_active_match && found_index.is_none() {
            found_index = Some(slot_index);
        }
        slot_index += 1;
    }
    found_index
}

/// Returns the index of the first inactive slot in the table, or None if full.
fn find_inactive_slot_index(table: &IrqBindingTable) -> Option<usize> {
    let mut found_index: Option<usize> = None;
    let mut slot_index: usize = 0;
    while slot_index < MAXIMUM_IRQ_BINDINGS {
        let slot_is_inactive = !table.bindings[slot_index].is_active;
        if slot_is_inactive && found_index.is_none() {
            found_index = Some(slot_index);
        }
        slot_index += 1;
    }
    found_index
}

/// Writes a new active binding record into the given slot index.
fn write_binding_record(
    table: &mut IrqBindingTable,
    slot_index: usize,
    irq_number: u8,
    endpoint_slot_index: u8,
    process_index: u8,
) {
    table.bindings[slot_index] = IrqBindingRecord {
        irq_number,
        bound_endpoint_slot_index: endpoint_slot_index,
        owning_process_index: process_index,
        is_active: true,
    };
}

/// Returns a copy of the active binding record for irq_number, or None if not bound.
///
/// Enforces INV-DEV-003: stale or inactive bindings are not returned.
/// Verified by: test_lookup_binding_for_unbound_irq_returns_none
pub fn lookup_binding_for_irq(table: &IrqBindingTable, irq_number: u8) -> Option<IrqBindingRecord> {
    let active_index = find_active_binding_index(table, irq_number);
    active_index.map(|index| table.bindings[index])
}

#[cfg(test)]
mod tests {
    use super::{
        IrqBindingError, IrqBindingTable, MAXIMUM_IRQ_BINDINGS,
        bind_irq_to_endpoint, is_irq_in_device_set, lookup_binding_for_irq,
    };
    use crate::capability::device_capability::{DeviceCapabilityData, DeviceType, IRQ_NONE};

    fn build_nic_device_data() -> DeviceCapabilityData {
        DeviceCapabilityData {
            device_type: DeviceType::NetworkInterface,
            mmio_base_address: 0xFEBE_0000,
            mmio_size: 0x1000,
            irq_set: [11, IRQ_NONE, IRQ_NONE, IRQ_NONE],
        }
    }

    /// Verifies that a device IRQ capability is not a global interrupt authority.
    ///
    /// Enforces INV-DEV-003: interrupt authority is explicit — the IRQ number must
    /// appear in the device's irq_set before the binding is permitted.
    #[test]
    fn test_device_irq_capability_is_not_global() {
        let nic_data = build_nic_device_data();
        let irq_eleven_in_set = is_irq_in_device_set(11, &nic_data);
        let irq_ten_not_in_set = is_irq_in_device_set(10, &nic_data);
        let irq_zero_not_in_set = is_irq_in_device_set(0, &nic_data);
        assert!(irq_eleven_in_set);
        assert!(!irq_ten_not_in_set);
        assert!(!irq_zero_not_in_set);
    }

    /// Verifies that binding an IRQ to an endpoint succeeds for a valid IRQ number.
    ///
    /// Enforces INV-DEV-003: a valid binding can be established and retrieved.
    #[test]
    fn test_bind_irq_to_endpoint_succeeds_for_valid_irq() {
        let mut table = IrqBindingTable::new();
        let bind_result = bind_irq_to_endpoint(&mut table, 11, 0, 0);
        assert_eq!(bind_result, Ok(()));
        let lookup_result = lookup_binding_for_irq(&table, 11);
        assert!(lookup_result.is_some());
        let record = lookup_result.unwrap();
        assert_eq!(record.bound_endpoint_slot_index, 0);
    }

    /// Verifies that binding an already-bound IRQ returns IrqAlreadyBound.
    ///
    /// Enforces INV-DEV-003: each IRQ line has at most one active binding.
    #[test]
    fn test_bind_irq_to_endpoint_rejects_duplicate_binding() {
        let mut table = IrqBindingTable::new();
        let first_bind_result = bind_irq_to_endpoint(&mut table, 11, 0, 0);
        assert_eq!(first_bind_result, Ok(()));
        let second_bind_result = bind_irq_to_endpoint(&mut table, 11, 1, 0);
        assert_eq!(second_bind_result, Err(IrqBindingError::IrqAlreadyBound));
    }

    /// Verifies that filling the table with 16 entries causes the 17th to fail.
    ///
    /// Enforces T-DEV-008: binding table overflow is structurally prevented.
    #[test]
    fn test_bind_irq_fills_table_returns_full_error() {
        let mut table = IrqBindingTable::new();
        let mut irq_number: u8 = 0;
        while irq_number < MAXIMUM_IRQ_BINDINGS as u8 {
            let bind_result = bind_irq_to_endpoint(&mut table, irq_number, 0, 0);
            assert_eq!(bind_result, Ok(()));
            irq_number += 1;
        }
        let overflow_result = bind_irq_to_endpoint(&mut table, 100, 0, 0);
        assert_eq!(overflow_result, Err(IrqBindingError::BindingTableFull));
    }

    /// Verifies that looking up an unbound IRQ returns None.
    ///
    /// Enforces T-DEV-009: lookup does not return stale or inactive bindings.
    #[test]
    fn test_lookup_binding_for_unbound_irq_returns_none() {
        let table = IrqBindingTable::new();
        let lookup_result = lookup_binding_for_irq(&table, 99);
        assert!(lookup_result.is_none());
    }

    /// Verifies that a new IrqBindingTable starts with all entries inactive.
    ///
    /// Enforces the structural invariant that no binding is active at construction time.
    #[test]
    fn test_irq_binding_table_starts_all_inactive() {
        let table = IrqBindingTable::new();
        let mut all_inactive = true;
        let mut slot_index: usize = 0;
        while slot_index < MAXIMUM_IRQ_BINDINGS {
            if table.bindings[slot_index].is_active {
                all_inactive = false;
            }
            slot_index += 1;
        }
        assert!(all_inactive);
    }
}
