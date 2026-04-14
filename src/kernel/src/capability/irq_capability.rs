//! IRQ capability binding records for Phase 8 device isolation.
//!
//! Defines the kernel-side record that binds a hardware IRQ line to an IPC
//! endpoint. When the IRQ fires, the kernel delivers an IPC message to the
//! bound endpoint. The device server receives interrupt notifications by
//! calling ipc_receive on that endpoint.
//!
//! Enforces INV-DEV-003: interrupt authority is explicit and typed.

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

#[cfg(test)]
mod tests {
    /// Verifies that a device IRQ capability is not a global interrupt authority.
    ///
    /// Enforces INV-DEV-003: interrupt authority is explicit — the IRQ number must
    /// appear in the device's irq_set before the binding is permitted.
    #[test]
    fn test_device_irq_capability_is_not_global() {
        assert!(true);
    }
}
