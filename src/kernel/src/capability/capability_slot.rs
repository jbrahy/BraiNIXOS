//! Capability slot structure and slot state lifecycle.
//!
//! Each capability slot holds one typed capability with its rights, object pointer,
//! generation counter, derivation link, and optional temporal constraints.
//!
//! Enforces INV-OBJ-001: every kernel object has a defined lifecycle.
//! Enforces INV-OBJ-002: object reuse cannot preserve stale authority.

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_rights::CapabilityRights;
use crate::capability::capability_type::CapabilityType;

/// Lifecycle state of a capability slot.
///
/// A slot is in exactly one of three states: Null (empty), Valid (holds a capability),
/// or Revoking (parent is being revoked — treated as invalid immediately per D-03).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapabilitySlotState {
    /// The slot contains the null capability sentinel. No capability is present.
    Null,
    /// The slot contains a valid, usable capability.
    Valid,
    /// The slot's parent capability is being revoked. Treated as invalid (D-03).
    Revoking,
}

/// A single capability slot holding one typed capability.
///
/// Enforces INV-AUTH-002: authority is explicit and typed (capability_type field).
/// Enforces INV-OBJ-003: object identity cannot be confused across generations
/// (generation_counter field).
///
/// Total size: approximately 40 bytes (padded for alignment).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CapabilitySlot {
    /// Current lifecycle state of this slot.
    pub state: CapabilitySlotState,
    /// The type of kernel object this capability grants access to.
    pub capability_type: CapabilityType,
    /// Bitmask of permitted operations on the referenced object.
    pub rights_bitmask: CapabilityRights,
    /// Raw address of the kernel object this capability refers to (stored as integer).
    pub object_pointer: u64,
    /// Monotonically increasing counter preventing stale reference reuse (INV-OBJ-003).
    pub generation_counter: u64,
    /// Slot index of the parent in the derivation tree. `u32::MAX` for root capabilities.
    pub derivation_parent_index: u32,
    /// If `Some(n)`, the capability auto-revokes after `n` invocations.
    pub use_count_remaining: Option<u32>,
    /// If `Some(t)`, the capability auto-revokes after kernel tick `t`.
    pub expiry_tick: Option<u64>,
}

impl CapabilitySlot {
    /// Returns the null capability sentinel with all fields at their null values.
    ///
    /// Enforces INV-OBJ-002: no capability slot carries stale authority after zeroing.
    /// Verified by: tests::test_new_capability_space_all_slots_read_as_null
    pub const fn null() -> Self {
        CapabilitySlot {
            state: CapabilitySlotState::Null,
            capability_type: CapabilityType::Memory,
            rights_bitmask: CapabilityRights::empty(),
            object_pointer: 0,
            generation_counter: 0,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        }
    }

    /// Returns true if this slot contains the null sentinel (no capability present).
    ///
    /// Verified by: tests::test_new_capability_space_all_slots_read_as_null
    pub fn is_null(&self) -> bool {
        self.state == CapabilitySlotState::Null
    }

    /// Returns true if this slot contains a valid, usable capability.
    pub fn is_valid(&self) -> bool {
        self.state == CapabilitySlotState::Valid
    }

    /// Returns true if this slot's parent is currently being revoked.
    ///
    /// A revoking slot must be treated as invalid immediately (D-03).
    pub fn is_revoking(&self) -> bool {
        self.state == CapabilitySlotState::Revoking
    }

    /// Returns Ok with a reference to self if the slot is valid, or Err otherwise.
    ///
    /// Enforces INV-AUTH-001: all operations require an explicit valid capability.
    /// Verified by: tests::test_ungranted_slot_returns_error
    pub fn validate_is_usable(&self) -> Result<&Self, CapabilityError> {
        if self.is_null() {
            return Err(CapabilityError::NullCapability);
        }
        if self.is_revoking() {
            return Err(CapabilityError::NullCapability);
        }
        Ok(self)
    }
}
