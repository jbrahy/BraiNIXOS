//! Capability space (CSpace): a process's flat array of capability slots.
//!
//! Design note: `CapabilitySpace` holds ONLY the slots array, NOT the derivation tree.
//! The derivation tree is a separate struct (`CapabilityDerivationTree`) for borrow-checker
//! reasons: `derive_capability` and `revoke_capability` need simultaneous mutable access to
//! both slots and the tree. If both lived in one struct, a single `&mut CapabilitySpace`
//! borrow would prevent independent mutation. Downstream plans pass them as separate
//! `&mut` parameters.
//!
//! Enforces INV-AUTH-001: no process has authority without explicit slots.
//! Enforces INV-AUTH-005: userspace accesses capabilities by slot index only.

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_slot::CapabilitySlot;
use crate::hardware_security::spectre_mitigation::issue_speculative_load_barrier;

/// Maximum number of capability slots per process.
///
/// 256 slots fit in a `u8` index, eliminating bounds-check overflow by construction.
/// Each `CapabilitySlot` is ~40 bytes, so each `CapabilitySpace` is ~10 KiB.
pub const MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS: usize = 256;

/// A process's capability space: a flat array of capability slots.
///
/// Slots are addressed by `u8` index (0–255), providing constant-time lookup.
/// `CapabilitySpace` does NOT contain the derivation tree (see module-level doc).
pub struct CapabilitySpace {
    slots: [CapabilitySlot; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
}

impl CapabilitySpace {
    /// Returns a new `CapabilitySpace` with all 256 slots initialized to null.
    ///
    /// Enforces INV-AUTH-001: a new process has no authority until explicitly granted.
    /// Verified by: tests::test_new_capability_space_all_slots_read_as_null
    pub const fn new() -> Self {
        CapabilitySpace {
            slots: [CapabilitySlot::null(); MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
        }
    }

    /// Returns a shared reference to the slot at `slot_index`.
    ///
    /// Returns `Err(CapabilityError::NullCapability)` if the slot is null.
    /// Slot index is `u8`, so it is always in range (0–255) by construction.
    ///
    /// Enforces INV-AUTH-005: slot index is the only userspace-visible reference.
    /// Verified by: tests::test_ungranted_slot_returns_error
    pub fn lookup_slot(&self, slot_index: u8) -> Result<&CapabilitySlot, CapabilityError> {
        let slot = self.read_slot_at_index(slot_index);
        slot.validate_is_usable()
    }

    /// Returns a mutable reference to the slot at `slot_index` for internal use.
    ///
    /// The `u8` index guarantees the access is always in bounds.
    pub fn lookup_slot_mut(&mut self, slot_index: u8) -> &mut CapabilitySlot {
        let index = usize::from(slot_index);
        &mut self.slots[index]
    }

    fn read_slot_at_index(&self, slot_index: u8) -> &CapabilitySlot {
        let index = usize::from(slot_index);
        // Spectre v1 mitigation: LFENCE after capability slot index bounds check.
        // Prevents speculative read of adjacent capability data using an
        // attacker-controlled out-of-bounds index. Per D-02.
        issue_speculative_load_barrier();
        &self.slots[index]
    }

    /// Returns a shared reference to the raw slot at `slot_index` without state checks.
    ///
    /// Unlike `lookup_slot`, this does not return an error for null slots.
    /// Used internally by derive_capability and revoke_capability to inspect slot state.
    pub fn lookup_slot_ref(&self, slot_index: u8) -> &CapabilitySlot {
        self.read_slot_at_index(slot_index)
    }

    /// Returns an iterator over all slots for inspection (used in tests and audit).
    pub fn all_slots(&self) -> &[CapabilitySlot; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS] {
        &self.slots
    }
}

impl Default for CapabilitySpace {
    fn default() -> Self {
        Self::new()
    }
}
