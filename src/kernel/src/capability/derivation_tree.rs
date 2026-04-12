//! Capability derivation tree: tracks parent/child/sibling relationships between slots.
//!
//! The derivation tree is a fixed-size array of DerivationRecords indexed by slot number.
//! It is separate from CapabilitySpace to allow simultaneous mutable access during
//! derive_capability and revoke_capability (borrow-checker split per Plan 01 design).
//!
//! Enforces INV-AUTH-003: rights monotonicity is enforced at derivation time.
//! Enforces INV-AUTH-004: complete descendant revocation requires the full tree.

use crate::capability::capability_space::MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS;
use crate::capability::derivation_record::{DerivationRecord, SENTINEL_INDEX};

/// Fixed-size derivation tree for a single process's capability space.
///
/// One DerivationRecord per slot, all initialized to empty (all sentinels).
/// Indexed by the same u8 slot index used in CapabilitySpace.
pub struct CapabilityDerivationTree {
    records: [DerivationRecord; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
}

impl CapabilityDerivationTree {
    /// Returns a new tree with all records initialized to empty (all sentinel indices).
    pub const fn new() -> Self {
        CapabilityDerivationTree {
            records: [DerivationRecord::empty(); MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
        }
    }

    /// Links child_slot_index as a child of parent_slot_index in the derivation tree.
    ///
    /// The child is prepended to the parent's child list via next_sibling_index.
    pub fn record_derivation(&mut self, parent_slot_index: u8, child_slot_index: u8) {
        self.set_child_parent_link(child_slot_index, parent_slot_index);
        self.prepend_child_to_sibling_chain(parent_slot_index, child_slot_index);
    }

    /// Resets a record to empty, removing it from the tree.
    ///
    /// Used during revocation cleanup. Does not relink siblings; callers must
    /// clean up sibling chains if needed (revocation zeroes all descendants).
    pub fn remove_record(&mut self, slot_index: u8) {
        let index = usize::from(slot_index);
        self.records[index] = DerivationRecord::empty();
    }

    /// Returns the first child slot index of the given slot, or None if no children.
    pub fn first_child_of(&self, slot_index: u8) -> Option<u8> {
        let record = self.record_at(slot_index);
        sentinel_to_option(record.first_child_index)
    }

    /// Returns the next sibling slot index of the given slot, or None if last sibling.
    pub fn next_sibling_of(&self, slot_index: u8) -> Option<u8> {
        let record = self.record_at(slot_index);
        sentinel_to_option(record.next_sibling_index)
    }

    /// Returns the parent slot index of the given slot, or None if a root capability.
    pub fn parent_of(&self, slot_index: u8) -> Option<u8> {
        let record = self.record_at(slot_index);
        sentinel_to_option(record.parent_index)
    }

    fn record_at(&self, slot_index: u8) -> &DerivationRecord {
        &self.records[usize::from(slot_index)]
    }

    fn record_at_mut(&mut self, slot_index: u8) -> &mut DerivationRecord {
        &mut self.records[usize::from(slot_index)]
    }

    fn set_child_parent_link(&mut self, child_slot_index: u8, parent_slot_index: u8) {
        let child_record = self.record_at_mut(child_slot_index);
        child_record.parent_index = u32::from(parent_slot_index);
    }

    fn prepend_child_to_sibling_chain(&mut self, parent_slot_index: u8, child_slot_index: u8) {
        let existing_first_child = self.record_at(parent_slot_index).first_child_index;
        let child_record = self.record_at_mut(child_slot_index);
        child_record.next_sibling_index = existing_first_child;
        let parent_record = self.record_at_mut(parent_slot_index);
        parent_record.first_child_index = u32::from(child_slot_index);
    }
}

impl Default for CapabilityDerivationTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Converts a raw index to Option<u8>, returning None for SENTINEL_INDEX.
fn sentinel_to_option(raw_index: u32) -> Option<u8> {
    if raw_index == SENTINEL_INDEX {
        return None;
    }
    Some(raw_index as u8)
}
