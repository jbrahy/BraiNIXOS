//! Rights-monotonic capability derivation.
//!
//! Implements derive_capability: creates a child capability with a subset of the
//! parent's rights. Cross-type derivation is prohibited.
//!
//! Enforces INV-AUTH-003: rights monotonicity under derivation.
//! A derived capability can never grant rights not present in its parent.

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_rights::CapabilityRights;
use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::derivation_tree::CapabilityDerivationTree;

/// Creates a child capability derived from parent_slot_index at child_slot_index.
///
/// The child receives the requested_rights, which must be a subset of the parent's
/// rights_bitmask. The child inherits the parent's capability_type and object_pointer.
///
/// Enforces INV-AUTH-003: rights monotonicity under derivation.
/// Verified by: tests::test_derived_capability_cannot_have_rights_not_in_parent
pub fn derive_capability(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    parent_slot_index: u8,
    child_slot_index: u8,
    requested_rights: CapabilityRights,
) -> Result<(), CapabilityError> {
    let parent_snapshot = read_valid_parent(capability_space, parent_slot_index)?;
    check_child_slot_is_null(capability_space, child_slot_index)?;
    check_rights_do_not_exceed_parent(requested_rights, parent_snapshot.rights_bitmask)?;
    initialize_child_slot(
        capability_space,
        parent_slot_index,
        child_slot_index,
        requested_rights,
        &parent_snapshot,
    );
    derivation_tree.record_derivation(parent_slot_index, child_slot_index);
    Ok(())
}

/// Returns a copy of the parent slot if it is Valid, else NullCapability.
fn read_valid_parent(
    capability_space: &CapabilitySpace,
    parent_slot_index: u8,
) -> Result<CapabilitySlot, CapabilityError> {
    let parent_slot = capability_space.lookup_slot_ref(parent_slot_index);
    if !parent_slot.is_valid() {
        return Err(CapabilityError::NullCapability);
    }
    Ok(*parent_slot)
}

/// Returns Err(SlotOccupied) if child_slot_index is not null.
fn check_child_slot_is_null(
    capability_space: &CapabilitySpace,
    child_slot_index: u8,
) -> Result<(), CapabilityError> {
    let child_slot = capability_space.lookup_slot_ref(child_slot_index);
    if !child_slot.is_null() {
        return Err(CapabilityError::SlotOccupied);
    }
    Ok(())
}

/// Returns Err(RightsExceedParent) if requested_rights has bits not in parent_rights.
///
/// Enforces INV-AUTH-003: `requested_rights & !parent_rights` must be zero.
fn check_rights_do_not_exceed_parent(
    requested_rights: CapabilityRights,
    parent_rights: CapabilityRights,
) -> Result<(), CapabilityError> {
    let excess_rights = requested_rights & !parent_rights;
    if !excess_rights.is_empty() {
        return Err(CapabilityError::RightsExceedParent);
    }
    Ok(())
}

/// Initializes all child slot fields by calling the two field-population helpers.
///
/// Splits into two helpers to keep each under the 6-line body limit.
fn initialize_child_slot(
    capability_space: &mut CapabilitySpace,
    parent_slot_index: u8,
    child_slot_index: u8,
    requested_rights: CapabilityRights,
    parent_snapshot: &CapabilitySlot,
) {
    populate_child_slot_core_fields(
        capability_space,
        child_slot_index,
        requested_rights,
        parent_snapshot,
    );
    set_child_derivation_parent(capability_space, child_slot_index, parent_slot_index);
}

/// Fills the child slot's core fields: state, type, rights, and object pointer.
fn populate_child_slot_core_fields(
    capability_space: &mut CapabilitySpace,
    child_slot_index: u8,
    requested_rights: CapabilityRights,
    parent_snapshot: &CapabilitySlot,
) {
    let child_slot = capability_space.lookup_slot_mut(child_slot_index);
    child_slot.state = CapabilitySlotState::Valid;
    child_slot.capability_type = parent_snapshot.capability_type;
    child_slot.rights_bitmask = requested_rights;
    child_slot.object_pointer = parent_snapshot.object_pointer;
    child_slot.generation_counter = parent_snapshot.generation_counter;
}

/// Sets the derivation parent index on the child slot.
///
/// Separate from core field population so each helper stays within 6 lines.
fn set_child_derivation_parent(
    capability_space: &mut CapabilitySpace,
    child_slot_index: u8,
    parent_slot_index: u8,
) {
    let child_slot = capability_space.lookup_slot_mut(child_slot_index);
    child_slot.derivation_parent_index = u32::from(parent_slot_index);
}
