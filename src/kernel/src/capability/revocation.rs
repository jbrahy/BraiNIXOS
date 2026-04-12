//! Cascading capability revocation via depth-first descendant walk.
//!
//! Implements revoke_capability: marks a slot and all its descendants as Revoking,
//! then zeroes each via write_volatile through the memory module's slot_zeroing function.
//!
//! Enforces INV-AUTH-004: revocation is final within defined scope.
//! Enforces INV-OBJ-002: revoked slots cannot carry stale authority.

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_slot::CapabilitySlotState;
use crate::capability::capability_space::{CapabilitySpace, MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS};
use crate::capability::derivation_tree::CapabilityDerivationTree;
use crate::memory::slot_zeroing::zero_capability_slot_via_reference;

/// Revokes the capability at target_slot_index and all its descendants.
///
/// Performs a depth-first walk using an explicit bounded stack (no recursion).
/// Each slot is marked Revoking then zeroed via write_volatile.
///
/// Enforces INV-AUTH-004: revocation is final within defined scope.
/// Verified by: tests::test_revoked_parent_makes_all_children_unusable
///              tests::test_revoked_slot_reads_as_null_not_stale_data
pub fn revoke_capability(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    target_slot_index: u8,
) -> Result<u32, CapabilityError> {
    check_target_slot_is_valid(capability_space, target_slot_index)?;
    mark_slot_as_revoking(capability_space, target_slot_index);
    let descendant_count =
        walk_and_zero_descendants(capability_space, derivation_tree, target_slot_index);
    zero_single_slot(capability_space, target_slot_index);
    derivation_tree.remove_record(target_slot_index);
    Ok(descendant_count.wrapping_add(1))
}

/// Returns Err(NullCapability) if the target slot is not Valid.
fn check_target_slot_is_valid(
    capability_space: &CapabilitySpace,
    target_slot_index: u8,
) -> Result<(), CapabilityError> {
    let slot = capability_space.lookup_slot_ref(target_slot_index);
    if !slot.is_valid() {
        return Err(CapabilityError::NullCapability);
    }
    Ok(())
}

/// Sets the target slot's state to Revoking (D-03 sentinel).
fn mark_slot_as_revoking(capability_space: &mut CapabilitySpace, slot_index: u8) {
    let slot = capability_space.lookup_slot_mut(slot_index);
    slot.state = CapabilitySlotState::Revoking;
}

/// Performs a depth-first walk of all descendants, zeroing each slot.
///
/// Returns the count of descendant slots zeroed (not counting the target).
/// Uses an explicit stack array bounded by MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS.
fn walk_and_zero_descendants(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    target_slot_index: u8,
) -> u32 {
    let mut depth_first_stack = [0u8; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS];
    let mut stack_depth: usize = 0;
    let mut revoked_count: u32 = 0;
    push_children_onto_stack(
        derivation_tree,
        target_slot_index,
        &mut depth_first_stack,
        &mut stack_depth,
    );
    while stack_depth > 0 {
        revoked_count = process_one_descendant(
            capability_space,
            derivation_tree,
            &mut depth_first_stack,
            &mut stack_depth,
            revoked_count,
        );
    }
    revoked_count
}

/// Pops one descendant from the stack, zeroes it, and pushes its children.
fn process_one_descendant(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    depth_first_stack: &mut [u8; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
    stack_depth: &mut usize,
    revoked_count: u32,
) -> u32 {
    let current_slot_index = pop_from_stack(depth_first_stack, stack_depth);
    push_children_onto_stack(
        derivation_tree,
        current_slot_index,
        depth_first_stack,
        stack_depth,
    );
    zero_single_slot(capability_space, current_slot_index);
    derivation_tree.remove_record(current_slot_index);
    revoked_count.wrapping_add(1)
}

/// Pushes all children of parent_slot_index onto the stack via sibling chain traversal.
fn push_children_onto_stack(
    derivation_tree: &CapabilityDerivationTree,
    parent_slot_index: u8,
    depth_first_stack: &mut [u8; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
    stack_depth: &mut usize,
) {
    let mut next_child = derivation_tree.first_child_of(parent_slot_index);
    while let Some(child_index) = next_child {
        push_onto_stack(depth_first_stack, stack_depth, child_index);
        next_child = derivation_tree.next_sibling_of(child_index);
    }
}

/// Pushes a slot index onto the explicit stack if space permits.
fn push_onto_stack(
    depth_first_stack: &mut [u8; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
    stack_depth: &mut usize,
    slot_index: u8,
) {
    if *stack_depth < MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS {
        depth_first_stack[*stack_depth] = slot_index;
        *stack_depth = stack_depth.wrapping_add(1);
    }
}

/// Pops and returns the top slot index from the explicit stack.
fn pop_from_stack(
    depth_first_stack: &mut [u8; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
    stack_depth: &mut usize,
) -> u8 {
    *stack_depth = stack_depth.wrapping_sub(1);
    depth_first_stack[*stack_depth]
}

/// Zeroes a single capability slot via write_volatile through the memory module's safe wrapper.
///
/// The unsafe boundary is contained in memory::slot_zeroing — no unsafe here.
fn zero_single_slot(capability_space: &mut CapabilitySpace, slot_index: u8) {
    let slot_reference = capability_space.lookup_slot_mut(slot_index);
    zero_capability_slot_via_reference(slot_reference);
}
