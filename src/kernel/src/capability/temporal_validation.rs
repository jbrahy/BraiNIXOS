//! Temporal capability validation gate.
//!
//! Implements the single validation gate called before every capability operation.
//! Checks use-count and time-window bounds, zeroing the slot on expiry.
//!
//! Enforces INV-AUTH-004: temporal expiry is a form of revocation.
//! See tick_source.rs for the tick abstraction design decision (D-11).

use crate::capability::capability_error::CapabilityError;
use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::derivation_tree::CapabilityDerivationTree;
use crate::capability::revocation::revoke_capability;

/// Validates a capability slot for use, checking temporal bounds.
///
/// Called before every capability operation. Checks:
/// 1. Slot is not Null (returns NullCapability)
/// 2. Slot is not Revoking (returns NullCapability — defensive, per D-03)
/// 3. Use count not exhausted (returns CapabilityExpired, zeros slot)
/// 4. Time window not expired (returns CapabilityExpired, zeros slot)
/// 5. On success: decrements use_count_remaining if Some
///
/// Enforces INV-AUTH-004: temporal expiry is a form of revocation.
/// Verified by: tests::test_temporal_capability_expires_after_use_count_is_reached
pub fn validate_capability(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    slot_index: u8,
    current_tick: u64,
) -> Result<(), CapabilityError> {
    let slot = capability_space.lookup_slot_ref(slot_index);
    check_slot_is_not_null(slot)?;
    check_slot_is_not_revoking(slot)?;
    let use_count_result = check_use_count_not_exhausted(slot);
    if use_count_result.is_err() {
        return Err(expire_and_zero_slot(
            capability_space,
            derivation_tree,
            slot_index,
        ));
    }
    let time_window_result = check_time_window_not_expired(slot, current_tick);
    if time_window_result.is_err() {
        return Err(expire_and_zero_slot(
            capability_space,
            derivation_tree,
            slot_index,
        ));
    }
    decrement_use_count_if_limited(capability_space.lookup_slot_mut(slot_index));
    Ok(())
}

/// Returns Err(NullCapability) if the slot state is Null.
fn check_slot_is_not_null(slot: &CapabilitySlot) -> Result<(), CapabilityError> {
    if slot.state == CapabilitySlotState::Null {
        return Err(CapabilityError::NullCapability);
    }
    Ok(())
}

/// Returns Err(NullCapability) if the slot state is Revoking (D-03 defensive check).
fn check_slot_is_not_revoking(slot: &CapabilitySlot) -> Result<(), CapabilityError> {
    if slot.state == CapabilitySlotState::Revoking {
        return Err(CapabilityError::NullCapability);
    }
    Ok(())
}

/// Returns Err(CapabilityExpired) if use_count_remaining is Some(0).
fn check_use_count_not_exhausted(slot: &CapabilitySlot) -> Result<(), CapabilityError> {
    if slot.use_count_remaining == Some(0) {
        return Err(CapabilityError::CapabilityExpired);
    }
    Ok(())
}

/// Returns Err(CapabilityExpired) if expiry_tick is Some(t) and current_tick >= t.
fn check_time_window_not_expired(
    slot: &CapabilitySlot,
    current_tick: u64,
) -> Result<(), CapabilityError> {
    if let Some(expiry_tick) = slot.expiry_tick {
        if current_tick >= expiry_tick {
            return Err(CapabilityError::CapabilityExpired);
        }
    }
    Ok(())
}

/// Decrements use_count_remaining if it is Some(n) where n > 0.
///
/// n > 0 is guaranteed by the prior check_use_count_not_exhausted call.
fn decrement_use_count_if_limited(slot: &mut CapabilitySlot) {
    if let Some(remaining_count) = slot.use_count_remaining {
        #[allow(clippy::arithmetic_side_effects)]
        // n > 0 checked by prior validation step (check_use_count_not_exhausted)
        {
            slot.use_count_remaining = Some(remaining_count - 1);
        }
    }
}

/// Expires and zeroes a slot by invoking revoke_capability, then returns CapabilityExpired.
///
/// Cascades revocation to children before zeroing the slot itself.
/// Returns CapabilityExpired regardless of whether revocation counted descendants.
fn expire_and_zero_slot(
    capability_space: &mut CapabilitySpace,
    derivation_tree: &mut CapabilityDerivationTree,
    slot_index: u8,
) -> CapabilityError {
    let _ = revoke_capability(capability_space, derivation_tree, slot_index);
    CapabilityError::CapabilityExpired
}
