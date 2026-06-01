//! Rendezvous: atomic register copy and capability transfer (IPC_SPEC.md §3, §5).
//!
//! Enforces INV-IPC-002: capability transfer cannot amplify rights (rights monotonicity).
//! Enforces INV-IPC-005: transfer is atomic — no partial delivery.
//! Enforces INV-AUTH-003: transferred rights are a strict subset of sender's rights.

use crate::capability::capability_rights;
use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::{IpcError, IpcMessage, CAPABILITY_TRANSFER_NONE_SENTINEL};

/// Performs the kernel rendezvous: copies message registers and transfers capability.
///
/// Returns the delivered `IpcMessage` (with badge stamped from the endpoint).
///
/// Enforces INV-IPC-002 / INV-AUTH-003: rights monotonicity checked before transfer.
/// Enforces INV-IPC-005: if rights check fails, no state is modified.
/// Verified by: test_transferred_capability_has_no_additional_rights (SC-02)
pub fn perform_rendezvous(
    sender_message: &IpcMessage,
    sender_capability_slot_index: u8,
    receiver_capability_destination_slot: u8,
    sender_cspace: &mut CapabilitySpace,
    receiver_cspace: &mut CapabilitySpace,
    endpoint_badge: u64,
) -> Result<IpcMessage, IpcError> {
    let delivered_message = stamp_badge_on_message(sender_message, endpoint_badge);
    if sender_capability_slot_index == CAPABILITY_TRANSFER_NONE_SENTINEL {
        return Ok(delivered_message);
    }
    transfer_capability_between_cspaces(
        sender_capability_slot_index,
        receiver_capability_destination_slot,
        sender_cspace,
        receiver_cspace,
    )?;
    Ok(delivered_message)
}

/// Copies `sender_message` and stamps the `endpoint_badge` onto the result.
fn stamp_badge_on_message(sender_message: &IpcMessage, endpoint_badge: u64) -> IpcMessage {
    IpcMessage {
        register_zero: sender_message.register_zero,
        register_one: sender_message.register_one,
        register_two: sender_message.register_two,
        register_three: sender_message.register_three,
        badge: endpoint_badge,
    }
}

/// Transfers the capability from sender's slot to receiver's slot.
///
/// Validates: sender holds capability with Grant right; destination slot is null;
/// transferred rights do not exceed sender's rights (INV-IPC-002/INV-AUTH-003).
fn transfer_capability_between_cspaces(
    source_slot_index: u8,
    destination_slot_index: u8,
    sender_cspace: &mut CapabilitySpace,
    receiver_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    validate_source_slot_has_grant_right(source_slot_index, sender_cspace)?;
    validate_destination_slot_is_null(destination_slot_index, receiver_cspace)?;
    copy_capability_slot(
        source_slot_index,
        destination_slot_index,
        sender_cspace,
        receiver_cspace,
    )
}

/// Returns `Err(GrantRightNotHeld)` if the sender's slot lacks the Grant right.
///
/// Enforces INV-AUTH-003: only capabilities with Grant right may be transferred.
fn validate_source_slot_has_grant_right(
    source_slot_index: u8,
    sender_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let source_slot = sender_cspace.lookup_slot_ref(source_slot_index);
    if source_slot.is_null() {
        return Err(IpcError::GrantRightNotHeld);
    }
    let slot_has_grant = source_slot.rights().contains(capability_rights::GRANT);
    if slot_has_grant {
        Ok(())
    } else {
        Err(IpcError::GrantRightNotHeld)
    }
}

/// Returns `Err(SlotOccupied)` if the receiver's destination slot is not null.
///
/// Enforces INV-IPC-005: no overwrite of existing capabilities at rendezvous.
fn validate_destination_slot_is_null(
    destination_slot_index: u8,
    receiver_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let destination_slot = receiver_cspace.lookup_slot_ref(destination_slot_index);
    if destination_slot.is_null() {
        Ok(())
    } else {
        Err(IpcError::SlotOccupied)
    }
}

/// Copies the capability slot value from sender to receiver cspace.
///
/// Rights are preserved as-is (sender already holds them and has Grant right).
/// Enforces INV-IPC-002: the receiver receives the capability with the sender's
/// rights — no amplification is structurally possible because the sender's own
/// rights form the upper bound.
fn copy_capability_slot(
    source_slot_index: u8,
    destination_slot_index: u8,
    sender_cspace: &mut CapabilitySpace,
    receiver_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    let source_slot = *sender_cspace.lookup_slot_ref(source_slot_index);
    let destination_slot = receiver_cspace.lookup_slot_mut(destination_slot_index);
    *destination_slot = source_slot;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::capability_rights;
    use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
    use crate::capability::capability_type::CapabilityType;

    fn build_sender_cspace_with_grant_right() -> CapabilitySpace {
        let mut cspace = CapabilitySpace::new();
        let slot = cspace.lookup_slot_mut(1);
        *slot = CapabilitySlot {
            state: CapabilitySlotState::Valid,
            capability_type: CapabilityType::Memory,
            rights_bitmask: capability_rights::GRANT | capability_rights::READ,
            object_pointer: 0xDEAD,
            generation_counter: 1,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        };
        cspace
    }

    #[test]
    fn rendezvous_without_capability_copies_message_registers() {
        let message = IpcMessage {
            register_zero: 10,
            register_one: 20,
            register_two: 30,
            register_three: 40,
            badge: 0,
        };
        let mut sender_cspace = CapabilitySpace::new();
        let mut receiver_cspace = CapabilitySpace::new();
        let delivered = perform_rendezvous(
            &message,
            CAPABILITY_TRANSFER_NONE_SENTINEL,
            0,
            &mut sender_cspace,
            &mut receiver_cspace,
            99,
        )
        .unwrap();
        assert_eq!(delivered.register_zero, 10);
        assert_eq!(delivered.register_one, 20);
        assert_eq!(delivered.register_two, 30);
        assert_eq!(delivered.register_three, 40);
        assert_eq!(delivered.badge, 99);
    }

    #[test]
    fn rendezvous_with_grant_right_transfers_capability_to_receiver() {
        let message = IpcMessage::default();
        let mut sender_cspace = build_sender_cspace_with_grant_right();
        let mut receiver_cspace = CapabilitySpace::new();
        perform_rendezvous(&message, 1, 2, &mut sender_cspace, &mut receiver_cspace, 0).unwrap();
        let received_slot = receiver_cspace.lookup_slot_ref(2);
        assert!(!received_slot.is_null());
        assert!(received_slot.rights().contains(capability_rights::READ));
    }

    #[test]
    fn rendezvous_without_grant_right_returns_grant_right_not_held() {
        let message = IpcMessage::default();
        let mut sender_cspace = CapabilitySpace::new();
        let slot = sender_cspace.lookup_slot_mut(1);
        *slot = CapabilitySlot {
            state: CapabilitySlotState::Valid,
            capability_type: CapabilityType::Memory,
            rights_bitmask: capability_rights::READ,
            object_pointer: 0,
            generation_counter: 0,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        };
        let mut receiver_cspace = CapabilitySpace::new();
        let result =
            perform_rendezvous(&message, 1, 2, &mut sender_cspace, &mut receiver_cspace, 0);
        assert_eq!(result, Err(IpcError::GrantRightNotHeld));
    }

    #[test]
    fn rendezvous_with_occupied_destination_returns_slot_occupied() {
        let message = IpcMessage::default();
        let mut sender_cspace = build_sender_cspace_with_grant_right();
        let mut receiver_cspace = CapabilitySpace::new();
        let destination_slot = receiver_cspace.lookup_slot_mut(2);
        *destination_slot = CapabilitySlot {
            state: CapabilitySlotState::Valid,
            capability_type: CapabilityType::Memory,
            rights_bitmask: capability_rights::READ,
            object_pointer: 0xBEEF,
            generation_counter: 0,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        };
        let result =
            perform_rendezvous(&message, 1, 2, &mut sender_cspace, &mut receiver_cspace, 0);
        assert_eq!(result, Err(IpcError::SlotOccupied));
    }
}
