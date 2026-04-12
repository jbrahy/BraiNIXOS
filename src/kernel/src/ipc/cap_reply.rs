//! CapReply creation, validation, and single-use zeroing (IPC_SPEC.md §6).
//!
//! CapReply is kernel-created on SYS_IPC_RECEIVE when a SYS_IPC_CALL is waiting.
//! It is placed at CAPABILITY_REPLY_DESIGNATED_SLOT (255) in the server's CSpace.
//! It is consumed on use: the slot is zeroed via volatile write, enforcing single-use.
//!
//! Enforces INV-AUTH-005: CapReply is kernel-created, unforgeable.
//! Enforces INV-AUTH-006: CapReply is single-use, non-copyable structurally.

use crate::capability::capability_slot::CapabilitySlot;
use crate::capability::capability_type::CapabilityType;
use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::{IpcError, CAPABILITY_REPLY_DESIGNATED_SLOT};
use crate::memory::slot_zeroing::zero_capability_slot_via_reference;

/// Installs a kernel-created CapReply into the server's CSpace designated slot.
///
/// `caller_thread_identifier` identifies the blocked caller for reply routing.
///
/// Returns `Err(IpcError::ReplySlotOccupied)` if slot 255 is not null.
/// Enforces INV-AUTH-005: CapReply is created by kernel, placed directly.
/// Verified by: test_reply_capability_is_single_use (SC-04)
pub fn install_cap_reply_in_server_cspace(
    server_cspace: &mut CapabilitySpace,
    caller_thread_identifier: u32,
) -> Result<(), IpcError> {
    validate_reply_slot_is_empty(server_cspace)?;
    write_cap_reply_slot(server_cspace, caller_thread_identifier);
    Ok(())
}

/// Returns `Err(IpcError::ReplySlotOccupied)` if the designated slot is not null.
fn validate_reply_slot_is_empty(server_cspace: &CapabilitySpace) -> Result<(), IpcError> {
    let reply_slot = server_cspace.lookup_slot_ref(CAPABILITY_REPLY_DESIGNATED_SLOT);
    if reply_slot.is_null() { Ok(()) } else { Err(IpcError::ReplySlotOccupied) }
}

/// Writes a CapReply slot into the designated slot of `server_cspace`.
fn write_cap_reply_slot(server_cspace: &mut CapabilitySpace, caller_thread_identifier: u32) {
    let reply_slot = CapabilitySlot::new_cap_reply(caller_thread_identifier);
    let destination = server_cspace.lookup_slot_mut(CAPABILITY_REPLY_DESIGNATED_SLOT);
    *destination = reply_slot;
}

/// Consumes the CapReply by zeroing the designated slot.
///
/// Returns `Err(IpcError::ReplyCapabilityAlreadyUsed)` if slot 255 is already null
/// (CapReply was already consumed or was never installed).
///
/// Enforces INV-AUTH-006: CapReply is single-use.
/// Verified by: test_reply_capability_is_single_use (SC-04)
pub fn consume_cap_reply_and_zero_slot(
    server_cspace: &mut CapabilitySpace,
) -> Result<(), IpcError> {
    validate_reply_slot_has_cap_reply(server_cspace)?;
    perform_volatile_zero_of_reply_slot(server_cspace);
    Ok(())
}

/// Returns `Err(IpcError::ReplyCapabilityAlreadyUsed)` if slot is null or not Reply type.
fn validate_reply_slot_has_cap_reply(server_cspace: &CapabilitySpace) -> Result<(), IpcError> {
    let reply_slot = server_cspace.lookup_slot_ref(CAPABILITY_REPLY_DESIGNATED_SLOT);
    if reply_slot.is_null() {
        return Err(IpcError::ReplyCapabilityAlreadyUsed);
    }
    let is_reply_type = reply_slot.capability_type() == CapabilityType::Reply;
    if is_reply_type { Ok(()) } else { Err(IpcError::ReplyCapabilityAlreadyUsed) }
}

/// Zeroes the designated reply slot using volatile write (INV-AUTH-004).
fn perform_volatile_zero_of_reply_slot(server_cspace: &mut CapabilitySpace) {
    let reply_slot_mut = server_cspace.lookup_slot_mut(CAPABILITY_REPLY_DESIGNATED_SLOT);
    zero_capability_slot_via_reference(reply_slot_mut);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_cap_reply_places_slot_at_designated_index() {
        let mut server_cspace = CapabilitySpace::new();
        install_cap_reply_in_server_cspace(&mut server_cspace, 42).unwrap();
        let reply_slot = server_cspace.lookup_slot_ref(CAPABILITY_REPLY_DESIGNATED_SLOT);
        assert!(!reply_slot.is_null());
        assert_eq!(reply_slot.capability_type(), CapabilityType::Reply);
    }

    #[test]
    fn install_cap_reply_when_slot_occupied_returns_reply_slot_occupied() {
        let mut server_cspace = CapabilitySpace::new();
        install_cap_reply_in_server_cspace(&mut server_cspace, 1).unwrap();
        let result = install_cap_reply_in_server_cspace(&mut server_cspace, 2);
        assert_eq!(result, Err(IpcError::ReplySlotOccupied));
    }

    #[test]
    fn consume_cap_reply_zeroes_slot_and_returns_ok() {
        let mut server_cspace = CapabilitySpace::new();
        install_cap_reply_in_server_cspace(&mut server_cspace, 42).unwrap();
        let result = consume_cap_reply_and_zero_slot(&mut server_cspace);
        assert_eq!(result, Ok(()));
        let reply_slot = server_cspace.lookup_slot_ref(CAPABILITY_REPLY_DESIGNATED_SLOT);
        assert!(reply_slot.is_null());
    }

    #[test]
    fn consume_cap_reply_second_time_returns_already_used() {
        let mut server_cspace = CapabilitySpace::new();
        install_cap_reply_in_server_cspace(&mut server_cspace, 42).unwrap();
        consume_cap_reply_and_zero_slot(&mut server_cspace).unwrap();
        let result = consume_cap_reply_and_zero_slot(&mut server_cspace);
        assert_eq!(result, Err(IpcError::ReplyCapabilityAlreadyUsed));
    }
}
