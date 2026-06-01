//! IPC path formal verification shim for Prusti (D-07, D-08).
//!
//! This crate compiles on the host target (not bare-metal). The Prusti
//! verifier checks the three annotated functions against their
//! #[requires]/#[ensures] specifications when run via viperproject/prusti-action.
//!
//! Properties verified:
//! 1. Rights monotonicity (INV-IPC-002, INV-AUTH-003): D-07 property 1
//! 2. Timeout rollback completeness (INV-IPC-003): D-07 property 2
//! 3. Message register index bounds (INV-IPC-005): D-07 property 3

#![deny(unsafe_code)]
// prusti cfg is set by the Prusti verifier's Docker image (D-08), not by cargo.
// Suppress the unexpected_cfg lint so normal builds are warning-free.
#![allow(unexpected_cfgs)]

// Prusti annotation imports are gated behind the "prusti" feature so that
// normal cargo build/test does not require the prusti-contracts crate.
#[cfg(feature = "prusti")]
use prusti_contracts::*;

/// IPC errors used in Prusti specifications.
///
/// Mirrors IpcError in the kernel ipc module; duplicated here so
/// brainix-ipc-core compiles without a bare-metal kernel dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcVerificationError {
    /// Transferred rights exceed sender's rights (rights amplification attempt).
    RightsExceedSender,
    /// Timeout fired before rendezvous; no capability or message state was modified.
    Timeout,
    /// Register index is outside the valid message register range [0, 3].
    RegisterIndexOutOfBounds,
}

/// Number of message data registers (r8-r11, IPC_SPEC.md §3).
///
/// Used as the exclusive upper bound for register index validation.
pub const MESSAGE_REGISTER_COUNT: usize = 4;

/// Pure helper: returns true if `child_bits` are a subset of `parent_bits`.
///
/// `child_bits & !parent_bits == 0` iff every set bit in child is also set in parent.
/// Marked #[pure] so Prusti can use it inside #[ensures] clauses.
#[cfg_attr(feature = "prusti", pure)]
pub fn rights_bits_are_subset(child_bits: u32, parent_bits: u32) -> bool {
    (child_bits & !parent_bits) == 0
}

/// Verifies rights monotonicity for capability transfer (D-07 property 1).
///
/// Enforces INV-IPC-002 and INV-AUTH-003: the capability delivered to the
/// receiver cannot have rights not present in the sender's capability.
///
/// Returns `Ok(())` if `transferred_rights_bits` is a subset of `sender_rights_bits`.
/// Returns `Err(IpcVerificationError::RightsExceedSender)` if amplification detected.
///
/// Prusti post-condition: result is Ok implies rights_bits_are_subset(transferred, sender)
#[cfg_attr(feature = "prusti", ensures(
    result == Ok(()) ==> rights_bits_are_subset(transferred_rights_bits, sender_rights_bits)
))]
pub fn verify_rights_monotonicity(
    sender_rights_bits: u32,
    transferred_rights_bits: u32,
) -> Result<(), IpcVerificationError> {
    if rights_bits_are_subset(transferred_rights_bits, sender_rights_bits) {
        Ok(())
    } else {
        Err(IpcVerificationError::RightsExceedSender)
    }
}

/// Pure helper: timeout implies no transfer and clean state.
///
/// Encodes the implication for use in Prusti ensures clause.
#[cfg_attr(feature = "prusti", pure)]
pub fn timeout_rollback_invariant_holds(
    timed_out: bool,
    capability_was_transferred: bool,
    message_state_is_clean: bool,
) -> bool {
    !timed_out || (!capability_was_transferred && message_state_is_clean)
}

/// Verifies timeout rollback completeness (D-07 property 2).
///
/// Enforces INV-IPC-003: on timeout, no capability transfer has occurred
/// and no partial message state persists in the receiver's registers.
///
/// Returns `Ok(())` if the rollback invariant holds.
/// Returns `Err(IpcVerificationError::Timeout)` if timeout fired with residual state.
///
/// Prusti post-condition: result is Ok implies timeout_rollback_invariant_holds(...)
#[cfg_attr(feature = "prusti", ensures(
    result == Ok(()) ==>
        timeout_rollback_invariant_holds(timed_out, capability_was_transferred, message_state_is_clean)
))]
pub fn verify_timeout_rollback_completeness(
    timed_out: bool,
    capability_was_transferred: bool,
    message_state_is_clean: bool,
) -> Result<(), IpcVerificationError> {
    if timeout_rollback_invariant_holds(
        timed_out,
        capability_was_transferred,
        message_state_is_clean,
    ) {
        Ok(())
    } else {
        Err(IpcVerificationError::Timeout)
    }
}

/// Verifies message register index bounds (D-07 property 3).
///
/// Enforces INV-IPC-005: all register indices in the message copy path
/// are within `[0, MESSAGE_REGISTER_COUNT - 1]`; no out-of-bounds access possible.
///
/// Returns `Ok(())` if `register_index` is a valid message register index.
/// Returns `Err(IpcVerificationError::RegisterIndexOutOfBounds)` otherwise.
///
/// Prusti post-condition: result is Ok implies register_index < MESSAGE_REGISTER_COUNT
#[cfg_attr(feature = "prusti", ensures(
    result == Ok(()) ==> register_index < MESSAGE_REGISTER_COUNT
))]
pub fn verify_register_index_is_in_bounds(
    register_index: usize,
) -> Result<(), IpcVerificationError> {
    if register_index < MESSAGE_REGISTER_COUNT {
        Ok(())
    } else {
        Err(IpcVerificationError::RegisterIndexOutOfBounds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_subset_passes_when_transferred_is_proper_subset() {
        // sender has Read+Write (0b0011), transferred is Read-only (0b0001) — subset
        let result = verify_rights_monotonicity(0b0011, 0b0001);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn rights_amplification_is_rejected() {
        // sender has Read (0b0001), transferred is Read+Write (0b0011) — amplification
        let result = verify_rights_monotonicity(0b0001, 0b0011);
        assert_eq!(result, Err(IpcVerificationError::RightsExceedSender));
    }

    #[test]
    fn timeout_rollback_passes_when_no_state_was_modified() {
        let result = verify_timeout_rollback_completeness(true, false, true);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn timeout_rollback_fails_when_capability_was_transferred_despite_timeout() {
        let result = verify_timeout_rollback_completeness(true, true, true);
        assert_eq!(result, Err(IpcVerificationError::Timeout));
    }

    #[test]
    fn register_index_in_bounds_passes_for_all_valid_indices() {
        for valid_index in 0..MESSAGE_REGISTER_COUNT {
            assert_eq!(verify_register_index_is_in_bounds(valid_index), Ok(()));
        }
    }

    #[test]
    fn register_index_out_of_bounds_fails() {
        let result = verify_register_index_is_in_bounds(MESSAGE_REGISTER_COUNT);
        assert_eq!(result, Err(IpcVerificationError::RegisterIndexOutOfBounds));
    }
}
