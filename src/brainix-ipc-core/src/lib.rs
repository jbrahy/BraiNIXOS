//! IPC path formal verification shim for Prusti (D-07, D-08).
//!
//! This crate compiles on the host target (not bare-metal). The Prusti
//! verifier checks the three annotated functions against their
//! #[requires]/#[ensures] specifications.
//!
//! Properties verified:
//! 1. Rights monotonicity (INV-IPC-002, INV-AUTH-003)
//! 2. Timeout rollback completeness (INV-IPC-003)
//! 3. Message register index bounds [0, 3] (INV-IPC-005)

#![deny(unsafe_code)]
// prusti cfg is set by the Prusti verifier's Docker image (D-08), not by cargo.
// Suppress the unexpected_cfg lint so normal builds are warning-free.
#![allow(unexpected_cfgs)]

// Prusti annotations are activated by the Prusti verifier setting cfg(prusti).
// Normal cargo builds do not set this cfg; the Prusti Docker image sets it.
#[cfg(prusti)]
use prusti_contracts::*;

/// IPC errors used in Prusti specifications.
///
/// Mirrors IpcError in the kernel ipc module; duplicated here so
/// brainix-ipc-core compiles without a bare-metal kernel dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcVerificationError {
    /// Transferred rights exceed sender's rights (rights amplification attempt).
    RightsExceedSender,
    /// Timeout fired before rendezvous; no state was modified.
    Timeout,
}

/// Number of message data registers (r8-r11, IPC_SPEC.md §3).
pub const MESSAGE_REGISTER_COUNT: usize = 4;

/// Verifies rights monotonicity for capability transfer (D-07 property 1).
///
/// Enforces INV-IPC-002 and INV-AUTH-003: the capability delivered to the
/// receiver cannot have rights not present in the sender's capability.
///
/// `sender_rights_bits`: bit mask of the sender's capability rights (max 0b1111).
/// `transferred_rights_bits`: bit mask of rights the sender wishes to grant.
///
/// Returns Ok(()) if the transfer is permitted.
/// Returns Err(IpcVerificationError::RightsExceedSender) if amplification detected.
///
/// Prusti property: result == Ok(()) implies (transferred_rights_bits & !sender_rights_bits) == 0
pub fn verify_rights_monotonicity(
    sender_rights_bits: u32,
    transferred_rights_bits: u32,
) -> Result<(), IpcVerificationError> {
    // Stub: Plan 05 (Prusti) implements the body and adds Prusti annotations.
    let _ = sender_rights_bits;
    let _ = transferred_rights_bits;
    Ok(())
}

/// Verifies timeout rollback completeness (D-07 property 2).
///
/// Enforces INV-IPC-003: on IpcError::Timeout, no capability transfer has
/// occurred and no partial message state persists in the receiver's registers.
///
/// `timed_out`: whether the timeout fired before rendezvous.
/// `capability_was_transferred`: whether capability transfer occurred.
/// `message_state_is_clean`: whether receiver message registers are zeroed.
///
/// Prusti property: timed_out implies (!capability_was_transferred && message_state_is_clean)
pub fn verify_timeout_rollback_completeness(
    timed_out: bool,
    capability_was_transferred: bool,
    message_state_is_clean: bool,
) -> Result<(), IpcVerificationError> {
    // Stub: Plan 05 (Prusti) implements the body and adds Prusti annotations.
    let _ = timed_out;
    let _ = capability_was_transferred;
    let _ = message_state_is_clean;
    Ok(())
}

/// Verifies message register index bounds (D-07 property 3).
///
/// Enforces INV-IPC-005: all register indices in the message copy path
/// are statically within [0, MESSAGE_REGISTER_COUNT - 1].
///
/// `register_index`: the index to validate before copying.
///
/// Prusti property: result == Ok(()) implies register_index < MESSAGE_REGISTER_COUNT
pub fn verify_register_index_is_in_bounds(
    register_index: usize,
) -> Result<(), IpcVerificationError> {
    // Stub: Plan 05 (Prusti) implements the body and adds Prusti annotations.
    let _ = register_index;
    Ok(())
}
