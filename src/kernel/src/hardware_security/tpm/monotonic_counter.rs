//! TPM monotonic counter for kernel binary rollback protection.
//!
//! Phase 6 Plan 05: Reads the monotonic counter stored in a dedicated TPM NV index
//! (provisioned at first boot). Verifies that the current binary's embedded counter
//! value is >= the stored counter value. Increments the stored counter after successful
//! verification. A binary with a lower counter value than the stored value causes a
//! fatal boot halt at the attestation gate (D-21).
//!
//! The NV index is provisioned via the swtpm flow for development and via TPM2_NV_DefineSpace
//! for production hardware. No fallback to unprotected boot exists.
//!
//! Enforces invariant INV-BOOT-001 (measured boot path integrity).
//! Verified by: test_lower_monotonic_counter_is_rejected_on_boot

use super::registers::TpmError;

/// TPM NV index for the Brainix monotonic rollback-protection counter.
pub const BRAINIX_MONOTONIC_COUNTER_NV_INDEX: u32 = 0x0150_0001;

/// Errors that can occur during monotonic counter verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MonotonicCounterError {
    /// Binary counter is lower than stored counter: rollback detected, boot must halt.
    RollbackDetected {
        /// The counter value embedded in the current binary.
        binary_value: u64,
        /// The counter value stored in TPM NV.
        stored_value: u64,
    },
    /// TPM NV_Read command failed.
    TpmReadFailed(TpmError),
    /// TPM NV_Increment command failed.
    TpmIncrementFailed(TpmError),
}

/// Verify the binary counter against the stored TPM counter and increment on success.
///
/// Reads the current counter from TPM NV, checks that `binary_counter_value` is
/// not less than the stored value, then increments the stored counter.
/// Returns `Err(RollbackDetected)` if rollback is detected — caller must halt.
///
/// Enforces invariant INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_lower_monotonic_counter_is_rejected_on_boot
pub fn verify_and_update_monotonic_counter(
    binary_counter_value: u64,
) -> Result<(), MonotonicCounterError> {
    let stored_counter_value = read_stored_counter_from_tpm()?;
    check_for_rollback(binary_counter_value, stored_counter_value)?;
    increment_stored_counter_in_tpm()
}

/// Read the current monotonic counter value from TPM NV storage.
fn read_stored_counter_from_tpm() -> Result<u64, MonotonicCounterError> {
    super::commands::read_monotonic_counter_from_nv(BRAINIX_MONOTONIC_COUNTER_NV_INDEX)
        .map_err(MonotonicCounterError::TpmReadFailed)
}

/// Return an error if binary_value is less than stored_value (rollback detected).
fn check_for_rollback(
    binary_value: u64,
    stored_value: u64,
) -> Result<(), MonotonicCounterError> {
    if should_reject_rollback(binary_value, stored_value) {
        return Err(MonotonicCounterError::RollbackDetected { binary_value, stored_value });
    }
    Ok(())
}

/// Increment the stored monotonic counter in TPM NV.
fn increment_stored_counter_in_tpm() -> Result<(), MonotonicCounterError> {
    super::commands::increment_monotonic_counter_in_nv(BRAINIX_MONOTONIC_COUNTER_NV_INDEX)
        .map_err(MonotonicCounterError::TpmIncrementFailed)
}

/// Pure rollback-rejection predicate: returns true when boot must be rejected.
///
/// Returns `true` when `binary_counter_value < stored_counter_value` (rollback).
/// Returns `false` when binary value equals or exceeds stored value (boot allowed).
///
/// This pure function is separately testable without TPM hardware.
///
/// Enforces invariant INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_lower_monotonic_counter_is_rejected_on_boot
pub fn should_reject_rollback(binary_counter_value: u64, stored_counter_value: u64) -> bool {
    binary_counter_value < stored_counter_value
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-05: binary counter < stored counter causes boot halt (rollback rejection).
    ///
    /// Tests the pure rollback logic: should_reject_rollback covers all comparison cases.
    #[test]
    fn test_lower_monotonic_counter_is_rejected_on_boot() {
        assert!(
            should_reject_rollback(3, 5),
            "binary 3 < stored 5: must reject (rollback detected)"
        );
        assert!(
            !should_reject_rollback(5, 5),
            "binary 5 == stored 5: must accept (equal is not rollback)"
        );
        assert!(
            !should_reject_rollback(7, 5),
            "binary 7 > stored 5: must accept (higher counter is valid)"
        );
        assert!(
            !should_reject_rollback(0, 0),
            "binary 0 == stored 0: must accept (first boot)"
        );
    }

    /// Rollback rejection is strict: any binary value below stored value is rejected.
    #[test]
    fn test_should_reject_rollback_rejects_any_lower_binary_value() {
        assert!(should_reject_rollback(0, 1));
        assert!(should_reject_rollback(99, 100));
        assert!(should_reject_rollback(u64::MAX.saturating_sub(1), u64::MAX));
    }

    /// Rollback rejection allows equal or higher binary values.
    #[test]
    fn test_should_reject_rollback_accepts_equal_or_higher_binary_value() {
        assert!(!should_reject_rollback(1, 0));
        assert!(!should_reject_rollback(100, 99));
        assert!(!should_reject_rollback(u64::MAX, u64::MAX));
    }

    /// MonotonicCounterError::RollbackDetected carries both values for diagnostics.
    #[test]
    fn test_rollback_detected_error_carries_binary_and_stored_values() {
        let error = MonotonicCounterError::RollbackDetected {
            binary_value: 3,
            stored_value: 5,
        };
        match error {
            MonotonicCounterError::RollbackDetected { binary_value, stored_value } => {
                assert_eq!(binary_value, 3);
                assert_eq!(stored_value, 5);
            }
            _ => panic!("expected RollbackDetected variant"),
        }
    }

    /// BRAINIX_MONOTONIC_COUNTER_NV_INDEX has the expected NV index value.
    #[test]
    fn test_brainix_monotonic_counter_nv_index_constant_is_correct() {
        assert_eq!(BRAINIX_MONOTONIC_COUNTER_NV_INDEX, 0x0150_0001u32);
    }

    /// verify_and_update_monotonic_counter succeeds on host target (mock TPM returns 0).
    #[test]
    fn test_verify_and_update_monotonic_counter_succeeds_on_host_with_zero_binary_value() {
        let result = verify_and_update_monotonic_counter(0);
        assert!(result.is_ok(), "must succeed when binary_value >= stored (0 >= 0)");
    }
}
