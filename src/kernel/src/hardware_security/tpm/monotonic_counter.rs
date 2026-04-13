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

#[cfg(test)]
mod tests {
    /// SC-05: binary counter < stored counter causes boot halt (rollback rejection).
    ///
    /// Phase 6 Plan 05 replaces this stub with the real test.
    #[test]
    #[ignore = "Phase 6 Plan 05 implements this test"]
    fn test_lower_monotonic_counter_is_rejected_on_boot() {
        // SC-05: binary_counter < stored_counter causes boot halt
    }
}
