//! Ed25519 binary signing verification and dev/prod key separation.
//!
//! Phase 6 Plan 06: Verifies kernel binary Ed25519 signatures at boot.
//! The production signing key is structurally separate from the development signing key;
//! the production verifier rejects binaries signed with the dev key (D-18).
//! The DEV_BUILD marker (a compile-time constant in a dedicated read-only section) is
//! checked at boot: the production boot verifier rejects any binary containing the
//! DEV_BUILD marker, even if the Ed25519 signature is valid (D-19).
//!
//! Uses the `ed25519-dalek` crate (no_std, verify-only in kernel) for signature
//! verification. Signing occurs offline via the build toolchain, never in the kernel.

#[cfg(test)]
mod tests {
    /// SC-04: DEV_BUILD marker is structurally rejected by the production verifier.
    ///
    /// Phase 6 Plan 06 replaces this stub with the real test.
    #[test]
    #[ignore = "Phase 6 Plan 06 implements this test"]
    fn test_dev_build_marker_is_refused_by_production_signature_check() {
        // SC-04: DEV_BUILD marker structurally rejected by production verifier
    }
}
