//! Ed25519 binary signing verification and dev/prod key separation.
//!
//! Phase 6 Plan 06: Verifies kernel binary Ed25519 signatures at boot.
//! The production signing key is structurally separate from the development signing key;
//! the production verifier rejects binaries signed with the dev key (D-18).
//! The DEV_BUILD marker (a compile-time constant) is checked at boot: the production
//! boot verifier rejects any binary containing the DEV_BUILD marker, even if the
//! Ed25519 signature is valid (D-19).
//!
//! Uses `ed25519-dalek` (no_std, verify-only in kernel) for signature verification.
//! Signing occurs offline via the build toolchain, never in the kernel.
//!
//! Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
//! Verified by: test_dev_build_marker_is_refused_by_production_signature_check

use ed25519_dalek::ed25519::signature::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};

/// Compile-time marker distinguishing development and production builds.
///
/// Per D-19 and RELEASE_AND_SIGNING_POLICY.md Section 6:
/// - Development: cargo build --features dev-build
/// - Production: cargo build (default, no dev-build feature)
///
/// Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
#[cfg(feature = "dev-build")]
pub const IS_DEVELOPMENT_BUILD: bool = true;

#[cfg(not(feature = "dev-build"))]
pub const IS_DEVELOPMENT_BUILD: bool = false;

/// Errors that can occur during binary signature verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureVerificationError {
    /// The Ed25519 signature does not verify against the provided key and hash.
    InvalidSignature,
    /// A development-build marker is present in a binary being verified by the production path.
    ///
    /// Per D-19: production verifier rejects any binary with DEV_BUILD marker present.
    DevelopmentMarkerInProductionBuild,
    /// The public key is not valid for the current build environment.
    WrongKeyEnvironment,
}

/// Development public key for unit testing (32 bytes). NOT a real key -- test use only.
///
/// This is a valid Ed25519 public key for the test signing key pair embedded below.
/// Key pair generated deterministically for testing: seed = [1u8; 32].
const TEST_DEVELOPMENT_PUBLIC_KEY: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// Production public key for unit testing (32 bytes). NOT a real key -- test use only.
///
/// Distinct from the development key to verify structural separation.
/// Key pair generated deterministically for testing: seed = [2u8; 32].
const TEST_PRODUCTION_PUBLIC_KEY: [u8; 32] = [
    0x3b, 0x6a, 0x27, 0xbc, 0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d, 0x73,
    0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1, 0x8b, 0x59, 0xda, 0x29,
];

/// Select the verification key set for the given build environment.
///
/// Returns the development public key when `is_development_build` is true,
/// and the production public key when false. No fallback, no override.
///
/// Per RELEASE_AND_SIGNING_POLICY.md Section 3: no runtime switch exists.
/// Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
pub fn select_verification_key_set(is_development_build: bool) -> &'static [u8; 32] {
    if is_development_build {
        &TEST_DEVELOPMENT_PUBLIC_KEY
    } else {
        &TEST_PRODUCTION_PUBLIC_KEY
    }
}

/// Verify an Ed25519 signature over a binary hash against the given public key.
///
/// Returns `Ok(())` if the signature is valid for the given public key and hash.
/// Returns `Err(InvalidSignature)` if the signature does not verify.
///
/// Per D-18: all Brainix kernel binaries are signed with Ed25519.
/// Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
pub fn verify_binary_signature(
    binary_hash: &[u8; 32],
    signature_bytes: &[u8; 64],
    public_key_bytes: &[u8; 32],
) -> Result<(), SignatureVerificationError> {
    let verifying_key = build_verifying_key(public_key_bytes)?;
    let signature = build_signature(signature_bytes)?;
    verify_signature_against_key(&verifying_key, binary_hash, &signature)
}

/// Build a VerifyingKey from raw public key bytes.
fn build_verifying_key(
    public_key_bytes: &[u8; 32],
) -> Result<VerifyingKey, SignatureVerificationError> {
    VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| SignatureVerificationError::InvalidSignature)
}

/// Build a Signature from raw signature bytes.
fn build_signature(signature_bytes: &[u8; 64]) -> Result<Signature, SignatureVerificationError> {
    Ok(Signature::from_bytes(signature_bytes))
}

/// Verify the signature over the binary hash using the given key.
fn verify_signature_against_key(
    verifying_key: &VerifyingKey,
    binary_hash: &[u8; 32],
    signature: &Signature,
) -> Result<(), SignatureVerificationError> {
    verifying_key
        .verify(binary_hash, signature)
        .map_err(|_| SignatureVerificationError::InvalidSignature)
}

/// Reject a binary with a development-build marker in a production context.
///
/// Per D-19: the production verifier rejects any binary containing the DEV_BUILD
/// marker, even if the Ed25519 signature is valid.
///
/// Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
/// Verified by: test_dev_build_marker_is_refused_by_production_signature_check
pub fn reject_binary_with_development_marker(
    is_development_build: bool,
    binary_contains_development_marker: bool,
) -> Result<(), SignatureVerificationError> {
    if !is_development_build && binary_contains_development_marker {
        return Err(SignatureVerificationError::DevelopmentMarkerInProductionBuild);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-04: DEV_BUILD marker is structurally rejected by the production verifier.
    ///
    /// Enforces INV-BOOT-003: dev and prod cryptographic material remain separate.
    #[test]
    fn test_dev_build_marker_is_refused_by_production_signature_check() {
        // Production build + dev marker = reject
        let production_rejects_development_marker =
            reject_binary_with_development_marker(false, true);
        assert_eq!(
            production_rejects_development_marker,
            Err(SignatureVerificationError::DevelopmentMarkerInProductionBuild),
            "production verifier must reject binary with dev marker"
        );

        // Development build + dev marker = accept
        let development_accepts_development_marker =
            reject_binary_with_development_marker(true, true);
        assert!(
            development_accepts_development_marker.is_ok(),
            "dev build must accept binary with dev marker"
        );

        // Production build + no marker = accept
        let production_accepts_clean_binary = reject_binary_with_development_marker(false, false);
        assert!(
            production_accepts_clean_binary.is_ok(),
            "production verifier must accept binary without dev marker"
        );
    }

    /// Development builds use the development key set, not the production key set.
    #[test]
    fn test_select_verification_key_set_returns_development_key_for_dev_build() {
        let selected_key = select_verification_key_set(true);
        assert_eq!(
            selected_key, &TEST_DEVELOPMENT_PUBLIC_KEY,
            "dev build must use development key"
        );
    }

    /// Production builds use the production key set, not the development key set.
    #[test]
    fn test_select_verification_key_set_returns_production_key_for_production_build() {
        let selected_key = select_verification_key_set(false);
        assert_eq!(
            selected_key, &TEST_PRODUCTION_PUBLIC_KEY,
            "production build must use production key"
        );
    }

    /// Development and production key sets are structurally distinct.
    #[test]
    fn test_development_and_production_key_sets_are_distinct() {
        assert_ne!(
            TEST_DEVELOPMENT_PUBLIC_KEY, TEST_PRODUCTION_PUBLIC_KEY,
            "development and production keys must be different"
        );
    }

    /// verify_binary_signature returns Err for an invalid signature.
    #[test]
    fn test_verify_binary_signature_rejects_invalid_signature() {
        let binary_hash = [0u8; 32];
        let invalid_signature = [0u8; 64];
        let public_key = TEST_DEVELOPMENT_PUBLIC_KEY;
        let result = verify_binary_signature(&binary_hash, &invalid_signature, &public_key);
        assert_eq!(
            result,
            Err(SignatureVerificationError::InvalidSignature),
            "invalid signature must be rejected"
        );
    }

    /// reject_binary_with_development_marker accepts dev build with no marker.
    #[test]
    fn test_reject_binary_with_development_marker_accepts_dev_build_without_marker() {
        let result = reject_binary_with_development_marker(true, false);
        assert!(result.is_ok(), "dev build without marker must be accepted");
    }
}
