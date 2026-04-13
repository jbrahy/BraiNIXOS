//! Kernel compile-time security configuration blob for PCR[1] measurement.
//!
//! Phase 6 Plan 04: Defines a fixed-size struct containing all security policy
//! constants: MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS, IPC timeout limits, partition
//! table policy, Spectre mitigation mode, TME enforcement flag, attestation timeout,
//! and all other compile-time security parameters (D-11).
//!
//! The blob is SHA-256 hashed and extended into TPM PCR[1] during boot. Any change
//! to a security policy constant changes the PCR[1] value even if the kernel binary
//! .text hash is unchanged, preventing silent policy rollback.
//!
//! Enforces INV-BOOT-001: production security claims require measured boot path.
#![allow(unsafe_code)]

use sha2::{Digest, Sha256};

/// Compile-time security policy constants measured into PCR[1].
///
/// Per D-11: any change to any security policy constant changes the PCR value.
/// `#[repr(C)]` ensures deterministic memory layout for consistent hashing.
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
/// Verified by: tests::test_config_blob_hash_is_deterministic
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KernelSecurityConfigBlob {
    /// Maximum number of capability slots per process (256 per design).
    pub maximum_capability_slots_per_process: u16,
    /// Maximum IPC timeout in scheduler ticks before caller returns Timeout.
    pub ipc_timeout_maximum_ticks: u64,
    /// Number of partition slots in the compile-time partition table.
    pub partition_slot_count: u16,
    /// Spectre v2 mitigation mode: 0 = retpoline+IBRS, 1 = eIBRS.
    pub spectre_v2_mitigation_mode: u8,
    /// Spectre v1 LFENCE barriers applied: always 1 (D-02 applies at compile time).
    pub spectre_v1_lfence_barriers_applied: u8,
    /// Memory encryption enforcement: 0 = warning (dev), 1 = fatal (production).
    pub memory_encryption_enforcement_mode: u8,
    /// Attestation gate timeout in seconds before gate fails (60 per D-22).
    pub attestation_gate_timeout_seconds: u16,
    /// IOMMU enforcement: 0 = warning (dev), 1 = fatal (production).
    pub iommu_enforcement_mode: u8,
    /// Indirect Branch Tracking enabled: 0 = no, 1 = yes.
    pub indirect_branch_tracking_enabled: u8,
    /// Monotonic counter enforcement enabled: 1 = yes.
    pub monotonic_counter_enforcement_enabled: u8,
    /// Development build marker: 0 = production, 1 = development.
    pub development_build_marker_present: u8,
}

/// Compile-time constant for maximum capability slots per process.
const MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS_VALUE: u16 = 256;

/// Compile-time constant for the maximum IPC timeout ticks.
const IPC_TIMEOUT_MAXIMUM_TICKS_VALUE: u64 = 10_000;

/// Compile-time constant for partition slot count.
const PARTITION_SLOT_COUNT_VALUE: u16 = 3;

/// Compile-time constant for attestation gate timeout in seconds.
const ATTESTATION_GATE_TIMEOUT_SECONDS_VALUE: u16 = 60;

/// Creates a KernelSecurityConfigBlob with known compile-time constants.
///
/// Runtime-detected values are passed as parameters: spectre_mode from CPU detection,
/// memory_encryption_mode from TME/SME probe, ibt_enabled from CET probe, and
/// is_dev_build from compile-time DEV_BUILD constant.
///
/// Sets `spectre_v1_lfence_barriers_applied` to 1 always (D-02: LFENCE applied at
/// compile time regardless of CPU generation).
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
pub fn create_kernel_security_config_blob(
    spectre_mode: u8,
    memory_encryption_mode: u8,
    ibt_enabled: u8,
    is_dev_build: u8,
) -> KernelSecurityConfigBlob {
    KernelSecurityConfigBlob {
        maximum_capability_slots_per_process: MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS_VALUE,
        ipc_timeout_maximum_ticks: IPC_TIMEOUT_MAXIMUM_TICKS_VALUE,
        partition_slot_count: PARTITION_SLOT_COUNT_VALUE,
        spectre_v2_mitigation_mode: spectre_mode,
        spectre_v1_lfence_barriers_applied: 1,
        memory_encryption_enforcement_mode: memory_encryption_mode,
        attestation_gate_timeout_seconds: ATTESTATION_GATE_TIMEOUT_SECONDS_VALUE,
        iommu_enforcement_mode: memory_encryption_mode,
        indirect_branch_tracking_enabled: ibt_enabled,
        monotonic_counter_enforcement_enabled: 1,
        development_build_marker_present: is_dev_build,
    }
}

/// Converts a KernelSecurityConfigBlob reference to a byte slice for hashing.
///
/// # Safety
/// - `KernelSecurityConfigBlob` is `#[repr(C)]` with deterministic integer-only layout.
/// - Casting to a byte slice for read-only SHA-256 hashing is sound.
/// - Precondition: config_blob points to a valid, fully-initialized KernelSecurityConfigBlob.
/// - Invariant: INV-BOOT-001 (production security claims require measured boot).
/// - Evidence: test_config_blob_hash_is_deterministic
fn config_blob_as_byte_slice(config_blob: &KernelSecurityConfigBlob) -> &[u8] {
    let byte_count = core::mem::size_of::<KernelSecurityConfigBlob>();
    let byte_pointer = config_blob as *const KernelSecurityConfigBlob as *const u8;
    // SAFETY: KernelSecurityConfigBlob is #[repr(C)] with integer fields only.
    // - Precondition: config_blob is a valid, fully-initialized struct reference.
    // - Invariant: INV-BOOT-001 (measured boot integrity).
    // - Evidence: test_config_blob_hash_is_deterministic
    unsafe { core::slice::from_raw_parts(byte_pointer, byte_count) }
}

/// Computes the SHA-256 hash of a KernelSecurityConfigBlob.
///
/// Returns a 32-byte digest. Any change to any field changes the digest,
/// preventing silent security policy rollback (T-HW-PCR-02 mitigation).
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
/// Verified by: test_config_blob_hash_is_deterministic
pub fn compute_config_blob_hash(config_blob: &KernelSecurityConfigBlob) -> [u8; 32] {
    let blob_bytes = config_blob_as_byte_slice(config_blob);
    let mut hasher = Sha256::new();
    hasher.update(blob_bytes);
    let digest = hasher.finalize();
    digest.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a baseline config blob with known values for testing.
    fn build_test_config_blob() -> KernelSecurityConfigBlob {
        create_kernel_security_config_blob(0, 1, 1, 0)
    }

    /// Verifies SHA-256 of a known config blob returns a 32-byte result.
    #[test]
    fn test_config_blob_hash_returns_32_bytes() {
        let config_blob = build_test_config_blob();
        let hash = compute_config_blob_hash(&config_blob);
        assert_eq!(hash.len(), 32, "SHA-256 digest must be 32 bytes");
    }

    /// Verifies two calls with identical blob produce identical hash.
    ///
    /// Enforces INV-BOOT-001: deterministic hashing is required for attestation.
    #[test]
    fn test_config_blob_hash_is_deterministic() {
        let config_blob = build_test_config_blob();
        let first_hash = compute_config_blob_hash(&config_blob);
        let second_hash = compute_config_blob_hash(&config_blob);
        assert_eq!(first_hash, second_hash, "hash must be deterministic");
    }

    /// Verifies hash is non-zero (not returning uninitialized or zeroed memory).
    #[test]
    fn test_config_blob_hash_is_nonzero() {
        let config_blob = build_test_config_blob();
        let hash = compute_config_blob_hash(&config_blob);
        let all_zeros = [0u8; 32];
        assert_ne!(hash, all_zeros, "hash must not be all zeros");
    }

    /// Verifies changing spectre_v2_mitigation_mode changes the hash.
    ///
    /// Enforces T-HW-PCR-02 mitigation: any field change produces different hash.
    #[test]
    fn test_changing_spectre_mode_changes_hash() {
        let original_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let modified_blob = create_kernel_security_config_blob(1, 1, 1, 0);
        let original_hash = compute_config_blob_hash(&original_blob);
        let modified_hash = compute_config_blob_hash(&modified_blob);
        assert_ne!(original_hash, modified_hash, "spectre mode change must change hash");
    }

    /// Verifies changing memory_encryption_enforcement_mode changes the hash.
    #[test]
    fn test_changing_memory_encryption_mode_changes_hash() {
        let original_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let modified_blob = create_kernel_security_config_blob(0, 0, 1, 0);
        let original_hash = compute_config_blob_hash(&original_blob);
        let modified_hash = compute_config_blob_hash(&modified_blob);
        assert_ne!(original_hash, modified_hash, "encryption mode change must change hash");
    }

    /// Verifies spectre_v1_lfence_barriers_applied is always 1 (D-02).
    #[test]
    fn test_spectre_v1_lfence_barriers_applied_is_always_one() {
        let config_blob = build_test_config_blob();
        assert_eq!(
            config_blob.spectre_v1_lfence_barriers_applied, 1,
            "spectre v1 lfence barriers must always be applied (D-02)"
        );
    }

    /// Verifies changing dev build marker changes the hash.
    #[test]
    fn test_changing_dev_build_marker_changes_hash() {
        let production_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let development_blob = create_kernel_security_config_blob(0, 1, 1, 1);
        let production_hash = compute_config_blob_hash(&production_blob);
        let development_hash = compute_config_blob_hash(&development_blob);
        assert_ne!(production_hash, development_hash, "dev build marker change must change hash");
    }
}
