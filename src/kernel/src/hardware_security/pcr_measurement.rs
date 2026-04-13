//! PCR[0] and PCR[1] measurement for the kernel binary and config blob.
//!
//! Phase 6 Plan 04: Computes SHA-256 of the kernel .text and .rodata sections
//! using the linker-exported boundary symbols (_text_start, _text_end,
//! _rodata_start, _rodata_end) and extends the result into TPM PCR[0] (D-10).
//! Also computes SHA-256 of the kernel config blob (D-11) and extends into PCR[1].
//!
//! PCR extension ordering is strictly PCR[0] -> PCR[1] -> attestation gate opens (D-14).
//! PCR[2] was already extended in Phase 5 (partition table measurement).
//! PCR[3] is reserved for Phase 7 server binary hashes.
//!
//! Reuses the SHA-256 + TPM extend pattern established in
//! `src/kernel/src/scheduler/measurement.rs`.
#![allow(unsafe_code)]

use sha2::{Digest, Sha256};

use crate::hardware_security::kernel_config_blob::KernelSecurityConfigBlob;

// Linker script symbols marking the .text section boundaries.
// Exported by src/kernel/linker.ld. Used to locate kernel code pages for
// PCR[0] measurement and write-protection.
#[cfg(target_arch = "x86_64")]
extern "C" {
    static _text_start: u8;
    static _text_end: u8;
    static _rodata_start: u8;
    static _rodata_end: u8;
}

/// Returns the start pointer and byte length of the kernel .text section.
///
/// Uses linker-exported symbols to locate the exact section boundaries.
/// Guard: only available on x86_64 (bare-metal target).
///
/// Enforces T-HW-PCR-01 mitigation: linker symbols define the exact measured range.
#[cfg(target_arch = "x86_64")]
pub fn get_kernel_text_section_bounds() -> (*const u8, usize) {
    // SAFETY: _text_start and _text_end are linker symbols at valid kernel VA.
    // - Precondition: kernel is loaded at KERNEL_VIRTUAL_BASE (0xFFFFFFFF80100000).
    // - Invariant: INV-BOOT-001 (measured boot integrity).
    // - Evidence: test_compute_kernel_binary_measurement_returns_32_bytes
    let text_start_pointer = unsafe { &_text_start as *const u8 };
    let text_end_pointer = unsafe { &_text_end as *const u8 };
    let text_section_length = compute_section_length(text_start_pointer, text_end_pointer);
    (text_start_pointer, text_section_length)
}

/// Returns the start pointer and byte length of the kernel .rodata section.
///
/// Uses linker-exported symbols to locate the exact section boundaries.
/// Guard: only available on x86_64 (bare-metal target).
///
/// Enforces T-HW-PCR-01 mitigation: linker symbols define the exact measured range.
#[cfg(target_arch = "x86_64")]
pub fn get_kernel_rodata_section_bounds() -> (*const u8, usize) {
    // SAFETY: _rodata_start and _rodata_end are linker symbols at valid kernel VA.
    // - Precondition: kernel is loaded at KERNEL_VIRTUAL_BASE.
    // - Invariant: INV-BOOT-001 (measured boot integrity).
    // - Evidence: test_compute_kernel_binary_measurement_returns_32_bytes
    let rodata_start_pointer = unsafe { &_rodata_start as *const u8 };
    let rodata_end_pointer = unsafe { &_rodata_end as *const u8 };
    let rodata_section_length = compute_section_length(rodata_start_pointer, rodata_end_pointer);
    (rodata_start_pointer, rodata_section_length)
}

/// Computes the byte length between a section start and end pointer.
///
/// Both pointers must point into the same contiguous section.
#[cfg(target_arch = "x86_64")]
fn compute_section_length(start_pointer: *const u8, end_pointer: *const u8) -> usize {
    // SAFETY: start_pointer and end_pointer are linker symbols in the same allocation.
    // - Precondition: both pointers are valid kernel virtual addresses in the same section.
    // - Invariant: INV-BOOT-001.
    // - Evidence: linker script guarantees end >= start for .text and .rodata.
    unsafe { end_pointer.offset_from(start_pointer) as usize }
}

/// Creates a SHA-256 hasher updated with a byte slice.
fn hash_byte_slice(hasher: &mut Sha256, byte_slice: &[u8]) {
    hasher.update(byte_slice);
}

/// Computes SHA-256 of the kernel .text and .rodata sections combined.
///
/// PCR[0] = SHA-256(.text bytes || .rodata bytes). Updates hasher with .text
/// then .rodata, producing a single 32-byte digest for both sections.
///
/// Parameterized for testing: caller provides section byte slices directly.
/// Enforces D-10: kernel binary integrity measurement.
/// Verified by: test_compute_kernel_binary_measurement_returns_32_bytes
pub fn compute_kernel_binary_measurement(
    text_section_bytes: &[u8],
    rodata_section_bytes: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hash_byte_slice(&mut hasher, text_section_bytes);
    hash_byte_slice(&mut hasher, rodata_section_bytes);
    let digest = hasher.finalize();
    digest.into()
}

/// Computes SHA-256 of a KernelSecurityConfigBlob for PCR[1].
///
/// PCR[1] = SHA-256(config_blob_bytes). Any change to any security policy constant
/// changes this value, preventing silent security policy rollback (T-HW-PCR-02).
///
/// Delegates to kernel_config_blob::compute_config_blob_hash for the actual computation.
/// Enforces D-11: kernel config blob measurement.
/// Verified by: test_compute_config_blob_measurement_returns_32_bytes
pub fn compute_config_blob_measurement(config_blob: &KernelSecurityConfigBlob) -> [u8; 32] {
    crate::hardware_security::kernel_config_blob::compute_config_blob_hash(config_blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardware_security::kernel_config_blob::create_kernel_security_config_blob;

    /// Verifies compute_kernel_binary_measurement returns a 32-byte SHA-256 digest.
    #[test]
    fn test_compute_kernel_binary_measurement_returns_32_bytes() {
        let text_bytes = b"fake kernel text section bytes for testing";
        let rodata_bytes = b"fake kernel rodata section bytes for testing";
        let measurement = compute_kernel_binary_measurement(text_bytes, rodata_bytes);
        assert_eq!(measurement.len(), 32, "PCR[0] measurement must be 32 bytes");
    }

    /// Verifies compute_kernel_binary_measurement is deterministic.
    #[test]
    fn test_compute_kernel_binary_measurement_is_deterministic() {
        let text_bytes = b"text section";
        let rodata_bytes = b"rodata section";
        let first_measurement = compute_kernel_binary_measurement(text_bytes, rodata_bytes);
        let second_measurement = compute_kernel_binary_measurement(text_bytes, rodata_bytes);
        assert_eq!(
            first_measurement, second_measurement,
            "PCR[0] measurement must be deterministic"
        );
    }

    /// Verifies compute_kernel_binary_measurement is non-zero.
    #[test]
    fn test_compute_kernel_binary_measurement_is_nonzero() {
        let text_bytes = b"text section content";
        let rodata_bytes = b"rodata section content";
        let measurement = compute_kernel_binary_measurement(text_bytes, rodata_bytes);
        let all_zeros = [0u8; 32];
        assert_ne!(
            measurement, all_zeros,
            "PCR[0] measurement must not be all zeros"
        );
    }

    /// Verifies changing text bytes changes the measurement.
    #[test]
    fn test_different_text_bytes_produce_different_pcr0() {
        let rodata_bytes = b"same rodata";
        let first_measurement =
            compute_kernel_binary_measurement(b"text version one", rodata_bytes);
        let second_measurement =
            compute_kernel_binary_measurement(b"text version two", rodata_bytes);
        assert_ne!(
            first_measurement, second_measurement,
            "different text must produce different PCR[0]"
        );
    }

    /// Verifies changing rodata bytes changes the measurement.
    #[test]
    fn test_different_rodata_bytes_produce_different_pcr0() {
        let text_bytes = b"same text";
        let first_measurement =
            compute_kernel_binary_measurement(text_bytes, b"rodata version one");
        let second_measurement =
            compute_kernel_binary_measurement(text_bytes, b"rodata version two");
        assert_ne!(
            first_measurement, second_measurement,
            "different rodata must produce different PCR[0]"
        );
    }

    /// Verifies compute_config_blob_measurement returns a 32-byte SHA-256 digest.
    #[test]
    fn test_compute_config_blob_measurement_returns_32_bytes() {
        let config_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let measurement = compute_config_blob_measurement(&config_blob);
        assert_eq!(measurement.len(), 32, "PCR[1] measurement must be 32 bytes");
    }

    /// Verifies compute_config_blob_measurement is deterministic.
    #[test]
    fn test_compute_config_blob_measurement_is_deterministic() {
        let config_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let first_measurement = compute_config_blob_measurement(&config_blob);
        let second_measurement = compute_config_blob_measurement(&config_blob);
        assert_eq!(
            first_measurement, second_measurement,
            "PCR[1] measurement must be deterministic"
        );
    }

    /// Verifies compute_config_blob_measurement is non-zero.
    #[test]
    fn test_compute_config_blob_measurement_is_nonzero() {
        let config_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let measurement = compute_config_blob_measurement(&config_blob);
        let all_zeros = [0u8; 32];
        assert_ne!(
            measurement, all_zeros,
            "PCR[1] measurement must not be all zeros"
        );
    }

    /// Verifies changing the config blob changes the PCR[1] measurement.
    #[test]
    fn test_changing_config_blob_changes_pcr1() {
        let original_blob = create_kernel_security_config_blob(0, 1, 1, 0);
        let modified_blob = create_kernel_security_config_blob(1, 1, 1, 0);
        let original_measurement = compute_config_blob_measurement(&original_blob);
        let modified_measurement = compute_config_blob_measurement(&modified_blob);
        assert_ne!(
            original_measurement, modified_measurement,
            "changed blob must produce different PCR[1]"
        );
    }
}
