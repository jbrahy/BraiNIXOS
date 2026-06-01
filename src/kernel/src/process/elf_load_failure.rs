//! Attested-failure path for the userspace ELF loader.
//!
//! Any error from `create_server_process_from_elf` routes through
//! `handle_load_failure` (in `boot/phases.rs`), which extends PCR[5] with
//! a deterministic 32-byte record describing the failure, logs a `[FAIL]`
//! line, and halts the processor. The PCR extension is tamper-evident and
//! observable by a remote attester.
//!
//! This file holds the pure-data hash builder so it can be unit-tested
//! on the host without depending on TPM-MMIO or boot-step logger
//! infrastructure. No unsafe, no allocation.

use sha2::Digest;

use crate::process::elf_loader::ElfLoadError;
use crate::process::ProcessType;

/// Reserved PCR slot for userspace-ELF-load failure records. Currently
/// unused per `docs/operations/ATTESTATION_MODEL.md`; claimed here for
/// this purpose.
pub const USERSPACE_ELF_LOAD_FAILURE_PCR_INDEX: u32 = 5;

/// Computes the SHA-256 hash of the failure record tuple
/// `(process_type, error_variant, source_module_hash)`. Used as the
/// PCR[5] extension payload so a remote attester can identify the
/// exact failure shape without ambiguity.
///
/// Verified by: `failure_record_hash_*` tests below.
pub fn compute_load_failure_record_hash(
    process_type: ProcessType,
    error: ElfLoadError,
    source_module_hash: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = sha2::Sha256::new();
    hasher.update([process_type_to_byte(process_type)]);
    hasher.update([error_variant_to_byte(error)]);
    hasher.update(source_module_hash);
    hasher.finalize().into()
}

fn process_type_to_byte(process_type: ProcessType) -> u8 {
    process_type as u8
}

fn error_variant_to_byte(error: ElfLoadError) -> u8 {
    match error {
        ElfLoadError::BinaryTooSmall => 1,
        ElfLoadError::InvalidMagic => 2,
        ElfLoadError::Not64Bit => 3,
        ElfLoadError::NotLittleEndian => 4,
        ElfLoadError::NotExecutable => 5,
        ElfLoadError::NotX86_64 => 6,
        ElfLoadError::SegmentOutOfBounds => 7,
        ElfLoadError::WritableAndExecutableSegment => 8,
        ElfLoadError::UnsupportedProgramHeaderType => 9,
        ElfLoadError::UnsupportedSegmentFlags => 10,
        ElfLoadError::EntryPointNotCanonical => 11,
        ElfLoadError::PageAllocationFailed => 12,
        ElfLoadError::UserPageTableWalkFailed => 13,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_record_hash_is_deterministic_for_same_inputs() {
        let module_hash = [0xAA; 32];
        let first = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &module_hash,
        );
        let second = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &module_hash,
        );
        assert_eq!(first, second);
    }

    #[test]
    fn failure_record_hash_differs_when_process_type_differs() {
        let module_hash = [0xAA; 32];
        let shell = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &module_hash,
        );
        let init = compute_load_failure_record_hash(
            ProcessType::Init,
            ElfLoadError::WritableAndExecutableSegment,
            &module_hash,
        );
        assert_ne!(shell, init);
    }

    #[test]
    fn failure_record_hash_differs_when_error_variant_differs() {
        let module_hash = [0xAA; 32];
        let wx = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &module_hash,
        );
        let oob = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::SegmentOutOfBounds,
            &module_hash,
        );
        assert_ne!(wx, oob);
    }

    #[test]
    fn failure_record_hash_differs_when_module_hash_differs() {
        let first = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &[0xAA; 32],
        );
        let second = compute_load_failure_record_hash(
            ProcessType::Shell,
            ElfLoadError::WritableAndExecutableSegment,
            &[0xBB; 32],
        );
        assert_ne!(first, second);
    }
}
