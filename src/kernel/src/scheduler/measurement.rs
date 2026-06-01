//! SHA-256 measurement of the partition table for TPM PCR[2] extension.
//!
//! Per ATTESTATION_MODEL.md, PCR[2] receives SHA-256(kernel .text/.rodata) followed
//! by SHA-256(partition_table_bytes). This module computes the partition table hash.
//!
//! Any change to the compile-time PARTITION_TABLE produces a different attestation
//! measurement, preventing undetected modifications (T-SCHED-09).
//!
//! SCHED-05.

use sha2::{Digest, Sha256};

use super::partition_table::{PartitionSlot, PARTITION_TABLE};

/// Updates the hasher with the bytes of a single partition slot.
///
/// Hashes domain_identifier as one byte and duration_in_ticks as 8 little-endian bytes.
fn hash_single_partition_slot(hasher: &mut Sha256, slot: &PartitionSlot) {
    hasher.update([slot.domain_identifier]);
    hasher.update(slot.duration_in_ticks.to_le_bytes());
}

/// Computes the SHA-256 hash of the given partition slot sequence.
///
/// Parameterized for testing with arbitrary slot configurations.
/// Enforces SCHED-05. Called by compute_partition_table_hash for the compile-time table.
pub fn compute_partition_table_hash_from_slots(slots: &[PartitionSlot]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for slot in slots {
        hash_single_partition_slot(&mut hasher, slot);
    }
    let digest = hasher.finalize();
    digest.into()
}

/// Computes the SHA-256 hash of the compile-time PARTITION_TABLE bytes.
///
/// Returns a 32-byte digest suitable for extension into TPM PCR[2] at boot.
/// Any change to the partition table changes the hash (T-SCHED-09 mitigation).
///
/// Enforces SCHED-05. Hash extended into PCR[2] during boot.
/// Verified by: test_partition_table_hash_changes_when_table_changes
pub fn compute_partition_table_hash() -> [u8; 32] {
    compute_partition_table_hash_from_slots(PARTITION_TABLE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::partition_table::PARTITION_TABLE;

    /// Verifies the hash is a 32-byte array (SHA-256 digest size).
    #[test]
    fn test_compute_partition_table_hash_returns_32_bytes() {
        let hash = compute_partition_table_hash();
        assert_eq!(hash.len(), 32, "SHA-256 digest must be 32 bytes");
    }

    /// Verifies the hash is deterministic: two calls return identical results.
    #[test]
    fn test_compute_partition_table_hash_is_deterministic() {
        let first_hash = compute_partition_table_hash();
        let second_hash = compute_partition_table_hash();
        assert_eq!(first_hash, second_hash, "hash must be deterministic");
    }

    /// Verifies a modified table produces a different hash (T-SCHED-09 mitigation).
    ///
    /// Enforces SCHED-05: any change to the partition table changes the attestation hash.
    /// Verified by: test_partition_table_hash_changes_when_table_changes
    #[test]
    fn test_partition_table_hash_changes_when_table_changes() {
        let original_hash = compute_partition_table_hash();
        let modified_slots = [
            PartitionSlot {
                domain_identifier: 0,
                duration_in_ticks: 99,
            },
            PartitionSlot {
                domain_identifier: 1,
                duration_in_ticks: 100,
            },
            PartitionSlot {
                domain_identifier: 2,
                duration_in_ticks: 50,
            },
        ];
        let modified_hash = compute_partition_table_hash_from_slots(&modified_slots);
        assert_ne!(
            original_hash, modified_hash,
            "different partition table must produce different hash"
        );
    }

    /// Verifies the hash is non-zero (not returning uninitialized or zeroed memory).
    #[test]
    fn test_compute_partition_table_hash_is_nonzero() {
        let hash = compute_partition_table_hash();
        let all_zeros = [0u8; 32];
        assert_ne!(hash, all_zeros, "hash must not be all zeros");
    }

    /// Verifies hash consistency across identical slot configurations.
    #[test]
    fn test_compute_partition_table_hash_matches_slots_version() {
        let hash_from_constant = compute_partition_table_hash();
        let hash_from_slots = compute_partition_table_hash_from_slots(PARTITION_TABLE);
        assert_eq!(
            hash_from_constant, hash_from_slots,
            "constant and parameterized versions must agree"
        );
    }
}
