//! Compile-time partition table defining CPU time allocation per security domain.
//!
//! The partition table is a `const` array of time slots. Each slot assigns a
//! security domain to a fixed-length CPU time window. The major frame repeats
//! cyclically. The table is measured into TPM PCR[2] at boot (SCHED-05).
//!
//! Enforces INV-SCHED-001: domains cannot exceed their allocated budget.

/// A single time slot in the partition table major frame.
///
/// Each slot assigns a security domain to a fixed-length CPU time window.
/// The major frame repeats cyclically.
///
/// Enforces INV-SCHED-001: per-domain CPU budget accounting.
/// Verified by: test_partition_table_has_at_least_two_domain_slots
#[derive(Debug, Clone, Copy)]
pub struct PartitionSlot {
    /// Security domain identifier (matches Thread.domain_slot).
    pub domain_identifier: u8,
    /// Duration of this slot in scheduler ticks.
    pub duration_in_ticks: u64,
}

/// The compile-time partition table defining CPU time allocation per domain.
///
/// Measured into PCR[2] at boot (ATTESTATION_MODEL.md Section 1).
/// Any change to this table changes the attestation measurement.
///
/// Enforces INV-SCHED-001: domains cannot exceed their allocated budget.
/// Verified by: test_partition_table_has_at_least_two_domain_slots
pub const PARTITION_TABLE: &[PartitionSlot] = &[
    PartitionSlot { domain_identifier: 0, duration_in_ticks: 100 },
    PartitionSlot { domain_identifier: 1, duration_in_ticks: 100 },
    PartitionSlot { domain_identifier: 2, duration_in_ticks: 50 },
];

/// Computes the total ticks in one major frame by summing all slot durations.
///
/// Uses a loop since const fn cannot use iterators.
///
/// Enforces INV-SCHED-001: total budget is the sum of all domain budgets.
/// Verified by: test_compute_major_frame_total_ticks_sums_all_slot_durations
pub const fn compute_major_frame_total_ticks() -> u64 {
    let mut total_ticks: u64 = 0;
    let mut slot_index: usize = 0;
    while slot_index < PARTITION_TABLE.len() {
        total_ticks += PARTITION_TABLE[slot_index].duration_in_ticks;
        slot_index += 1;
    }
    total_ticks
}

/// The precomputed total ticks in one major frame.
///
/// Enforces INV-SCHED-001: total frame duration is fixed at compile time.
pub const MAJOR_FRAME_TOTAL_TICKS: u64 = compute_major_frame_total_ticks();
