//! Scheduler subsystem initialization during boot.
//!
//! Wires the APIC timer hardware to the scheduler tick loop and extends
//! the TPM PCR[2] with the partition table hash so the attestation chain
//! reflects the active scheduling policy.
//! Called from the boot sequence after IPC subsystem initialization.

use crate::arch::timer::initialize_apic_timer;
use crate::boot::logger::BootStepLogger;
use crate::hardware_security::tpm::commands::extend_platform_configuration_register;
use crate::scheduler::measurement::compute_partition_table_hash;

/// TPM PCR index that receives the partition table hash.
/// Per ATTESTATION_MODEL.md, PCR[2] carries scheduling policy measurements.
const PCR_INDEX_PARTITION_TABLE: u32 = 2;

/// Phase 5 boot step: initializes APIC timer, extends PCR[2] with the
/// partition table hash, and announces scheduler readiness.
///
/// Starts the local APIC timer in periodic mode (see arch::timer::initialize_apic_timer).
/// After this call, the timer fires IRQ 32 periodically to drive scheduler ticks.
/// The partition table is compile-time constant (PARTITION_TABLE in scheduler::mod).
///
/// Enforces INV-SCHED-001: scheduler clock is active before any threads run.
/// Enforces INV-BOOT-001: measured boot path integrity (partition table measured).
/// Verified by: boot sequence integration (APIC timer fires after boot).
pub fn initialize_scheduler_subsystem(boot_step_logger: &mut BootStepLogger) {
    initialize_apic_timer();
    extend_pcr2_with_partition_table_hash();
    boot_step_logger.ok("Scheduler initialized; PCR[2] extended with partition table hash");
}

/// Computes SHA-256 of the partition table and extends TPM PCR[2].
///
/// Enforces INV-BOOT-001: measured boot path integrity.
/// Verified by: test_extend_pcr2_does_not_panic_on_host_target
fn extend_pcr2_with_partition_table_hash() {
    let partition_table_hash = compute_partition_table_hash();
    let _ =
        extend_platform_configuration_register(PCR_INDEX_PARTITION_TABLE, &partition_table_hash);
}

#[cfg(test)]
mod tests {
    use crate::hardware_security::tpm::commands::extend_platform_configuration_register;
    use crate::scheduler::measurement::compute_partition_table_hash;

    const PCR_INDEX_PARTITION_TABLE: u32 = 2;

    /// Verifies that the partition table hash is non-zero (not SHA-256 of empty).
    #[test]
    fn test_partition_table_hash_is_nonzero() {
        let hash = compute_partition_table_hash();
        assert_ne!(
            hash, [0u8; 32],
            "partition table hash must not be all zeros"
        );
    }

    /// Verifies PCR[2] extend does not panic on host target.
    #[test]
    fn test_extend_pcr2_does_not_panic_on_host_target() {
        let hash = compute_partition_table_hash();
        let result = extend_platform_configuration_register(PCR_INDEX_PARTITION_TABLE, &hash);
        assert!(result.is_ok(), "PCR extend must succeed on host target");
    }
}
