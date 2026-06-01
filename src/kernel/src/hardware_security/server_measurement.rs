//! PCR[3] measurement of server binaries. Per D-05.
//!
//! Computes SHA-256 of each server binary (init, spawnd, auditd) and extends
//! the hash into TPM PCR[3] before any server byte is executed or mapped.
//!
//! PCR[3] ordering: init -> spawnd -> auditd (sequential extends per D-05).
//! PCR[0] = kernel text/rodata (Phase 6).
//! PCR[1] = kernel config blob (Phase 6).
//! PCR[2] = partition table (Phase 5).
//! PCR[3] = server binaries (this module).

use sha2::{Digest, Sha256};

use crate::hardware_security::tpm::commands::extend_platform_configuration_register;
use crate::hardware_security::tpm::registers::TpmError;

/// TPM PCR index reserved for server binary measurements.
const PCR_INDEX_SERVER_BINARIES: u32 = 3;

/// Computes SHA-256 of a server binary's bytes.
///
/// Enforces INV-BOOT-001: measured boot path integrity.
/// Verified by: boot::server_measurement::tests::test_compute_server_binary_hash_is_deterministic
pub fn compute_server_binary_hash(binary_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(binary_bytes);
    let digest = hasher.finalize();
    digest.into()
}

/// Extends PCR[3] with the SHA-256 hash of a single server binary.
///
/// Verified by: integration_swtpm_attestation_chain (CI-only)
pub fn measure_server_binary_into_pcr3(binary_bytes: &[u8]) -> Result<(), TpmError> {
    let binary_hash = compute_server_binary_hash(binary_bytes);
    extend_platform_configuration_register(PCR_INDEX_SERVER_BINARIES, &binary_hash)
}

/// Extends all eight server binary hashes into PCR[3] in order.
///
/// Eight sequential extends into PCR[3] per D-02 ordering: init, spawnd, auditd,
/// devd-nic, devd-disk, linkd, ipd, transportd. TPM errors are tolerated during
/// development — swtpm may not be present on host. Any change to any server
/// binary changes PCR[3].
// Eight explicit named parameters -- one per measured server binary -- are
// intentional per CODE_STANDARDS (named over packed); the count is fixed by D-02.
#[allow(clippy::too_many_arguments)]
pub fn measure_all_server_binaries(
    init_binary: &[u8],
    spawnd_binary: &[u8],
    auditd_binary: &[u8],
    devd_nic_binary: &[u8],
    devd_disk_binary: &[u8],
    linkd_binary: &[u8],
    ipd_binary: &[u8],
    transportd_binary: &[u8],
) {
    measure_original_five_server_binaries(
        init_binary,
        spawnd_binary,
        auditd_binary,
        devd_nic_binary,
        devd_disk_binary,
    );
    measure_network_server_binaries(linkd_binary, ipd_binary, transportd_binary);
}

/// Extends the original five server binary hashes into PCR[3].
fn measure_original_five_server_binaries(
    init_binary: &[u8],
    spawnd_binary: &[u8],
    auditd_binary: &[u8],
    devd_nic_binary: &[u8],
    devd_disk_binary: &[u8],
) {
    let _ = measure_server_binary_into_pcr3(init_binary);
    let _ = measure_server_binary_into_pcr3(spawnd_binary);
    let _ = measure_server_binary_into_pcr3(auditd_binary);
    let _ = measure_server_binary_into_pcr3(devd_nic_binary);
    let _ = measure_server_binary_into_pcr3(devd_disk_binary);
}

/// Extends the three network server binary hashes into PCR[3].
fn measure_network_server_binaries(
    linkd_binary: &[u8],
    ipd_binary: &[u8],
    transportd_binary: &[u8],
) {
    let _ = measure_server_binary_into_pcr3(linkd_binary);
    let _ = measure_server_binary_into_pcr3(ipd_binary);
    let _ = measure_server_binary_into_pcr3(transportd_binary);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that hashing the same bytes twice produces the same result.
    #[test]
    fn test_compute_server_binary_hash_is_deterministic() {
        let binary_bytes = b"server binary bytes for determinism test";
        let first_hash = compute_server_binary_hash(binary_bytes);
        let second_hash = compute_server_binary_hash(binary_bytes);
        assert_eq!(first_hash, second_hash, "SHA-256 must be deterministic");
    }

    /// Verifies that different inputs produce different hashes.
    #[test]
    fn test_compute_server_binary_hash_differs_for_different_input() {
        let first_bytes = b"first server binary content";
        let second_bytes = b"second server binary content";
        let first_hash = compute_server_binary_hash(first_bytes);
        let second_hash = compute_server_binary_hash(second_bytes);
        assert_ne!(
            first_hash, second_hash,
            "different inputs must produce different hashes"
        );
    }

    /// Verifies that measure_server_binary_into_pcr3 returns Ok on the host target.
    ///
    /// The Phase 6 host TPM stub returns Ok(()) without MMIO access on non-x86_64.
    #[test]
    fn test_measure_server_binary_into_pcr3_succeeds_on_host_target() {
        let binary_bytes = b"dummy server binary for pcr3 test";
        let result = measure_server_binary_into_pcr3(binary_bytes);
        assert!(
            result.is_ok(),
            "PCR[3] extend must return Ok on host target"
        );
    }
}
