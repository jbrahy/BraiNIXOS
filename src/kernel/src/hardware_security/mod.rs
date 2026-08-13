//! Hardware security subsystem for Phase 6.
//!
//! Provides CPU security feature enforcement (CET/IBT, SMEP/SMAP), Spectre mitigations,
//! memory encryption (Intel TME / AMD SME), ChaCha20 CSPRNG with two-phase seeding,
//! kernel section write-protection after init, TPM PCR measurement chain,
//! Ed25519 binary signing verification, and the attestation gate with monotonic counter
//! rollback protection.
//!
//! The pure-logic modules (csprng, binary_signing, attestation_gate, kernel_config_blob,
//! pcr_measurement) are testable on any host target. Architecture-specific operations
//! (entropy_source, cpu_feature_detection) gate their unsafe blocks on
//! `#[cfg(target_arch = "x86_64")]` internally.

pub mod attestation_gate;
pub mod binary_signing;
pub mod cpu_feature_detection;
#[cfg(bare_metal_x86)]
pub mod csprng;
#[cfg(bare_metal_x86)]
pub mod entropy_source;
#[cfg(bare_metal_x86)]
pub mod indirect_branch_tracking;
pub mod iommu_detection;
pub mod kernel_config_blob;
#[cfg(bare_metal_x86)]
pub mod kernel_write_protection;
#[cfg(bare_metal_x86)]
pub mod memory_encryption;
pub mod pcr_measurement;
#[cfg(bare_metal_x86)]
pub mod server_measurement;
pub mod spectre_mitigation;
#[cfg(bare_metal_x86)]
pub mod tpm;
