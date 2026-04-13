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
pub mod csprng;
pub mod entropy_source;
pub mod indirect_branch_tracking;
pub mod kernel_config_blob;
pub mod kernel_write_protection;
pub mod memory_encryption;
pub mod pcr_measurement;
pub mod server_measurement;
pub mod spectre_mitigation;
pub mod tpm;
