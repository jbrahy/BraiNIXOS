//! SHA-256 measurement of the partition table for TPM PCR[2] extension.
//!
//! At boot, the raw bytes of the compile-time partition table are hashed
//! with SHA-256 and the digest is extended into PCR[2]. Any change to the
//! partition table produces a different attestation measurement (SCHED-05).
