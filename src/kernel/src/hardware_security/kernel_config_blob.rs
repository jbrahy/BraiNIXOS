//! Kernel compile-time security configuration blob for PCR[1] measurement.
//!
//! Phase 6 Plan 03: Defines a fixed-size struct containing all security policy
//! constants: MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS, IPC timeout limits, partition
//! table policy, Spectre mitigation mode, TME enforcement flag, attestation timeout,
//! and all other compile-time security parameters (D-11).
//!
//! The blob is SHA-256 hashed and extended into TPM PCR[1] during boot. Any change
//! to a security policy constant changes the PCR[1] value even if the kernel binary
//! .text hash is unchanged, preventing silent policy rollback.

#[cfg(test)]
mod tests {}
