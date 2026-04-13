//! TPM 2.0 command encoders for kernel operations.
//!
//! Phase 6 Plan 03: Encodes and sends TPM2_GetRandom (for CSPRNG Phase B reseed),
//! TPM2_PCR_Extend (for PCR[0] and PCR[1] measurement), and TPM2_Quote
//! (for attestation gate verification) commands via the TIS MMIO interface.
//!
//! All command bytes are statically allocated (no heap). Fixed-size buffers hold
//! command and response payloads per the no-dynamic-kernel-heap constraint.
//! Command dispatch calls the MMIO accessors in `registers.rs`.

#[cfg(test)]
mod tests {}
