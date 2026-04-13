//! ChaCha20 CSPRNG with two-phase hardware entropy seeding.
//!
//! Phase 6 Plan 01: Implements a ChaCha20 stream cipher CSPRNG seeded in two phases.
//! Phase A (early boot, before TPM init): seeds from 8 RDRAND samples XOR-ed with 4
//! RDSEED samples to produce a 256-bit ChaCha20 key (D-07). RDRAND absence is a fatal
//! boot halt. Phase B (after TPM init): reseeds by extending the existing key with 256
//! bits of TPM2_GetRandom output via a KDF step (D-08). TPM init failure is non-fatal
//! for the CSPRNG -- Phase A seed is retained and an audit warning is logged.
//!
//! Uses the `chacha20` crate (RustCrypto, no_std, NCC-audited) for the cipher primitive.

#[cfg(test)]
mod tests {
    /// SC-01: RDRAND absence is a fatal boot halt.
    ///
    /// Phase 6 Plan 01 replaces this stub with the real test.
    #[test]
    #[ignore = "Phase 6 Plan 01 implements this test"]
    fn test_boot_halts_when_rdrand_is_unavailable() {
        // SC-01: RDRAND absence is a fatal boot halt
    }
}
