//! CPU security feature detection for x86-64.
//!
//! Phase 6 Plan 01: Detects CPUID-reported capabilities at early boot:
//! RDRAND/RDSEED availability, Enhanced IBRS (eIBRS) for Spectre v2,
//! Intel TME / AMD SME for memory encryption, CET/IBT support,
//! SMEP/SMAP enforcement bits.
//!
//! Detection results are logged at boot and extended into PCR[1] as part
//! of the kernel config blob (D-03, D-05). Raw hardware access (CPUID instruction)
//! is delegated to `src/kernel/src/arch/hardware_registers.rs` per the
//! UNSAFE_CODE_POLICY.md allowlist.

#[cfg(test)]
mod tests {}
