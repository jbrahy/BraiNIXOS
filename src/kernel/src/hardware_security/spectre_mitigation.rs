//! Spectre v1 and Spectre v2 mitigations.
//!
//! Phase 6 Plan 02: Applies LFENCE barriers in all speculative execution paths
//! (Spectre v1, compile-time, D-02). Detects eIBRS support via CPUID at boot
//! and enables hardware-enforced Enhanced IBRS if available; falls back to
//! retpoline + IBRS enable + IBPB on context switch if absent (D-01).
//!
//! eIBRS presence or absence is extended into PCR[1] as part of the kernel
//! config blob (D-03). MSR writes (IA32_SPEC_CTRL 0x48, IA32_PRED_CMD 0x49)
//! are delegated to `src/kernel/src/arch/hardware_registers.rs`.

#[cfg(test)]
mod tests {}
