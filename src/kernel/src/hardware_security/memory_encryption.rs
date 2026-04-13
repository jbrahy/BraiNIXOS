//! Intel TME / AMD SME memory encryption detection and enablement.
//!
//! Phase 6 Plan 02: Detects TME or SME support via CPUID at early boot, before CSPRNG
//! initialization (D-05). Enables whichever platform supports (D-06). Absence is fatal
//! in production builds (kernels built without the DEV_BUILD marker) and a logged
//! warning in development builds (D-04) -- mirrors the IOMMU policy.
//!
//! MSR writes for TME activation (IA32_TME_ACTIVATE 0x982) and SME activation
//! (MSR_AMD64_SYSCFG 0xC0010010) are delegated to
//! `src/kernel/src/arch/hardware_registers.rs` per the UNSAFE_CODE_POLICY.md allowlist.

#[cfg(test)]
mod tests {}
