//! Phase 6 unsafe boundary for hardware register access.
//!
//! This file is the sole location for all raw hardware register operations
//! introduced in Phase 6. It is allowlisted in `docs/security/UNSAFE_CODE_POLICY.md`.
//!
//! Permitted operations (per the allowlist entry):
//! - `cpuid` instruction for CPU feature detection
//! - `rdmsr`/`wrmsr` for IA32_SPEC_CTRL (0x48), IA32_PRED_CMD (0x49),
//!   IA32_ARCH_CAPABILITIES (0x10A), IA32_TME_ACTIVATE (0x982),
//!   MSR_AMD64_SYSCFG (0xC0010010)
//! - `mov cr4` for CET/IBT enable (bit 23)
//! - `rdrand`/`rdseed` instructions for hardware entropy
//! - `read_volatile`/`write_volatile` to TPM TIS registers at base 0xFED40000
//!
//! All functions in this file are safe wrappers over the minimal unsafe operations.
//! Every unsafe block has a `// SAFETY:` comment per UNSAFE_CODE_POLICY.md.
//! Callers in `hardware_security/` have zero unsafe code.
#![allow(unsafe_code)]

#[cfg(test)]
mod tests {}
