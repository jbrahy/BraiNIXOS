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
//!
//! `CpuidResult` is defined in `hardware_security::cpu_feature_detection` to keep
//! the pure detection logic testable on host targets without an x86_64 dependency.
#![allow(unsafe_code)]

use crate::hardware_security::cpu_feature_detection::CpuidResult;

/// Execute the CPUID instruction with the given leaf and subleaf.
///
/// Returns the four register values produced by the CPU for the requested
/// feature information leaf.
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit).
/// Verified by: test_cpuid_leaf_one_returns_nonzero_result
///
/// # Safety contract
/// CPUID is a non-destructive, read-only instruction available on all x86-64 CPUs.
/// No preconditions apply. No register state other than EAX/EBX/ECX/EDX is modified.
pub fn execute_cpuid_query(leaf: u32, subleaf: u32) -> CpuidResult {
    // SAFETY: CPUID is a non-destructive read-only instruction on all x86-64 CPUs.
    // - Precondition: None (always safe to execute)
    // - Invariant: INV-BOOT-005 (entropy initialization is explicit and conservative)
    // - Evidence: test_cpuid_leaf_one_returns_nonzero_result
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- cpuid instruction
    let raw_result = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
    build_cpuid_result(raw_result.eax, raw_result.ebx, raw_result.ecx, raw_result.edx)
}

/// Build a CpuidResult from the four register values.
fn build_cpuid_result(eax: u32, ebx: u32, ecx: u32, edx: u32) -> CpuidResult {
    CpuidResult { eax, ebx, ecx, edx }
}

/// Execute the RDRAND instruction to obtain one 64-bit random value.
///
/// Returns `Some(value)` if the carry flag is set (success), or `None` if the
/// carry flag is clear (entropy not available or instruction retried out).
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit and conservative).
/// Verified by: test_boot_halts_when_rdrand_is_unavailable
///
/// # Safety contract
/// RDRAND is a non-destructive instruction that returns a random value via a register.
/// The carry flag indicates whether the returned value is valid.
pub fn execute_rdrand_instruction() -> Option<u64> {
    // SAFETY: RDRAND is a non-destructive instruction. Returns random value or failure.
    // - Precondition: CPUID confirms RDRAND support (caller must check via is_rdrand_supported)
    // - Invariant: INV-BOOT-005 (entropy initialization is explicit and conservative)
    // - Evidence: test_boot_halts_when_rdrand_is_unavailable
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- rdrand instruction
    let random_value: u64;
    let carry_flag: u8;
    unsafe {
        core::arch::asm!(
            "rdrand {value}",
            "setc {carry}",
            value = out(reg) random_value,
            carry = out(reg_byte) carry_flag,
            options(nomem, nostack)
        );
    }
    extract_optional_value_from_carry(random_value, carry_flag)
}

/// Execute the RDSEED instruction to obtain one 64-bit seed value.
///
/// Returns `Some(value)` if the carry flag is set (success), or `None` if the
/// carry flag is clear (seed not available).
///
/// Verified by: test_rdseed_returns_none_when_unavailable
///
/// # Safety contract
/// RDSEED is a non-destructive instruction that returns a seed value via a register.
/// The carry flag indicates whether the returned value is valid.
pub fn execute_rdseed_instruction() -> Option<u64> {
    // SAFETY: RDSEED is a non-destructive instruction. Returns seed value or failure.
    // - Precondition: CPUID confirms RDSEED support (caller must check via is_rdseed_supported)
    // - Invariant: INV-BOOT-005 (entropy initialization is explicit and conservative)
    // - Evidence: test_rdseed_returns_none_when_unavailable
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- rdseed instruction
    let seed_value: u64;
    let carry_flag: u8;
    unsafe {
        core::arch::asm!(
            "rdseed {value}",
            "setc {carry}",
            value = out(reg) seed_value,
            carry = out(reg_byte) carry_flag,
            options(nomem, nostack)
        );
    }
    extract_optional_value_from_carry(seed_value, carry_flag)
}

/// Returns `Some(value)` if carry is nonzero, `None` otherwise.
fn extract_optional_value_from_carry(value: u64, carry_flag: u8) -> Option<u64> {
    if carry_flag != 0 { Some(value) } else { None }
}

#[cfg(test)]
mod tests {}
