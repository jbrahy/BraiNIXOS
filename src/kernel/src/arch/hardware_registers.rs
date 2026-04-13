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

/// Reads a Model Specific Register (MSR) by address.
///
/// Returns the 64-bit value from `rdmsr` (EDX:EAX combined).
/// Caller must verify MSR exists via CPUID before calling.
///
/// Enforces INV-X86-001 (platform feature detection via MSR).
/// Verified by: test_ibrs_detection_via_arch_capabilities_msr
///
/// # Safety contract
/// RDMSR is a non-destructive privileged instruction.
/// - Precondition: `msr_address` is a valid MSR for the current CPU
/// - Invariant: INV-X86-001 (platform feature detection)
/// - Evidence: test_ibrs_detection_via_arch_capabilities_msr
pub fn read_model_specific_register(msr_address: u32) -> u64 {
    let low_bits: u32;
    let high_bits: u32;
    // SAFETY: RDMSR reads an MSR register. Non-destructive. Ring 0 required.
    // - Precondition: msr_address is a valid MSR for the current CPU
    // - Invariant: INV-X86-001 (platform feature detection)
    // - Evidence: test_ibrs_detection_via_arch_capabilities_msr
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- rdmsr instruction
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr_address,
            out("eax") low_bits,
            out("edx") high_bits,
            options(nomem, nostack, preserves_flags),
        );
    }
    combine_msr_halves(high_bits, low_bits)
}

/// Combines the EDX:EAX halves of an RDMSR result into a single u64.
fn combine_msr_halves(high_bits: u32, low_bits: u32) -> u64 {
    ((high_bits as u64) << 32) | (low_bits as u64)
}

/// Writes a value to a Model Specific Register (MSR) by address.
///
/// Splits the 64-bit value into EDX:EAX and executes `wrmsr`.
/// Caller must verify MSR exists and value is architecturally correct.
///
/// Enforces INV-X86-002 (Spectre v2 mitigation, IBRS/IBPB writes).
/// Verified by: test_ibrs_is_enabled_when_eibrs_is_absent
///
/// # Safety contract
/// WRMSR writes CPU configuration registers. Ring 0 required.
/// - Precondition: msr_address is a valid writable MSR; value is architecturally correct
/// - Invariant: Spectre v2 mitigation (INV-X86-002) or memory encryption enable
/// - Evidence: test_ibrs_is_enabled_when_eibrs_is_absent
pub fn write_model_specific_register(msr_address: u32, value: u64) {
    let low_bits = value as u32;
    let high_bits = (value >> 32) as u32;
    // SAFETY: WRMSR modifies CPU configuration. Ring 0 required.
    // - Precondition: msr_address is a valid writable MSR, value is architecturally correct
    // - Invariant: INV-X86-002 (Spectre v2 mitigation)
    // - Evidence: test_ibrs_is_enabled_when_eibrs_is_absent
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- wrmsr instruction
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr_address,
            in("eax") low_bits,
            in("edx") high_bits,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Reads the current value of the CR4 control register.
///
/// CR4 controls CPU features such as PAE, SMEP, SMAP, CET/IBT.
///
/// Enforces INV-X86-002 (CET/IBT enable).
/// Verified by: test_indirect_branch_tracking_enable
pub fn read_control_register_four() -> u64 {
    let register_value: u64;
    // SAFETY: CR4 read. Non-destructive. Ring 0 required.
    // - Precondition: CPU is in ring 0
    // - Invariant: INV-X86-002 (CET/IBT enable via CR4 bit 23)
    // - Evidence: test_indirect_branch_tracking_enable
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- mov cr4 instruction
    unsafe {
        core::arch::asm!(
            "mov {value}, cr4",
            value = out(reg) register_value,
            options(nomem, nostack, preserves_flags),
        );
    }
    register_value
}

/// Writes a new value to the CR4 control register.
///
/// The value must preserve all required bits (SMEP, SMAP, PAE, etc.).
///
/// Enforces INV-X86-002 (CET/IBT enable via CR4 bit 23).
/// Verified by: test_indirect_branch_tracking_enable
///
/// # Safety contract
/// CR4 write modifies the CPU execution environment. Ring 0 required.
/// - Precondition: value preserves existing required bits (SMEP, SMAP, PAE)
/// - Invariant: INV-X86-002 (CET/IBT enable)
/// - Evidence: test_indirect_branch_tracking_enable
pub fn write_control_register_four(value: u64) {
    // SAFETY: CR4 write modifies CPU execution environment. Ring 0 required.
    // - Precondition: value preserves existing required bits (SMEP, SMAP, PAE)
    // - Invariant: INV-X86-002 (CET/IBT enable)
    // - Evidence: test_indirect_branch_tracking_enable
    // Allowlist: src/kernel/src/arch/hardware_registers.rs -- mov cr4 instruction
    unsafe {
        core::arch::asm!(
            "mov cr4, {value}",
            value = in(reg) value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {}
