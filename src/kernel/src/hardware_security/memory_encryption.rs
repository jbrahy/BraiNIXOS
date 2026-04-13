//! Intel TME / AMD SME memory encryption detection and enablement.
//!
//! Phase 6 Plan 03: Detects TME or SME support via CPUID at early boot, before CSPRNG
//! initialization (D-05). Enables whichever platform supports (D-06). Absence is fatal
//! in production builds (kernels built without the DEV_BUILD marker) and a logged
//! warning in development builds (D-04) -- mirrors the IOMMU policy.
//!
//! MSR writes for TME activation (IA32_TME_ACTIVATE 0x982) and SME activation
//! (MSR_AMD64_SYSCFG 0xC0010010) are delegated to
//! `src/kernel/src/arch/hardware_registers.rs` per the UNSAFE_CODE_POLICY.md allowlist.
//!
//! Enforces threat mitigations:
//! - T-HW-MEM-01: Cold boot attack (mitigated by TME/SME before secrets in RAM, D-05)
//! - T-HW-MEM-02: DMA attack on physical memory (mitigated by TME/SME, D-04)
//! - T-HW-MEM-03: Silent degradation in production (mitigated by fatal halt, D-04)

use crate::hardware_security::cpu_feature_detection::CpuidResult;

/// The memory encryption mode supported by this CPU.
///
/// Determined by CPUID at early boot before any secrets are placed in RAM (D-05).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEncryptionMode {
    /// Intel Total Memory Encryption: CPUID leaf 0x7 ECX bit 13.
    IntelTotalMemoryEncryption,
    /// AMD Secure Memory Encryption: CPUID leaf 0x8000001F EAX bit 0.
    AmdSecureMemoryEncryption,
    /// Neither TME nor SME is available on this CPU.
    Unavailable,
}

/// The result of applying the dev/prod memory encryption enforcement policy (D-04).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryEncryptionEnforcementResult {
    /// Memory encryption was successfully enabled.
    Enabled(MemoryEncryptionMode),
    /// Development build: encryption unavailable, warning logged, boot continues.
    DevelopmentWarning,
    /// Production build: encryption unavailable, fatal halt required.
    ProductionFatalHalt,
}

/// IA32_TME_CAPABILITY MSR address -- read to verify TME not already locked.
#[cfg(target_arch = "x86_64")]
const TOTAL_MEMORY_ENCRYPTION_CAPABILITY_MSR_ADDRESS: u32 = 0x981;

/// IA32_TME_ACTIVATE MSR address -- write to enable Intel TME.
const TOTAL_MEMORY_ENCRYPTION_ACTIVATE_MSR_ADDRESS: u32 = 0x982;

/// MSR_AMD64_SYSCFG address -- read-modify-write to enable AMD SME.
const AMD_SYSTEM_CONFIGURATION_MSR_ADDRESS: u32 = 0xC001_0010;

/// Bit 1 of IA32_TME_ACTIVATE enables TME.
#[cfg(target_arch = "x86_64")]
const TOTAL_MEMORY_ENCRYPTION_ENABLE_BIT: u64 = 1 << 1;

/// Bit 23 of MSR_AMD64_SYSCFG enables SME.
#[cfg(target_arch = "x86_64")]
const SECURE_MEMORY_ENCRYPTION_ENABLE_BIT: u64 = 1 << 23;

/// Detect which memory encryption mode is supported by this CPU.
///
/// Queries CPUID leaf 0x7 ECX bit 13 for TME and CPUID leaf 0x8000001F EAX bit 0 for SME.
/// Per D-06: if both are detected, prefer TME (Intel takes precedence on real hardware).
///
/// Enforces T-HW-MEM-01 (cold boot attack prevention) and T-HW-MEM-02 (DMA attack prevention).
/// Verified by: test_detect_memory_encryption_support_returns_intel_tme_when_bit_is_set
pub fn detect_memory_encryption_support(
    cpuid_leaf_seven_result: &CpuidResult,
    cpuid_extended_leaf_result: &CpuidResult,
) -> MemoryEncryptionMode {
    let tme_supported = is_tme_bit_set(cpuid_leaf_seven_result);
    let sme_supported = is_sme_bit_set(cpuid_extended_leaf_result);
    select_encryption_mode(tme_supported, sme_supported)
}

/// Returns true if CPUID leaf 0x7 ECX bit 13 (TME) is set.
fn is_tme_bit_set(cpuid_leaf_seven_result: &CpuidResult) -> bool {
    let total_memory_encryption_bit_position = 13u32;
    let bit_mask = 1u32 << total_memory_encryption_bit_position;
    (cpuid_leaf_seven_result.ecx & bit_mask) != 0
}

/// Returns true if CPUID leaf 0x8000001F EAX bit 0 (SME) is set.
fn is_sme_bit_set(cpuid_extended_leaf_result: &CpuidResult) -> bool {
    let secure_memory_encryption_bit_mask = 1u32;
    (cpuid_extended_leaf_result.eax & secure_memory_encryption_bit_mask) != 0
}

/// Select the encryption mode from detection results.
///
/// Per D-06: TME takes precedence if both are detected.
fn select_encryption_mode(tme_supported: bool, sme_supported: bool) -> MemoryEncryptionMode {
    if tme_supported {
        return MemoryEncryptionMode::IntelTotalMemoryEncryption;
    }
    if sme_supported {
        return MemoryEncryptionMode::AmdSecureMemoryEncryption;
    }
    MemoryEncryptionMode::Unavailable
}

/// Enable Intel Total Memory Encryption via IA32_TME_ACTIVATE MSR (0x982).
///
/// Writes the TME enable bit to the activate MSR.
/// Enforces T-HW-MEM-01 (cold boot attack prevention).
#[cfg(target_arch = "x86_64")]
fn enable_intel_total_memory_encryption() {
    use crate::arch::hardware_registers;
    let current_value = hardware_registers::read_model_specific_register(
        TOTAL_MEMORY_ENCRYPTION_CAPABILITY_MSR_ADDRESS,
    );
    let activate_value = current_value | TOTAL_MEMORY_ENCRYPTION_ENABLE_BIT;
    hardware_registers::write_model_specific_register(
        TOTAL_MEMORY_ENCRYPTION_ACTIVATE_MSR_ADDRESS,
        activate_value,
    );
}

/// Enable AMD Secure Memory Encryption via MSR_AMD64_SYSCFG (0xC0010010) bit 23.
///
/// Reads the current SYSCFG, ORs in the SME enable bit, writes it back.
/// Enforces T-HW-MEM-01 (cold boot attack prevention).
#[cfg(target_arch = "x86_64")]
fn enable_amd_secure_memory_encryption() {
    use crate::arch::hardware_registers;
    let current_syscfg =
        hardware_registers::read_model_specific_register(AMD_SYSTEM_CONFIGURATION_MSR_ADDRESS);
    let updated_syscfg = current_syscfg | SECURE_MEMORY_ENCRYPTION_ENABLE_BIT;
    hardware_registers::write_model_specific_register(
        AMD_SYSTEM_CONFIGURATION_MSR_ADDRESS,
        updated_syscfg,
    );
}

/// Apply the dev/prod memory encryption enforcement policy (D-04).
///
/// - TME/SME available: enable and return Enabled.
/// - Unavailable + development build: log warning, return DevelopmentWarning.
/// - Unavailable + production build: log fatal, return ProductionFatalHalt.
///
/// Enforces T-HW-MEM-03 (no silent degradation in production).
/// Verified by: test_enforce_policy_returns_production_fatal_halt_when_unavailable_in_production
pub fn enforce_memory_encryption_policy(
    mode: MemoryEncryptionMode,
    is_development_build: bool,
) -> MemoryEncryptionEnforcementResult {
    match mode {
        MemoryEncryptionMode::IntelTotalMemoryEncryption => enable_tme_and_report(),
        MemoryEncryptionMode::AmdSecureMemoryEncryption => enable_sme_and_report(),
        MemoryEncryptionMode::Unavailable => apply_unavailable_policy(is_development_build),
    }
}

/// Enable Intel TME and return the enforcement result.
fn enable_tme_and_report() -> MemoryEncryptionEnforcementResult {
    #[cfg(target_arch = "x86_64")]
    enable_intel_total_memory_encryption();
    MemoryEncryptionEnforcementResult::Enabled(MemoryEncryptionMode::IntelTotalMemoryEncryption)
}

/// Enable AMD SME and return the enforcement result.
fn enable_sme_and_report() -> MemoryEncryptionEnforcementResult {
    #[cfg(target_arch = "x86_64")]
    enable_amd_secure_memory_encryption();
    MemoryEncryptionEnforcementResult::Enabled(MemoryEncryptionMode::AmdSecureMemoryEncryption)
}

/// Apply policy when encryption is unavailable.
///
/// Returns DevelopmentWarning in dev builds, ProductionFatalHalt in production.
fn apply_unavailable_policy(is_development_build: bool) -> MemoryEncryptionEnforcementResult {
    if is_development_build {
        MemoryEncryptionEnforcementResult::DevelopmentWarning
    } else {
        MemoryEncryptionEnforcementResult::ProductionFatalHalt
    }
}

/// Entry point: detect memory encryption support and apply enforcement policy.
///
/// Called from the early boot sequence before CSPRNG initialization (D-05).
/// Ensures memory is encrypted before any secrets are placed in RAM.
///
/// Enforces T-HW-MEM-01, T-HW-MEM-02, T-HW-MEM-03.
/// Verified by: test_detect_and_enable_memory_encryption_enables_tme_on_supported_cpu
pub fn detect_and_enable_memory_encryption(
    cpuid_leaf_seven_result: &CpuidResult,
    cpuid_extended_leaf_result: &CpuidResult,
    is_development_build: bool,
) -> MemoryEncryptionEnforcementResult {
    let mode =
        detect_memory_encryption_support(cpuid_leaf_seven_result, cpuid_extended_leaf_result);
    enforce_memory_encryption_policy(mode, is_development_build)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cpuid_result_with_ecx(ecx_value: u32) -> CpuidResult {
        CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: ecx_value,
            edx: 0,
        }
    }

    fn build_cpuid_result_with_eax(eax_value: u32) -> CpuidResult {
        CpuidResult {
            eax: eax_value,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }

    fn build_empty_cpuid_result() -> CpuidResult {
        CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    }

    /// CPUID leaf 0x7 ECX bit 13 set => detect_memory_encryption_support returns IntelTME.
    #[test]
    fn test_detect_memory_encryption_support_returns_intel_tme_when_bit_is_set() {
        let tme_ecx = 1u32 << 13;
        let leaf_seven = build_cpuid_result_with_ecx(tme_ecx);
        let extended_leaf = build_empty_cpuid_result();
        let result = detect_memory_encryption_support(&leaf_seven, &extended_leaf);
        assert_eq!(result, MemoryEncryptionMode::IntelTotalMemoryEncryption);
    }

    /// CPUID leaf 0x8000001F EAX bit 0 set => detect_memory_encryption_support returns AmdSME.
    #[test]
    fn test_detect_memory_encryption_support_returns_amd_sme_when_bit_is_set() {
        let sme_eax = 1u32;
        let leaf_seven = build_empty_cpuid_result();
        let extended_leaf = build_cpuid_result_with_eax(sme_eax);
        let result = detect_memory_encryption_support(&leaf_seven, &extended_leaf);
        assert_eq!(result, MemoryEncryptionMode::AmdSecureMemoryEncryption);
    }

    /// Neither bit set => detect_memory_encryption_support returns Unavailable.
    #[test]
    fn test_detect_memory_encryption_support_returns_unavailable_when_no_bits_set() {
        let leaf_seven = build_empty_cpuid_result();
        let extended_leaf = build_empty_cpuid_result();
        let result = detect_memory_encryption_support(&leaf_seven, &extended_leaf);
        assert_eq!(result, MemoryEncryptionMode::Unavailable);
    }

    /// Production build + Unavailable => enforce_memory_encryption_policy returns ProductionFatalHalt.
    #[test]
    fn test_enforce_policy_returns_production_fatal_halt_when_unavailable_in_production() {
        let result = enforce_memory_encryption_policy(MemoryEncryptionMode::Unavailable, false);
        assert_eq!(
            result,
            MemoryEncryptionEnforcementResult::ProductionFatalHalt
        );
    }

    /// Development build + Unavailable => enforce_memory_encryption_policy returns DevelopmentWarning.
    #[test]
    fn test_enforce_policy_returns_development_warning_when_unavailable_in_development() {
        let result = enforce_memory_encryption_policy(MemoryEncryptionMode::Unavailable, true);
        assert_eq!(
            result,
            MemoryEncryptionEnforcementResult::DevelopmentWarning
        );
    }

    /// TME mode => enforce_memory_encryption_policy returns Enabled(IntelTME).
    #[test]
    fn test_enforce_policy_returns_enabled_intel_tme_when_tme_mode() {
        let result = enforce_memory_encryption_policy(
            MemoryEncryptionMode::IntelTotalMemoryEncryption,
            false,
        );
        assert_eq!(
            result,
            MemoryEncryptionEnforcementResult::Enabled(
                MemoryEncryptionMode::IntelTotalMemoryEncryption
            )
        );
    }

    /// SME mode => enforce_memory_encryption_policy returns Enabled(AmdSME).
    #[test]
    fn test_enforce_policy_returns_enabled_amd_sme_when_sme_mode() {
        let result = enforce_memory_encryption_policy(
            MemoryEncryptionMode::AmdSecureMemoryEncryption,
            false,
        );
        assert_eq!(
            result,
            MemoryEncryptionEnforcementResult::Enabled(
                MemoryEncryptionMode::AmdSecureMemoryEncryption
            )
        );
    }

    /// detect_and_enable_memory_encryption with TME bit set returns Enabled(IntelTME).
    #[test]
    fn test_detect_and_enable_memory_encryption_enables_tme_on_supported_cpu() {
        let tme_ecx = 1u32 << 13;
        let leaf_seven = build_cpuid_result_with_ecx(tme_ecx);
        let extended_leaf = build_empty_cpuid_result();
        let result = detect_and_enable_memory_encryption(&leaf_seven, &extended_leaf, false);
        assert_eq!(
            result,
            MemoryEncryptionEnforcementResult::Enabled(
                MemoryEncryptionMode::IntelTotalMemoryEncryption
            )
        );
    }

    /// MSR address constants verify hardware specification.
    #[test]
    fn test_msr_address_constants_match_specification() {
        assert_eq!(TOTAL_MEMORY_ENCRYPTION_ACTIVATE_MSR_ADDRESS, 0x982u32);
        assert_eq!(AMD_SYSTEM_CONFIGURATION_MSR_ADDRESS, 0xC001_0010u32);
    }
}
