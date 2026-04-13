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
//!
//! `CpuidResult` is defined here as a pure data type with no x86-specific code,
//! enabling host-target unit tests for all feature detection logic.

/// Result of a CPUID instruction execution.
///
/// Fields correspond to the four output registers: EAX, EBX, ECX, EDX.
/// Defined here (not in arch/) so that pure detection logic is testable on
/// any host target without an x86_64 dependency.
#[derive(Debug, Clone, Copy)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

/// Returns true if RDRAND is supported.
///
/// Checks ECX bit 30 of CPUID leaf 1 (standard feature flags).
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit).
/// Verified by: test_rdrand_detection_from_cpuid_when_bit_is_set
pub fn is_rdrand_supported(cpuid_leaf_one_result: &CpuidResult) -> bool {
    let rdrand_bit_position = 30u8;
    extract_bit(cpuid_leaf_one_result.ecx, rdrand_bit_position)
}

/// Returns true if RDSEED is supported.
///
/// Checks EBX bit 18 of CPUID leaf 7 (structured extended feature flags).
///
/// Verified by: test_rdseed_detection_from_cpuid_when_bit_is_set
pub fn is_rdseed_supported(cpuid_leaf_seven_result: &CpuidResult) -> bool {
    let rdseed_bit_position = 18u8;
    extract_bit(cpuid_leaf_seven_result.ebx, rdseed_bit_position)
}

/// Returns true if Enhanced IBRS (eIBRS) is supported.
///
/// Checks bit 1 of the IA32_ARCH_CAPABILITIES MSR value.
/// eIBRS is available on Intel ICL+ for Spectre v2 mitigation (D-01).
///
/// Verified by: test_enhanced_ibrs_detection_from_msr_when_bit_is_set
pub fn is_enhanced_ibrs_supported(arch_capabilities_msr_value: u64) -> bool {
    let enhanced_ibrs_bit_position = 1u8;
    extract_bit_from_u64(arch_capabilities_msr_value, enhanced_ibrs_bit_position)
}

/// Returns true if CET Indirect Branch Tracking (IBT) is supported.
///
/// Checks EDX bit 20 of CPUID leaf 7 subleaf 0.
///
/// Verified by: test_indirect_branch_tracking_detection_from_cpuid_when_bit_is_set
pub fn is_indirect_branch_tracking_supported(cpuid_leaf_seven_result: &CpuidResult) -> bool {
    let indirect_branch_tracking_bit_position = 20u8;
    extract_bit(cpuid_leaf_seven_result.edx, indirect_branch_tracking_bit_position)
}

/// Returns true if Intel TME (Total Memory Encryption) is supported.
///
/// Checks ECX bit 13 of CPUID leaf 7.
///
/// Verified by: test_total_memory_encryption_detection_from_cpuid_when_bit_is_set
pub fn is_total_memory_encryption_supported(cpuid_leaf_seven_result: &CpuidResult) -> bool {
    let total_memory_encryption_bit_position = 13u8;
    extract_bit(cpuid_leaf_seven_result.ecx, total_memory_encryption_bit_position)
}

/// Returns true if AMD SME (Secure Memory Encryption) is supported.
///
/// Checks EAX bit 0 of CPUID leaf 0x8000001F (AMD extended leaf).
///
/// Verified by: test_secure_memory_encryption_detection_from_cpuid_when_bit_is_set
pub fn is_secure_memory_encryption_supported(cpuid_leaf_extended_result: &CpuidResult) -> bool {
    let secure_memory_encryption_bit_position = 0u8;
    extract_bit(cpuid_leaf_extended_result.eax, secure_memory_encryption_bit_position)
}

/// Extracts a single bit from a u32 register value at the given bit position.
fn extract_bit(register_value: u32, bit_position: u8) -> bool {
    let shift_amount = bit_position as u32;
    let extracted_bit = (register_value >> shift_amount) & 1u32;
    extracted_bit != 0
}

/// Extracts a single bit from a u64 value at the given bit position.
fn extract_bit_from_u64(value: u64, bit_position: u8) -> bool {
    let shift_amount = bit_position as u64;
    let extracted_bit = (value >> shift_amount) & 1u64;
    extracted_bit != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cpuid_result_with_ecx(ecx_value: u32) -> CpuidResult {
        CpuidResult { eax: 0, ebx: 0, ecx: ecx_value, edx: 0 }
    }

    fn build_cpuid_result_with_ebx(ebx_value: u32) -> CpuidResult {
        CpuidResult { eax: 0, ebx: ebx_value, ecx: 0, edx: 0 }
    }

    fn build_cpuid_result_with_edx(edx_value: u32) -> CpuidResult {
        CpuidResult { eax: 0, ebx: 0, ecx: 0, edx: edx_value }
    }

    fn build_cpuid_result_with_eax(eax_value: u32) -> CpuidResult {
        CpuidResult { eax: eax_value, ebx: 0, ecx: 0, edx: 0 }
    }

    /// CPUID leaf 1 ECX bit 30 set => RDRAND supported.
    #[test]
    fn test_rdrand_detection_from_cpuid_when_bit_is_set() {
        let rdrand_ecx = 1u32 << 30;
        let cpuid_result = build_cpuid_result_with_ecx(rdrand_ecx);
        assert!(is_rdrand_supported(&cpuid_result));
    }

    /// CPUID leaf 1 ECX bit 30 clear => RDRAND not supported.
    #[test]
    fn test_rdrand_detection_from_cpuid_when_bit_is_clear() {
        let cpuid_result = build_cpuid_result_with_ecx(0u32);
        assert!(!is_rdrand_supported(&cpuid_result));
    }

    /// CPUID leaf 7 EBX bit 18 set => RDSEED supported.
    #[test]
    fn test_rdseed_detection_from_cpuid_when_bit_is_set() {
        let rdseed_ebx = 1u32 << 18;
        let cpuid_result = build_cpuid_result_with_ebx(rdseed_ebx);
        assert!(is_rdseed_supported(&cpuid_result));
    }

    /// CPUID leaf 7 EBX bit 18 clear => RDSEED not supported.
    #[test]
    fn test_rdseed_detection_from_cpuid_when_bit_is_clear() {
        let cpuid_result = build_cpuid_result_with_ebx(0u32);
        assert!(!is_rdseed_supported(&cpuid_result));
    }

    /// IA32_ARCH_CAPABILITIES MSR bit 1 set => eIBRS supported.
    #[test]
    fn test_enhanced_ibrs_detection_from_msr_when_bit_is_set() {
        let enhanced_ibrs_msr_value = 1u64 << 1;
        assert!(is_enhanced_ibrs_supported(enhanced_ibrs_msr_value));
    }

    /// IA32_ARCH_CAPABILITIES MSR bit 1 clear => eIBRS not supported.
    #[test]
    fn test_enhanced_ibrs_detection_from_msr_when_bit_is_clear() {
        assert!(!is_enhanced_ibrs_supported(0u64));
    }

    /// CPUID leaf 7 EDX bit 20 set => IBT supported.
    #[test]
    fn test_indirect_branch_tracking_detection_from_cpuid_when_bit_is_set() {
        let indirect_branch_tracking_edx = 1u32 << 20;
        let cpuid_result = build_cpuid_result_with_edx(indirect_branch_tracking_edx);
        assert!(is_indirect_branch_tracking_supported(&cpuid_result));
    }

    /// CPUID leaf 7 ECX bit 13 set => TME supported.
    #[test]
    fn test_total_memory_encryption_detection_from_cpuid_when_bit_is_set() {
        let total_memory_encryption_ecx = 1u32 << 13;
        let cpuid_result = build_cpuid_result_with_ecx(total_memory_encryption_ecx);
        assert!(is_total_memory_encryption_supported(&cpuid_result));
    }

    /// CPUID extended leaf EAX bit 0 set => SME supported.
    #[test]
    fn test_secure_memory_encryption_detection_from_cpuid_when_bit_is_set() {
        let secure_memory_encryption_eax = 1u32;
        let cpuid_result = build_cpuid_result_with_eax(secure_memory_encryption_eax);
        assert!(is_secure_memory_encryption_supported(&cpuid_result));
    }
}
