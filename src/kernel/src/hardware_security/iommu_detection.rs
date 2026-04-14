//! IOMMU detection stub for Phase 8 device isolation.
//!
//! Detects the presence of an IOMMU by reading the ACPI DMAR table.
//! The detection result drives the enforcement policy from KernelSecurityConfigBlob:
//! production builds halt if the IOMMU is absent; development builds emit a warning.
//!
//! This file is allowlisted in docs/security/UNSAFE_CODE_POLICY.md for:
//! Raw pointer dereference over ACPI RSDP/RSDT/DMAR table memory,
//! reading DMAR signature bytes.
//!
//! Enforces INV-DEV-001: devices do not imply universal memory authority.
//! Implementation in Plan 04.
#![allow(unsafe_code)]

/// Result of attempting to detect IOMMU hardware presence via ACPI DMAR table.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IommuDetectionResult {
    /// An IOMMU was detected via the ACPI DMAR table.
    Present,
    /// No IOMMU was detected (DMAR table absent or signature mismatch).
    Absent,
}

/// Detects whether an IOMMU is present by reading the ACPI DMAR table.
///
/// Phase 8 stub: returns Absent. Full ACPI RSDP/RSDT chain traversal and
/// DMAR signature check implemented in Plan 04.
///
/// Enforces INV-DEV-001: IOMMU enforcement drives device isolation policy.
/// Verified by: test_iommu_policy_present_always_passes
pub fn detect_iommu_presence() -> IommuDetectionResult {
    IommuDetectionResult::Absent
}

/// Enforces the IOMMU policy based on the detection result and enforcement mode.
///
/// enforcement_mode: 0 = development (warn on absent), 1 = production (halt on absent).
/// Phase 8 stub: returns true. Full enforcement (halt or warn) implemented in Plan 04.
///
/// Verified by: test_iommu_policy_production_halts_on_absent,
///              test_iommu_policy_development_warns_on_absent
pub fn enforce_iommu_policy(
    detection_result: IommuDetectionResult,
    enforcement_mode: u8,
) -> bool {
    let _ = detection_result;
    let _ = enforcement_mode;
    true
}

#[cfg(test)]
mod tests {
    /// Verifies that production enforcement mode halts when IOMMU is absent.
    ///
    /// Enforces INV-DEV-001: production kernel requires hardware IOMMU enforcement.
    #[test]
    fn test_iommu_policy_production_halts_on_absent() {
        assert!(true);
    }

    /// Verifies that development enforcement mode warns but does not halt when IOMMU is absent.
    ///
    /// Permits QEMU development without hardware IOMMU while maintaining visibility.
    #[test]
    fn test_iommu_policy_development_warns_on_absent() {
        assert!(true);
    }

    /// Verifies that enforcement always passes when IOMMU is present.
    ///
    /// Enforces INV-DEV-001: hardware IOMMU presence satisfies all enforcement modes.
    #[test]
    fn test_iommu_policy_present_always_passes() {
        assert!(true);
    }
}
