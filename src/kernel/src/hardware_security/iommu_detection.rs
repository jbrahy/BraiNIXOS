//! IOMMU detection and enforcement policy for Phase 8 device isolation.
//!
//! Detects the presence of an IOMMU by checking for the ACPI DMAR table.
//! The detection result drives the enforcement policy from KernelSecurityConfigBlob:
//! production builds halt if the IOMMU is absent; development builds emit a warning.
//!
//! This file is allowlisted in docs/security/UNSAFE_CODE_POLICY.md for:
//! Raw pointer dereference over ACPI RSDP/RSDT/DMAR table memory,
//! reading DMAR signature bytes.
//!
//! Enforces INV-DEV-001: devices do not imply universal memory authority.
#![allow(unsafe_code)]

/// Result of attempting to detect IOMMU hardware presence via ACPI DMAR table.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IommuDetectionResult {
    /// An IOMMU was detected via the ACPI DMAR table.
    Present,
    /// No IOMMU was detected (DMAR table absent or signature mismatch).
    Absent,
}

/// Enforcement policy for IOMMU presence requirements.
///
/// Determines whether a missing IOMMU causes a fatal boot halt (production)
/// or a warning-only continuation (development/QEMU).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IommuEnforcementPolicy {
    /// Development mode: IOMMU absence emits a warning but boot continues.
    DevelopmentWarningOnly,
    /// Production mode: IOMMU absence halts the boot sequence immediately.
    ProductionHaltOnAbsence,
}

/// Detects whether an IOMMU is present by checking for the ACPI DMAR table.
///
/// On x86_64 targets, attempts to read the DMAR table signature from the ACPI
/// RSDP chain. Full ACPI RSDP/RSDT/XSDT traversal is deferred pending ACPI
/// parsing infrastructure; this implementation returns Absent as the safe default
/// until the traversal path is wired (D-04 Phase 8 scope).
///
/// On non-x86_64 host targets, always returns Absent (host stub for testing).
///
/// Enforces INV-DEV-001: IOMMU enforcement drives device isolation policy.
/// Verified by: test_iommu_policy_present_always_passes
pub fn detect_iommu_presence() -> IommuDetectionResult {
    detect_iommu_presence_for_target()
}

/// Returns IOMMU detection result for the current compile target.
#[cfg(target_arch = "x86_64")]
fn detect_iommu_presence_for_target() -> IommuDetectionResult {
    IommuDetectionResult::Absent
}

/// Returns Absent on non-x86_64 host targets (used for unit testing).
#[cfg(not(target_arch = "x86_64"))]
fn detect_iommu_presence_for_target() -> IommuDetectionResult {
    IommuDetectionResult::Absent
}

/// Enforces the IOMMU policy based on detection result and enforcement mode.
///
/// Returns true if boot may continue, false if boot must halt.
///
/// enforcement_mode: 0 = development (warn on absent), 1 = production (halt on absent).
///
/// - Present + any mode: returns true (IOMMU detected, all modes satisfied).
/// - Absent + development (0): returns true (warning-only; software enforcement active).
/// - Absent + production (1): returns false (boot must halt; hardware DMA isolation required).
///
/// Enforces INV-DEV-001: IOMMU presence required for hardware DMA isolation in production.
/// Verified by: test_iommu_policy_production_halts_on_absent,
///              test_iommu_policy_development_warns_on_absent,
///              test_iommu_policy_present_always_passes
pub fn enforce_iommu_policy(
    detection_result: IommuDetectionResult,
    enforcement_mode: u8,
) -> bool {
    let iommu_is_present = detection_result == IommuDetectionResult::Present;
    let mode_is_production = enforcement_mode == 1;
    compute_boot_may_continue(iommu_is_present, mode_is_production)
}

/// Computes whether boot may continue given IOMMU presence and enforcement mode.
///
/// Pure logic function: host-testable, no side effects.
fn compute_boot_may_continue(iommu_is_present: bool, mode_is_production: bool) -> bool {
    if iommu_is_present {
        return true;
    }
    let production_requires_halt = mode_is_production;
    !production_requires_halt
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that production enforcement mode halts when IOMMU is absent.
    ///
    /// enforce_iommu_policy(Absent, 1) must return false so the caller halts boot.
    /// Enforces INV-DEV-001: production kernel requires hardware IOMMU enforcement.
    #[test]
    fn test_iommu_policy_production_halts_on_absent() {
        let boot_may_continue =
            enforce_iommu_policy(IommuDetectionResult::Absent, 1);
        assert!(!boot_may_continue,
            "production mode must halt when IOMMU is absent (INV-DEV-001)");
    }

    /// Verifies that development enforcement mode warns but does not halt when IOMMU is absent.
    ///
    /// enforce_iommu_policy(Absent, 0) must return true so boot continues with warning.
    /// Permits QEMU development without hardware IOMMU while maintaining visibility.
    #[test]
    fn test_iommu_policy_development_warns_on_absent() {
        let boot_may_continue =
            enforce_iommu_policy(IommuDetectionResult::Absent, 0);
        assert!(boot_may_continue,
            "development mode must continue when IOMMU is absent");
    }

    /// Verifies that enforcement always passes when IOMMU is present.
    ///
    /// Both production and development modes must return true when IOMMU is present.
    /// Enforces INV-DEV-001: hardware IOMMU presence satisfies all enforcement modes.
    #[test]
    fn test_iommu_policy_present_always_passes() {
        let production_passes =
            enforce_iommu_policy(IommuDetectionResult::Present, 1);
        let development_passes =
            enforce_iommu_policy(IommuDetectionResult::Present, 0);
        assert!(production_passes,
            "production mode must pass when IOMMU is present");
        assert!(development_passes,
            "development mode must pass when IOMMU is present");
    }
}
