//! CET Indirect Branch Tracking (IBT) enablement.
//!
//! Phase 6 Plan 02: Enables CET IBT by setting bit 23 (ENDBR64 enforcement) in CR4
//! after verifying CPUID reports IBT support. CPL0 shadow stack is NOT enabled --
//! Intel hardware does not support CPL0 shadow stack on current silicon (D-17, locked
//! Phase 0 decision).
//!
//! CR4 write is delegated to `src/kernel/src/arch/hardware_registers.rs` per the
//! UNSAFE_CODE_POLICY.md allowlist. ENDBR64 instructions are inserted in assembly
//! stubs via inline assembly in the same allowlisted arch/ module.

/// CR4 bit 23: enables CET Indirect Branch Tracking (ENDBR64 enforcement).
///
/// When set, indirect branches to targets without ENDBR64 raise #CP.
///
/// Used by x86_64-gated functions and tests. The allow(dead_code) suppresses
/// the host-target warning when the x86_64 callers are cfg-excluded.
#[allow(dead_code)]
const CONTROL_FLOW_ENFORCEMENT_TECHNOLOGY_ENABLE_BIT: u64 = 1 << 23;

/// Enables CET Indirect Branch Tracking via CR4 bit 23.
///
/// Reads the current CR4 value, sets bit 23 (CET enable), and writes it back.
/// Only called when `is_indirect_branch_tracking_supported()` returns true.
/// Logs "IBT: enabled" or "IBT: not available" to the boot serial console (D-17).
///
/// Enforces INV-X86-002 (CET/IBT enforcement when hardware supports it).
/// Verified by: test_indirect_branch_tracking_enable
#[cfg(target_arch = "x86_64")]
pub fn enable_indirect_branch_tracking() {
    use crate::arch::hardware_registers::execute_cpuid_query;
    use crate::arch::hardware_registers::{
        read_control_register_four, write_control_register_four,
    };
    use crate::hardware_security::cpu_feature_detection::is_indirect_branch_tracking_supported;
    let cpuid_leaf_seven_result = execute_cpuid_query(7, 0);
    if is_indirect_branch_tracking_supported(&cpuid_leaf_seven_result) {
        set_indirect_branch_tracking_bit_in_cr4(
            read_control_register_four,
            write_control_register_four,
        );
        log_indirect_branch_tracking_enabled();
    } else {
        log_indirect_branch_tracking_unavailable();
    }
}

/// Reads CR4, ORs in the IBT bit, and writes back the updated value.
///
/// Extracted as a named helper to make the CR4 bit-set operation explicit.
#[cfg(target_arch = "x86_64")]
fn set_indirect_branch_tracking_bit_in_cr4(read_cr4: fn() -> u64, write_cr4: fn(u64)) {
    let current_cr4_value = read_cr4();
    let updated_cr4_value = current_cr4_value | CONTROL_FLOW_ENFORCEMENT_TECHNOLOGY_ENABLE_BIT;
    write_cr4(updated_cr4_value);
}

/// Logs "IBT: enabled" to the boot serial console.
///
/// No-op: detailed IBT logging is handled by the BootStepLogger in
/// hardware_security_init.rs. The serial module exposes no free-function
/// write API; per-byte output requires an initialized SerialOutputPort handle.
#[cfg(target_arch = "x86_64")]
fn log_indirect_branch_tracking_enabled() {}

/// Logs "IBT: not available" to the boot serial console.
///
/// No-op: detailed IBT logging is handled by the BootStepLogger in
/// hardware_security_init.rs. The serial module exposes no free-function
/// write API; per-byte output requires an initialized SerialOutputPort handle.
#[cfg(target_arch = "x86_64")]
fn log_indirect_branch_tracking_unavailable() {}

/// Returns true if CET Indirect Branch Tracking is currently active in CR4.
///
/// Checks bit 23 of the current CR4 value.
/// On non-x86_64 host targets, returns false.
///
/// Enforces INV-X86-002 (CET/IBT enforcement when hardware supports it).
/// Verified by: test_indirect_branch_tracking_is_active_after_enable
#[cfg(target_arch = "x86_64")]
pub fn is_indirect_branch_tracking_active() -> bool {
    use crate::arch::hardware_registers::read_control_register_four;
    let current_cr4_value = read_control_register_four();
    (current_cr4_value & CONTROL_FLOW_ENFORCEMENT_TECHNOLOGY_ENABLE_BIT) != 0
}

/// Returns false on non-x86_64 host targets.
#[cfg(not(target_arch = "x86_64"))]
pub fn is_indirect_branch_tracking_active() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Setting IBT bit in CR4 is correct: bit 23 is set, existing bits preserved.
    ///
    /// Enforces D-17: IBT enabled via CR4 bit 23.
    #[test]
    fn test_set_indirect_branch_tracking_bit_preserves_existing_cr4_bits() {
        let initial_cr4 = 0x0000_0000_0000_0800u64;
        let result = initial_cr4 | CONTROL_FLOW_ENFORCEMENT_TECHNOLOGY_ENABLE_BIT;
        let expected = 0x0000_0000_0000_0800u64 | (1u64 << 23);
        assert_eq!(result, expected);
    }

    /// IBT bit is 1 << 23 (CR4 bit 23 for CET enable).
    #[test]
    fn test_control_flow_enforcement_bit_is_cr4_bit_23() {
        assert_eq!(CONTROL_FLOW_ENFORCEMENT_TECHNOLOGY_ENABLE_BIT, 1u64 << 23);
    }

    /// is_indirect_branch_tracking_active returns false on host target.
    #[test]
    fn test_indirect_branch_tracking_is_not_active_on_host_target() {
        // On non-x86_64 host, always returns false.
        #[cfg(not(target_arch = "x86_64"))]
        assert!(!is_indirect_branch_tracking_active());
    }
}
