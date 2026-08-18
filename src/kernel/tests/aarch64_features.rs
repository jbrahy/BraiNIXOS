//! Feature decoding, against the target's own identification registers.
//!
//! Read from the deployment machine on 2026-08-16 through `kernel_probe`.
//! These are not illustrative values.

use brainix_kernel::aarch64_features::{ControlFlowSupport, RandomSupport};

const TARGET_ISAR0: u64 = 0x0221_1001_1021_2120;
const TARGET_ISAR1: u64 = 0x0010_1111_1021_1402;
const TARGET_PFR1: u64 = 0x0000_0000_0000_0021;

/// The M2 Pro has no `FEAT_RNG`, and the kernel must not assume otherwise.
#[test]
fn the_target_has_no_hardware_random_number_generator() {
    let support = RandomSupport::from_isar0(TARGET_ISAR0);
    assert!(
        !support.present,
        "ID_AA64ISAR0_EL1[63:60] is 0 on this part. A kernel that calls RNDR \
         anyway takes an undefined-instruction exception at its first request \
         for entropy, during early boot, before a console exists."
    );
}

#[test]
fn a_part_that_does_implement_it_is_detected() {
    assert!(RandomSupport::from_isar0(0b0001 << 60).present);
    // 0b0010 is FEAT_RNG_TRAP, a different thing, and not RNDR.
    assert!(!RandomSupport::from_isar0(0b0010 << 60).present);
}

/// The trap that matters on Apple Silicon.
#[test]
fn apple_pointer_authentication_is_implementation_defined_not_qarma() {
    let support = ControlFlowSupport::from_id_registers(TARGET_ISAR1, TARGET_PFR1);

    assert!(
        !support.address_auth_qarma,
        "APA is 0 on this part -- checking only this field is the bug"
    );
    assert!(
        support.address_auth_impdef,
        "API is non-zero: Apple implements PAC with its own algorithm"
    );
    assert!(
        support.address_auth(),
        "so pointer authentication IS available, and a kernel that looks only \
         at the QARMA field silently gives up a mitigation it could have had"
    );

    assert!(!support.generic_auth_qarma);
    assert!(support.generic_auth_impdef);
}

#[test]
fn the_target_supports_branch_target_identification() {
    let support = ControlFlowSupport::from_id_registers(TARGET_ISAR1, TARGET_PFR1);
    assert!(
        support.branch_target_identification,
        "ID_AA64PFR1_EL1.BT = 1"
    );
}

#[test]
fn absent_means_absent_rather_than_defaulting_to_present() {
    let none = ControlFlowSupport::from_id_registers(0, 0);
    assert!(!none.address_auth());
    assert!(!none.address_auth_qarma);
    assert!(!none.address_auth_impdef);
    assert!(!none.generic_auth_qarma);
    assert!(!none.generic_auth_impdef);
    assert!(!none.branch_target_identification);
}
