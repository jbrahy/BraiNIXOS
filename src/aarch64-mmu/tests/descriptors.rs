//! The descriptor bits, against the architecture reference manual's fields.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_aarch64_mmu::{Descriptor, DescriptorError, Granule, Level, Permission};

const SIXTEEN_KIB: u64 = 16384;

#[test]
fn the_apple_silicon_granule_is_sixteen_kibibytes() {
    assert_eq!(Granule::Medium.bytes(), SIXTEEN_KIB);
    assert_eq!(Granule::Small.bytes(), 4096);
    assert_eq!(Granule::Large.bytes(), 65536);

    assert!(Granule::Medium.is_aligned(0));
    assert!(Granule::Medium.is_aligned(SIXTEEN_KIB * 3));
    assert!(
        !Granule::Medium.is_aligned(4096),
        "a 4 KiB page is not aligned at 16 KiB"
    );
}

#[test]
fn a_writable_page_sets_both_execute_never_bits() {
    // Not merely the one for the level being mapped: a page writable at EL0 and
    // executable at EL1 is the same defect wearing a different hat.
    let data = Descriptor::page(
        SIXTEEN_KIB,
        Permission::ReadWriteNoExecute,
        Level::User,
        Granule::Medium,
    )
    .expect("aligned");

    assert!(data.bits_permit_write());
    assert!(!data.bits_permit_execute());
    assert!(!data.violates_write_xor_execute());
    assert_ne!(data.bits() & (1 << 53), 0, "PXN");
    assert_ne!(data.bits() & (1 << 54), 0, "UXN");
}

#[test]
fn an_executable_page_is_never_writable_and_never_executable_at_the_other_level() {
    let kernel_code = Descriptor::page(
        SIXTEEN_KIB * 2,
        Permission::ReadOnlyExecute,
        Level::Kernel,
        Granule::Medium,
    )
    .expect("aligned");
    assert!(!kernel_code.bits_permit_write());
    assert!(kernel_code.bits_permit_execute());
    assert_ne!(
        kernel_code.bits() & (1 << 54),
        0,
        "UXN: never executable at EL0"
    );

    let user_code = Descriptor::page(
        SIXTEEN_KIB * 3,
        Permission::ReadOnlyExecute,
        Level::User,
        Granule::Medium,
    )
    .expect("aligned");
    assert_ne!(
        user_code.bits() & (1 << 53),
        0,
        "PXN: never executable at EL1"
    );
}

#[test]
fn sealed_weights_are_neither_writable_nor_executable() {
    // What WEIGHTS_REGION becomes after modeld's S10 seal.
    let sealed = Descriptor::page(
        SIXTEEN_KIB * 4,
        Permission::ReadOnlyNoExecute,
        Level::User,
        Granule::Medium,
    )
    .expect("aligned");
    assert!(!sealed.bits_permit_write());
    assert!(!sealed.bits_permit_execute());
}

#[test]
fn every_descriptor_carries_the_access_flag_and_the_page_type() {
    // A descriptor without the access flag faults on first touch, which is a
    // mapping that looks correct in a table dump and does not work.
    for permission in [
        Permission::ReadOnlyExecute,
        Permission::ReadWriteNoExecute,
        Permission::ReadOnlyNoExecute,
    ] {
        for level in [Level::Kernel, Level::User] {
            let descriptor =
                Descriptor::page(SIXTEEN_KIB, permission, level, Granule::Medium).expect("aligned");
            assert_ne!(descriptor.bits() & (1 << 10), 0, "access flag");
            assert_eq!(descriptor.bits() & 0b11, 0b11, "page descriptor type");
            assert_eq!(descriptor.permission(), permission);
            assert_eq!(descriptor.granule(), Granule::Medium);
        }
    }
}

#[test]
fn a_misaligned_or_oversized_address_denies_rather_than_truncating() {
    // A truncated address maps the wrong page: a mapping that works until it
    // corrupts something.
    assert_eq!(
        Descriptor::page(
            SIXTEEN_KIB + 8,
            Permission::ReadWriteNoExecute,
            Level::User,
            Granule::Medium
        ),
        Err(DescriptorError::Misaligned)
    );
    assert_eq!(
        Descriptor::page(
            0xFFFF_0000_0000_0000,
            Permission::ReadWriteNoExecute,
            Level::User,
            Granule::Medium
        ),
        Err(DescriptorError::AddressTooLarge)
    );
}

#[test]
fn the_output_address_reads_back_exactly() {
    for multiple in [0u64, 1, 2, 1024] {
        let address = SIXTEEN_KIB * multiple;
        let descriptor = Descriptor::page(
            address,
            Permission::ReadOnlyNoExecute,
            Level::Kernel,
            Granule::Medium,
        )
        .expect("aligned");
        assert_eq!(descriptor.output_address(), address);
    }
}

#[test]
fn the_permission_type_admits_no_writable_executable_variant() {
    // The invariant is the absence of a fourth variant, so this test is about
    // the enum's shape: every variant is writable or executable, never both.
    for permission in [
        Permission::ReadOnlyExecute,
        Permission::ReadWriteNoExecute,
        Permission::ReadOnlyNoExecute,
    ] {
        assert!(!(permission.is_writable() && permission.is_executable()));
    }
}
