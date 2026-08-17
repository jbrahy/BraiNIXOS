//! `ID_AA64MMFR0_EL1` decoding, against the value the target actually reports.
//!
//! These run on the host, but the input is not invented: `0x110012120f100003`
//! was read out of the deployment machine on 2026-08-16 by `kernel_probe`,
//! running on the M2 Pro through m1n1's proxy.
//!
//! The decode is worth testing rather than eyeballing because the three granule
//! fields do **not** share a sentinel. 4 KiB and 64 KiB use `0b1111` for "not
//! supported"; 16 KiB uses `0b0000`. Reading the manual quickly gives you three
//! identical comparisons and a `TCR_EL1` that selects a granule the silicon
//! does not implement, which on this hardware is unrecoverable and silent.



use brainix_kernel::aarch64_ident::MemoryModel;

/// Read from the target, 2026-08-16.
const TARGET_ID_AA64MMFR0: u64 = 0x1100_1212_0f10_0003;

#[test]
fn the_targets_own_value_decodes_to_what_the_hardware_supports() {
    let model = MemoryModel::from_id_register(TARGET_ID_AA64MMFR0);

    assert_eq!(model.physical_address_bits, Some(42), "PARange 0b0011");
    assert!(model.granule_4k, "TGran4 = 0b0000, supported");
    assert!(model.granule_16k, "TGran16 = 0b0001, supported");
    assert!(
        !model.granule_64k,
        "TGran64 = 0b1111, NOT supported -- selecting it in TCR_EL1 would be \
         unrecoverable on this machine"
    );
}

#[test]
fn the_sixteen_kilobyte_sentinel_is_the_opposite_of_the_others() {
    // The whole reason this decode is a tested function. A field of all-ones
    // means "absent" for 4K and 64K, and "supported, revision 15" for 16K.
    let all_ones_everywhere = 0xFFFF_FFFF_FFFF_FFFF;
    let model = MemoryModel::from_id_register(all_ones_everywhere);

    assert!(!model.granule_4k, "0b1111 means absent for 4K");
    assert!(!model.granule_64k, "0b1111 means absent for 64K");
    assert!(model.granule_16k, "0b1111 does NOT mean absent for 16K");

    let all_zero = 0;
    let model = MemoryModel::from_id_register(all_zero);
    assert!(model.granule_4k, "0b0000 means supported for 4K");
    assert!(model.granule_64k, "0b0000 means supported for 64K");
    assert!(!model.granule_16k, "0b0000 means absent for 16K");
}

#[test]
fn every_defined_physical_address_encoding_is_mapped() {
    let expected = [
        (0b0000, 32),
        (0b0001, 36),
        (0b0010, 40),
        (0b0011, 42),
        (0b0100, 44),
        (0b0101, 48),
        (0b0110, 52),
    ];
    for (encoding, bits) in expected {
        assert_eq!(
            MemoryModel::from_id_register(encoding).physical_address_bits,
            Some(bits),
            "PARange {encoding:#06b}"
        );
    }
}

#[test]
fn reserved_physical_address_encodings_deny_rather_than_guessing() {
    for encoding in 0b0111..=0b1111 {
        assert_eq!(
            MemoryModel::from_id_register(encoding).physical_address_bits,
            None,
            "reserved PARange {encoding:#06b} must not be given a size; a guess \
             here sizes the page tables wrong"
        );
    }
}
