//! Page-table walking, against synthetic tables and against the machine.
//!
//! The live-hardware check lives in `kernel_probe`, not here: it walks the
//! tables the target is actually running on and compares with the MMU's own
//! answer from `AT s1e2r`. On 2026-08-16 both produced `0x1000d4d4938` for the
//! same input, terminating on a **block** descriptor `0x1000c000601` at level 2
//! of 4, with a 16 KiB granule.
//!
//! What that hardware run cannot cover is the failure paths, because the live
//! tables are well-formed. Those are here.

use brainix_kernel::aarch64_walk::{walk, WalkConfig, WalkError};
use core::cell::Cell;

/// The target's own `TCR_EL2`, read 2026-08-16.
const TARGET_TCR: u64 = 0x0000_0003_7510_b510;

#[test]
fn the_targets_tcr_decodes_to_a_sixteen_kilobyte_granule() {
    let config = WalkConfig::from_tcr(TARGET_TCR).expect("the machine's own TCR must decode");
    assert_eq!(config.granule_bits, 14, "TG0 = 0b10 is 16 KiB");
    assert_eq!(config.t0sz, 16);
    assert_eq!(config.levels(), 4, "matches what the hardware run reported");
}

/// The encoding is not in size order, and reading it as if it were is a bug
/// that only shows on the granules Apple Silicon actually uses.
#[test]
fn the_granule_encoding_is_not_in_size_order() {
    let with_tg0 = |tg0: u64| WalkConfig::from_tcr((tg0 << 14) | 16);
    assert_eq!(with_tg0(0b00).unwrap().granule_bits, 12, "0b00 is 4 KiB");
    assert_eq!(
        with_tg0(0b01).unwrap().granule_bits,
        16,
        "0b01 is 64 KiB, not 16"
    );
    assert_eq!(
        with_tg0(0b10).unwrap().granule_bits,
        14,
        "0b10 is 16 KiB, not 64"
    );
    assert!(with_tg0(0b11).is_none(), "0b11 is reserved and must deny");
}

#[test]
fn an_out_of_range_address_denies_rather_than_wrapping() {
    // T0SZ 32 means a 32-bit input address.
    let config = WalkConfig::from_tcr(32).expect("decodes");
    let result = walk(0x1000, 1u64 << 33, config, |_| 0);
    assert_eq!(result.unwrap_err(), WalkError::AddressOutOfRange);
}

#[test]
fn an_invalid_descriptor_names_the_level_it_was_found_at() {
    let config = WalkConfig::from_tcr(TARGET_TCR).unwrap();
    // Every read returns 0: bits [1:0] = 0b00, invalid.
    let result = walk(0x4000, 0x1_0000, config, |_| 0);
    match result.unwrap_err() {
        WalkError::InvalidDescriptor { level, descriptor } => {
            assert_eq!(level, 0, "the first lookup is where it fails");
            assert_eq!(descriptor, 0);
        }
        other => panic!("expected InvalidDescriptor, got {other:?}"),
    }
}

#[test]
fn a_block_encoding_at_the_final_level_denies() {
    // 0b01 at the last level is a reserved encoding, not a large page.
    // Treating it as one would resolve to a plausible wrong address.
    let config = WalkConfig::from_tcr(TARGET_TCR).unwrap();
    let levels = config.levels();
    // `walk` takes `impl Fn`, not `FnMut`, deliberately: a walker that needs to
    // mutate its reader is a walker with hidden state. `Cell` is the cheapest
    // way for a *test* to count calls without relaxing that.
    let seen = Cell::new(0u32);
    let result = walk(0x4000, 0, config, |_| {
        seen.set(seen.get() + 1);
        // Tables all the way down, then 0b01 at the final level.
        if seen.get() < levels {
            0b11 | 0x8000
        } else {
            0b01 | 0x8000
        }
    });
    match result.unwrap_err() {
        WalkError::BlockAtIllegalLevel { level } => {
            assert_eq!(level, levels - 1);
        }
        other => panic!("expected BlockAtIllegalLevel, got {other:?}"),
    }
}

#[test]
fn a_four_kilobyte_page_resolves_with_its_offset_preserved() {
    // T0SZ 16, 4 KiB granule: four levels, nine bits each.
    let config = WalkConfig::from_tcr(16).unwrap();
    assert_eq!(config.granule_bits, 12);

    const PAGE: u64 = 0x0000_0001_2345_0000;
    let levels = config.levels();
    let seen = Cell::new(0u32);
    let translation = walk(0x4000, 0xABC, config, |_| {
        seen.set(seen.get() + 1);
        if seen.get() < levels {
            0b11 | 0x9000
        } else {
            0b11 | PAGE
        }
    })
    .expect("a well-formed chain must resolve");

    assert_eq!(
        translation.physical_address,
        PAGE | 0xABC,
        "the in-page offset must survive translation"
    );
    assert!(!translation.is_block);
}
