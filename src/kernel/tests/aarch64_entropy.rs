//! The boot seed, checked against the tree read off the target.
//!
//! The fixture is the real ADT from the M2 Pro (`Mac14,12`, `J474s`), so these
//! are not tests against a tree this repository invented. That distinction has
//! already earned its keep once: the ADT window arithmetic passed every
//! synthetic test and denied the machine's own firmware.

#![cfg(not(target_os = "none"))]

use brainix_kernel::aarch64_entropy::{
    boot_seed, boot_seed_span, derive, derive_pair, SeedQuality,
};

static REAL_ADT: &[u8] = include_bytes!("../../adt/tests/fixtures/mac14-12-j474s-adt.bin");

#[test]
fn boot_seed_is_present_in_the_real_tree() {
    let seed = boot_seed(REAL_ADT).expect("/chosen/random-seed is in the real tree");
    assert_eq!(seed.len(), 64, "iBoot leaves 64 bytes");
}

#[test]
fn boot_seed_matches_the_bytes_captured_from_the_machine() {
    // The exact bytes this fixture was captured with. Pinning them means a
    // change to the parser that shifts the property by a few bytes -- which
    // would still return 64 plausible-looking bytes -- fails here rather than
    // silently seeding the kernel from the middle of a neighbouring property.
    let seed = boot_seed(REAL_ADT).expect("present");
    assert_eq!(
        &seed[..8],
        &[0x75, 0x58, 0x16, 0x6c, 0x85, 0x1e, 0x95, 0x72],
        "first eight bytes as read off the target"
    );
}

#[test]
fn the_real_seed_is_usable() {
    let seed = boot_seed(REAL_ADT).expect("present");
    let quality = SeedQuality::of(seed);
    assert_eq!(quality.len, 64);
    assert!(quality.nonzero >= 60, "nonzero was {}", quality.nonzero);
    assert!(quality.usable(), "{quality:?}");
}

#[test]
fn an_all_zero_buffer_is_not_usable() {
    // This is `cl4-entropy` on the target: 192 bytes, none of them set. The
    // whole point of `usable` is that a caller which cannot tell this apart
    // from a real seed installs an all-zero key and reports success.
    let quality = SeedQuality::of(&[0u8; 192]);
    assert_eq!(quality.nonzero, 0);
    assert_eq!(quality.distinct, 1);
    assert!(!quality.usable());
}

#[test]
fn a_repeating_pattern_is_not_usable() {
    // Non-zero, full length, and worthless. `nonzero` alone would pass it.
    let filled = [0xA5u8; 64];
    let quality = SeedQuality::of(&filled);
    assert_eq!(quality.nonzero, 64);
    assert_eq!(quality.distinct, 1);
    assert!(!quality.usable(), "a single repeated byte is not entropy");
}

#[test]
fn a_short_seed_is_not_usable() {
    let quality = SeedQuality::of(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert!(!quality.usable(), "eight bytes is not a key seed");
}

#[test]
fn the_span_points_at_the_seed_inside_the_blob() {
    let (offset, len) = boot_seed_span(REAL_ADT).expect("present");
    assert_eq!(len, 64);
    let seed = boot_seed(REAL_ADT).expect("present");
    // The span is what the erase path writes through. If it pointed anywhere
    // else, erasing would leave the seed intact and destroy something else.
    assert_eq!(&REAL_ADT[offset..offset + len], seed);
}

#[test]
fn different_domains_derive_unrelated_values() {
    let seed = boot_seed(REAL_ADT).expect("present");
    let apia = derive(seed, b"pac.apia");
    let apib = derive(seed, b"pac.apib");
    assert_ne!(apia, apib, "domain separation is the point");
}

#[test]
fn a_domain_that_prefixes_another_does_not_collide() {
    // Without the length prefix, `derive(seed, b"pac")` and a scheme that
    // concatenated `b"pac"` with a later field could produce the same input.
    let seed = boot_seed(REAL_ADT).expect("present");
    assert_ne!(derive(seed, b"pac"), derive(seed, b"pac.apia"));
}

#[test]
fn derivation_is_deterministic_for_one_seed() {
    let seed = boot_seed(REAL_ADT).expect("present");
    assert_eq!(derive(seed, b"pac.apia"), derive(seed, b"pac.apia"));
}

#[test]
fn different_seeds_derive_different_keys() {
    // The property the whole exercise depends on: a per-boot seed has to give
    // per-boot keys, or rotating the seed buys nothing.
    let one = derive(&[1u8; 64], b"pac.apia");
    let two = derive(&[2u8; 64], b"pac.apia");
    assert_ne!(one, two);
}

#[test]
fn the_pair_is_the_first_sixteen_bytes_of_the_derived_value() {
    let seed = boot_seed(REAL_ADT).expect("present");
    let bytes = derive(seed, b"pac.apia");
    let (low, high) = derive_pair(seed, b"pac.apia");
    assert_eq!(low, u64::from_le_bytes(bytes[0..8].try_into().unwrap()));
    assert_eq!(high, u64::from_le_bytes(bytes[8..16].try_into().unwrap()));
    assert_ne!(low, high);
    assert_ne!(low, 0);
}

#[test]
fn a_missing_chosen_node_is_none_not_a_panic() {
    // A truncated or foreign tree must not take the kernel down on the entropy
    // path, which runs before there is any way to report a panic.
    assert!(boot_seed(&[0u8; 64]).is_none());
    assert!(boot_seed(&[]).is_none());
}
