//! Unknown means refuse. Every test here is a way of not falling back.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity)]

use brainix_platform_select::{select, KnownDevice, SelectionError, KNOWN_AIC_REVISIONS};

const KNOWN: [KnownDevice; 2] = [
    KnownDevice {
        compatible: "aic,2",
        revision: "aic-v2",
    },
    KnownDevice {
        compatible: "dart,t8020",
        revision: "dart-t8020",
    },
];

#[test]
fn an_exactly_matching_string_selects_its_device() {
    let selected = select(Some(b"aic,2"), &KNOWN).expect("a known device");
    assert_eq!(selected.revision, "aic-v2");

    let selected = select(Some(b"dart,t8020"), &KNOWN).expect("a known device");
    assert_eq!(selected.revision, "dart-t8020");
}

#[test]
fn a_trailing_nul_is_the_adt_storing_a_c_string_and_not_part_of_the_name() {
    let selected = select(Some(b"aic,2\0"), &KNOWN).expect("a known device");
    assert_eq!(selected.revision, "aic-v2");
    // Anything after the NUL is not the name either.
    let selected = select(Some(b"aic,2\0trailing junk"), &KNOWN).expect("a known device");
    assert_eq!(selected.revision, "aic-v2");
}

#[test]
fn an_unknown_string_refuses_rather_than_choosing_the_closest() {
    // The tempting fallback is "probably a newer revision of something we know".
    // An unrecognised DART driven by the wrong PTE format programs *something*,
    // and the device gets a window nobody intended.
    for unknown in [
        &b"aic,3"[..],
        &b"aic,1"[..],
        &b"dart,t6020"[..],
        &b"something-entirely-else"[..],
    ] {
        assert_eq!(
            select(Some(unknown), &KNOWN).unwrap_err(),
            SelectionError::UnknownCompatible,
            "{unknown:?} must not select anything"
        );
    }
}

#[test]
fn a_prefix_or_a_superstring_is_not_a_match() {
    // `aic,2` must not select for `aic,2-experimental`, and `aic,` must not
    // select for anything: a prefix match is how a device we cannot drive gets
    // driven.
    assert_eq!(
        select(Some(b"aic,2-experimental"), &KNOWN).unwrap_err(),
        SelectionError::UnknownCompatible
    );
    assert_eq!(
        select(Some(b"aic,"), &KNOWN).unwrap_err(),
        SelectionError::UnknownCompatible
    );
    assert_eq!(
        select(Some(b"xaic,2"), &KNOWN).unwrap_err(),
        SelectionError::UnknownCompatible
    );
}

#[test]
fn case_is_not_folded() {
    // A string differing only in case is a different string. Folding is how it
    // would look like one we know.
    assert_eq!(
        select(Some(b"AIC,2"), &KNOWN).unwrap_err(),
        SelectionError::UnknownCompatible
    );
}

#[test]
fn an_absent_or_empty_compatible_refuses() {
    assert_eq!(
        select(None, &KNOWN).unwrap_err(),
        SelectionError::MissingCompatible
    );
    assert_eq!(
        select(Some(b""), &KNOWN).unwrap_err(),
        SelectionError::MissingCompatible
    );
    // All NUL is absent, not the empty device.
    assert_eq!(
        select(Some(b"\0\0\0"), &KNOWN).unwrap_err(),
        SelectionError::MissingCompatible
    );
}

#[test]
fn a_string_that_is_not_text_names_nothing() {
    // Firmware-supplied bytes are hostile input, and invalid UTF-8 is one of
    // the shapes hostile input takes.
    assert_eq!(
        select(Some(&[0xFF, 0xFE, 0xFD]), &KNOWN).unwrap_err(),
        SelectionError::NotText
    );
}

#[test]
fn an_empty_table_selects_nothing_which_is_what_a_build_with_no_driver_should_do() {
    // KNOWN_AIC_REVISIONS is empty today, and every AIC node therefore fails
    // closed. That is the honest state of a build with no AIC driver, and the
    // table grows by adding a spec rather than by adding a guess.
    assert!(KNOWN_AIC_REVISIONS.is_empty());
    assert_eq!(
        select(Some(b"aic,2"), &KNOWN_AIC_REVISIONS).unwrap_err(),
        SelectionError::UnknownCompatible
    );
}
