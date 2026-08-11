//! UART discovery against synthetic Apple Device Trees.
//!
//! Covers the selection algorithm of the AS-0 fact table §8.6 and every deny
//! path in the AS-1a design's §5. Discovery must never return a guessed or
//! partially validated address, so each failure has its own assertion.

mod common;

use brainix_boot_stub_apple::discover::{uart_base_from_adt, DiscoverError, SelectedNode};
use common::{
    tree, tree_with_both_uarts, tree_without_arm_io, TreeOptions, UART_CHILD_BASE,
    UART_TRANSLATED_BASE,
};

#[test]
fn the_default_node_resolves_to_its_translated_base() {
    let blob = tree(&TreeOptions::default());

    let location = uart_base_from_adt(&blob).expect("a well-formed tree must resolve");

    assert_eq!(location.base, UART_TRANSLATED_BASE);
    assert_eq!(location.selected, SelectedNode::Default);
}

/// The whole point of §8.5's translation rule: an untranslated `/arm-io`
/// address is a valid-looking physical address pointing at the wrong place.
#[test]
fn the_returned_base_is_translated_and_never_the_raw_reg_value() {
    let blob = tree(&TreeOptions::default());

    let location = uart_base_from_adt(&blob).expect("must resolve");

    assert_ne!(
        location.base, UART_CHILD_BASE,
        "returning the untranslated reg address would MMIO-map the wrong device"
    );
    assert_eq!(location.base, UART_TRANSLATED_BASE);
}

#[test]
fn the_debug_console_marker_selects_uart6_over_uart0() {
    let blob = tree_with_both_uarts();

    let location = uart_base_from_adt(&blob).expect("must resolve");

    assert_eq!(
        location.selected,
        SelectedNode::PreferredWithMarker,
        "the marker's existence selects uart6 even though uart0 also resolves"
    );
    assert_eq!(
        location.base, UART_TRANSLATED_BASE,
        "uart6's reg, not uart0's, must be the one translated"
    );
}

#[test]
fn the_marker_is_a_child_node_whose_contents_are_never_read() {
    // The marker node in the fixture carries only a name. If the implementation
    // read anything else out of it, this would deny instead of resolving.
    let blob = tree_with_both_uarts();
    assert!(uart_base_from_adt(&blob).is_ok());
}

#[test]
fn a_tree_with_neither_candidate_denies_rather_than_defaulting() {
    let blob = tree_without_arm_io();

    let error = uart_base_from_adt(&blob).expect_err("no candidate must deny");

    assert_eq!(
        error,
        DiscoverError::NoUartNode,
        "§8.6: there is no third candidate and no default address"
    );
}

#[test]
fn a_node_without_a_compatible_property_denies() {
    let blob = tree(&TreeOptions {
        compatible: None,
        ..TreeOptions::default()
    });

    assert_eq!(
        uart_base_from_adt(&blob).expect_err("must deny"),
        DiscoverError::CompatibleMissing
    );
}

/// The error this whole cross-check exists to catch. `apple,s5l-uart` is the
/// Linux FDT binding name, not the ADT value; an implementation matching on it
/// would find nothing on every real machine.
#[test]
fn the_linux_binding_name_is_not_accepted_as_the_adt_compatible_value() {
    let blob = tree(&TreeOptions {
        compatible: Some("apple,s5l-uart"),
        ..TreeOptions::default()
    });

    assert_eq!(
        uart_base_from_adt(&blob).expect_err("must deny"),
        DiscoverError::CompatibleMismatch,
        "the ADT value is uart-1,samsung; apple,s5l-uart is the Linux binding"
    );
}

#[test]
fn a_node_that_resolves_but_is_a_different_device_denies() {
    let blob = tree(&TreeOptions {
        compatible: Some("something,else"),
        ..TreeOptions::default()
    });

    assert_eq!(
        uart_base_from_adt(&blob).expect_err("must deny"),
        DiscoverError::CompatibleMismatch,
        "a wrong path that happens to resolve must not have its reg mapped"
    );
}

#[test]
fn a_node_without_reg_denies() {
    let blob = tree(&TreeOptions {
        with_reg: false,
        ..TreeOptions::default()
    });

    assert!(
        matches!(
            uart_base_from_adt(&blob).expect_err("must deny"),
            DiscoverError::RegUntranslatable(_)
        ),
        "a missing reg must deny, never yield address zero"
    );
}

/// Regression test for a real gap this suite found.
///
/// `NodePath::translated_reg` documents that an ancestor with no `ranges`
/// **terminates** translation rather than failing it, so it returns the *raw*
/// address successfully. That is correct in general — a missing `ranges` marks
/// an address-space boundary — but wrong for `/arm-io`, whose children's `reg`
/// values point nowhere untranslated (§8.5, §8.6).
///
/// Before the `TranslationUnavailable` check, discovery accepted `0x79200000`
/// here and would have handed it to MMIO.
#[test]
fn an_untranslatable_address_denies_rather_than_passing_the_raw_value_through() {
    let blob = tree(&TreeOptions {
        with_ranges: false,
        ..TreeOptions::default()
    });

    let error = uart_base_from_adt(&blob).expect_err("must deny");

    assert_eq!(
        error,
        DiscoverError::TranslationUnavailable,
        "a successful translated_reg is not evidence translation happened"
    );
}

#[test]
fn the_raw_reg_address_is_never_returned_when_translation_is_impossible() {
    let blob = tree(&TreeOptions {
        with_ranges: false,
        ..TreeOptions::default()
    });

    match uart_base_from_adt(&blob) {
        Ok(location) => panic!(
            "returned {:#x} with no ranges present; an untranslated /arm-io \
             address is a valid-looking pointer at the wrong device",
            location.base
        ),
        Err(error) => assert_eq!(error, DiscoverError::TranslationUnavailable),
    }
}

#[test]
fn a_truncated_blob_denies_at_the_parser() {
    let blob = tree(&TreeOptions::default());
    let truncated = &blob[..blob.len() / 2];

    assert!(
        matches!(
            uart_base_from_adt(truncated).expect_err("must deny"),
            DiscoverError::AdtParse(_) | DiscoverError::MarkerProbe(_)
        ),
        "a truncated tree must deny through the decoder's own error"
    );
}

#[test]
fn an_empty_blob_denies() {
    assert!(uart_base_from_adt(&[]).is_err());
}

#[test]
fn every_deny_path_is_distinguishable_from_every_other() {
    // Bring-up depends on being able to tell these apart from a serial line, so
    // collapsing two causes into one variant would be a real regression.
    let missing = uart_base_from_adt(&tree(&TreeOptions {
        compatible: None,
        ..TreeOptions::default()
    }))
    .unwrap_err();
    let mismatch = uart_base_from_adt(&tree(&TreeOptions {
        compatible: Some("wrong"),
        ..TreeOptions::default()
    }))
    .unwrap_err();
    let absent = uart_base_from_adt(&tree_without_arm_io()).unwrap_err();

    assert_ne!(missing, mismatch);
    assert_ne!(mismatch, absent);
    assert_ne!(missing, absent);
}
