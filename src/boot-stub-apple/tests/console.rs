//! Console bring-up ordering and the base cross-check.
//!
//! The ordering is the design's answer to a circularity: fail-closed reporting
//! needs a console, and the console's address comes from the thing that might
//! fail. These tests pin the ordering down, because getting it backwards would
//! not fail loudly — it would produce silence on real hardware, which is
//! indistinguishable from "never started".

mod common;

use brainix_boot_stub_apple::console::{bring_up, Outcome, BANNER, LIVENESS_MARKER};
use brainix_boot_stub_apple::discover::{DiscoverError, SelectedNode};
use brainix_boot_stub_apple::registers::{TX_READY_MASK, UART_BASE_FALLBACK, UTRSTAT_OFFSET};
use common::{tree, tree_without_arm_io, FakeFactory, TreeOptions, UART_TRANSLATED_BASE};

fn factory() -> FakeFactory {
    FakeFactory::new(UTRSTAT_OFFSET, TX_READY_MASK)
}

/// The core ordering property. A liveness marker must reach the fallback
/// console *before* anything that can deny runs.
#[test]
fn the_liveness_marker_is_emitted_on_the_fallback_base_before_the_adt_is_touched() {
    let mut factory = factory();

    bring_up(&mut factory, &tree(&TreeOptions::default()));

    assert_eq!(
        factory.bases.first().copied(),
        Some(UART_BASE_FALLBACK),
        "the first window opened must be the fallback, before any parsing"
    );
}

#[test]
fn a_resolvable_tree_reports_disagreement_and_uses_the_adt_base() {
    let mut factory = factory();

    let outcome = bring_up(&mut factory, &tree(&TreeOptions::default()));

    match outcome {
        Outcome::Disagreed {
            adt_base,
            fallback_base,
            selected,
        } => {
            assert_eq!(adt_base, UART_TRANSLATED_BASE);
            assert_eq!(fallback_base, UART_BASE_FALLBACK);
            assert_eq!(selected, SelectedNode::Default);
        }
        other => panic!("expected a disagreement, got {other:?}"),
    }

    assert!(
        factory.bases.contains(&UART_TRANSLATED_BASE),
        "the banner must go to the ADT-derived base, not the fallback"
    );
}

/// Disagreement is the *expected* outcome on the target: the fallback is a
/// `T6030` observation and the target is `T6020`. It must not be an error.
#[test]
fn disagreement_is_not_treated_as_a_failure() {
    let mut factory = factory();

    let outcome = bring_up(&mut factory, &tree(&TreeOptions::default()));

    assert!(
        !matches!(outcome, Outcome::AdtFailed(_)),
        "a differing ADT base means the ADT worked, not that anything failed"
    );
}

#[test]
fn both_addresses_are_printed_when_they_disagree_so_neither_is_implicitly_preferred() {
    let mut factory = factory();
    bring_up(&mut factory, &tree(&TreeOptions::default()));

    // Both bases must have been opened as windows: the fallback for liveness,
    // the ADT base for the banner. Printing only one would leave a bring-up
    // session unable to tell which value the payload actually used.
    assert!(factory.bases.contains(&UART_BASE_FALLBACK));
    assert!(factory.bases.contains(&UART_TRANSLATED_BASE));
}

#[test]
fn a_failing_adt_falls_back_so_the_error_is_still_reportable() {
    let mut factory = factory();

    let outcome = bring_up(&mut factory, &tree_without_arm_io());

    assert_eq!(
        outcome,
        Outcome::AdtFailed(DiscoverError::NoUartNode),
        "the discovery error must be carried out, not swallowed"
    );
    assert_eq!(
        factory.bases,
        vec![UART_BASE_FALLBACK],
        "with no ADT base available, only the fallback window is ever opened"
    );
}

#[test]
fn a_failing_adt_never_opens_a_window_at_a_guessed_address() {
    let mut factory = factory();

    bring_up(&mut factory, &tree_without_arm_io());

    assert!(
        factory.bases.iter().all(|base| *base == UART_BASE_FALLBACK),
        "discovery failure must not lead to MMIO at an invented address, got {:?}",
        factory.bases
    );
}

#[test]
fn the_debug_console_marker_is_reported_in_the_outcome() {
    let mut factory = factory();

    let outcome = bring_up(&mut factory, &common::tree_with_both_uarts());

    match outcome {
        Outcome::Disagreed { selected, .. } | Outcome::Agreed { selected, .. } => assert_eq!(
            selected,
            SelectedNode::PreferredWithMarker,
            "which branch was taken must be visible without guessing"
        ),
        other => panic!("expected a resolved outcome, got {other:?}"),
    }
}

#[test]
fn the_banner_and_marker_are_distinguishable_from_each_other() {
    assert_ne!(
        BANNER, LIVENESS_MARKER,
        "reading one on a terminal must not be mistaken for the other"
    );
    assert!(
        BANNER.contains("first light"),
        "the banner is the AS-1a exit criterion and must say so"
    );
}

#[test]
fn every_message_ends_its_lines_with_crlf_for_a_raw_serial_terminal() {
    for message in [BANNER, LIVENESS_MARKER] {
        assert!(
            message.contains("\r\n"),
            "a raw serial terminal does no LF-to-CRLF translation, so {message:?} \
             would stair-step"
        );
    }
}
