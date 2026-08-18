//! DockChannel-first bring-up, against the real device tree.
//!
//! The property under test is the one AS-1a's exit criterion depends on: that
//! on **this machine** the banner is written to the peripheral that is actually
//! wired to the host, and that every base driven is one the ADT produced.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use brainix_boot_stub_apple::console::{bring_up_console, ConsoleOutcome};
use brainix_boot_stub_apple::registers::{DOCKCHANNEL_BASE_OBSERVED, DOCKCHANNEL_TX_FREE_OFFSET};
use common::{tree, FakeFactory, TreeOptions};

/// The device tree of the deployment target.
static REAL_ADT: &[u8] = include_bytes!("../../adt/tests/fixtures/mac14-12-j474s-adt.bin");

/// A factory whose windows always report FIFO space.
fn factory() -> FakeFactory {
    FakeFactory::new(DOCKCHANNEL_TX_FREE_OFFSET, 1)
}

#[test]
fn on_the_real_machine_the_banner_goes_to_dockchannel() {
    let mut factory = factory();

    let outcome = bring_up_console(&mut factory, REAL_ADT);

    match outcome {
        ConsoleOutcome::DockChannel {
            base,
            matched_observed,
        } => {
            assert_eq!(base, DOCKCHANNEL_BASE_OBSERVED);
            assert!(
                matched_observed,
                "the ADT and the address m1n1 printed must agree on this machine"
            );
        }
        other => panic!("expected DockChannel on the target's own tree, got {other:?}"),
    }
}

#[test]
fn liveness_is_emitted_before_anything_that_can_deny() {
    let mut factory = factory();

    // An empty blob cannot parse, so discovery denies immediately.
    let outcome = bring_up_console(&mut factory, &[]);

    assert!(matches!(outcome, ConsoleOutcome::Denied(_)));
    assert_eq!(
        factory.bases.first().copied(),
        Some(DOCKCHANNEL_BASE_OBSERVED),
        "the very first window opened must be the liveness console, or a \
         failing ADT leaves nowhere to report the failure"
    );
}

#[test]
fn the_liveness_base_is_the_observed_one_not_the_t6030_constant() {
    let mut factory = factory();
    bring_up_console(&mut factory, REAL_ADT);

    let first = factory.bases.first().copied().expect("a window was opened");
    assert_eq!(first, DOCKCHANNEL_BASE_OBSERVED);
    assert_ne!(
        first, 0x2_8920_0000,
        "the old liveness marker went to a T6030 s5l address: wrong SoC and \
         wrong peripheral, so it could never have appeared"
    );
}

#[test]
fn every_base_driven_on_the_real_machine_came_from_the_adt() {
    let mut factory = factory();
    bring_up_console(&mut factory, REAL_ADT);

    for base in &factory.bases {
        assert_eq!(
            *base, DOCKCHANNEL_BASE_OBSERVED,
            "bring-up must not open a window at an address the ADT did not yield"
        );
    }
    assert!(
        factory.bases.len() >= 2,
        "liveness window, then the console"
    );
}

#[test]
fn a_machine_without_dockchannel_uses_the_s5l_uart_and_records_why() {
    let synthetic = tree(&TreeOptions::default());
    let mut factory = factory();

    let outcome = bring_up_console(&mut factory, &synthetic);

    match outcome {
        ConsoleOutcome::S5lFallback {
            dockchannel_error, ..
        } => {
            // The reason must survive to the caller; on a machine that really
            // does need DockChannel this branch prints nothing visible, and the
            // cause has to be recoverable afterwards.
            assert_eq!(
                brainix_boot_stub_apple::console::describe(dockchannel_error),
                "neither /arm-io/uart6 nor /arm-io/uart0 resolved"
            );
        }
        other => panic!("expected the s5l fallback on a tree with no dockchannel, got {other:?}"),
    }
}

#[test]
fn a_tree_with_no_console_at_all_denies_and_says_so_on_the_liveness_console() {
    let empty = common::tree_without_arm_io();
    let mut factory = factory();

    let outcome = bring_up_console(&mut factory, &empty);

    assert!(matches!(outcome, ConsoleOutcome::Denied(_)));
    assert_eq!(
        factory.bases,
        vec![DOCKCHANNEL_BASE_OBSERVED],
        "denial must not open a second window at a guessed address"
    );
}
