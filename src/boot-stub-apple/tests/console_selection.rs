//! Console selection, tested against the **real** device tree of the machine
//! this payload is being brought up on.
//!
//! `src/adt/tests/fixtures/mac14-12-j474s-adt.bin` was read out of the target
//! over m1n1's proxy on 2026-08-16 (`Mac14,12` / `J474s` / `T6020`). Using it
//! here rather than a synthetic tree is the entire point of these tests: the
//! bug they exist to prevent is one that every synthetic fixture passes.
//!
//! # The bug
//!
//! That machine's tree contains `/arm-io/uart0`, correctly described, carrying
//! `compatible = uart-1,samsung`, translatable through `/arm-io`'s `ranges`,
//! and marked with `boot-console`. The §8.6 algorithm selects it, and every
//! individual step is right. It is also not the console: the debug-serial mux
//! presents DockChannel on the SBU pins, so writing that UART emits **no bytes
//! at the host** — which looks exactly like a payload that never ran. See
//! OQ-5 in `docs/platform-specs/apple-s5l-uart.md`.
//!
//! No fixture written from our own understanding of the format would have
//! caught that, because the mistake was in the understanding.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use brainix_boot_stub_apple::discover::{
    console_from_adt, dockchannel_base_from_adt, uart_base_from_adt, ConsoleChoice, DiscoverError,
};
use brainix_boot_stub_apple::registers::DOCKCHANNEL_BASE_OBSERVED;
use common::{tree, TreeOptions};

/// The device tree of the deployment target itself.
static REAL_ADT: &[u8] = include_bytes!("../../adt/tests/fixtures/mac14-12-j474s-adt.bin");

#[test]
fn on_the_real_machine_the_console_is_dockchannel() {
    let choice = console_from_adt(REAL_ADT).expect("the target's ADT must yield a console");

    match choice {
        ConsoleChoice::DockChannel { base } => assert_eq!(
            base, DOCKCHANNEL_BASE_OBSERVED,
            "must match the address m1n1 printed on this machine"
        ),
        ConsoleChoice::S5lUart {
            location,
            dockchannel_error,
        } => panic!(
            "selected the s5l UART at {:#x} on a machine whose console is \
             DockChannel; DockChannel was rejected because {dockchannel_error:?}. \
             This is the silent-failure mode OQ-5 describes.",
            location.base
        ),
    }
}

/// Pins the observed address independently of the selection logic.
#[test]
fn dockchannel_resolves_to_the_address_m1n1_reported() {
    let base = dockchannel_base_from_adt(REAL_ADT).expect("dockchannel must resolve");
    assert_eq!(base, 0x2_9E52_8000);
    assert_eq!(base, DOCKCHANNEL_BASE_OBSERVED);
}

/// The trap, made explicit.
///
/// The old algorithm still succeeds on this machine. It is not broken; it is
/// answering a different question than the one that matters.
#[test]
fn the_s5l_algorithm_still_succeeds_on_this_machine_and_that_is_the_trap() {
    let location =
        uart_base_from_adt(REAL_ADT).expect("uart0 really is present and well-formed here");

    assert_ne!(
        location.base, DOCKCHANNEL_BASE_OBSERVED,
        "the two consoles are different peripherals"
    );
    assert_eq!(
        location.base, 0x3_9B20_0000,
        "uart0's reg 0x1_9B200000 translated through the same /arm-io window"
    );
}

#[test]
fn a_machine_without_dockchannel_falls_back_and_reports_why() {
    // The synthetic tree has an s5l UART and no DockChannel node at all, which
    // is the shape of every machine the s5l path was written for.
    let synthetic = tree(&TreeOptions::default());

    let choice = console_from_adt(&synthetic).expect("the s5l fallback must succeed");

    match choice {
        ConsoleChoice::S5lUart {
            dockchannel_error, ..
        } => assert_eq!(
            dockchannel_error,
            DiscoverError::NoUartNode,
            "the fallback must carry the reason, so a downgrade is never silent"
        ),
        ConsoleChoice::DockChannel { base } => {
            panic!("invented a DockChannel at {base:#x} in a tree that has none")
        }
    }
}

#[test]
fn a_tree_with_neither_console_denies_rather_than_guessing() {
    let empty = common::tree_without_arm_io();

    let error = console_from_adt(&empty).expect_err("no console must deny");

    assert_eq!(error, DiscoverError::NoUartNode);
}

#[test]
fn the_chosen_base_is_the_one_that_would_be_driven() {
    let choice = console_from_adt(REAL_ADT).unwrap();
    assert_eq!(
        choice.base(),
        DOCKCHANNEL_BASE_OBSERVED,
        "base() must not disagree with the variant it came from"
    );
}
