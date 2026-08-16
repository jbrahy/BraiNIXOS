//! The parser against the machine, rather than against our beliefs about the
//! format.
//!
//! Every other fixture in this crate was authored here, so every other test
//! confirms that the parser agrees with whoever wrote the fixture. This one
//! uses the Apple Device Tree read out of the deployment target itself
//! (`Mac14,12` / `J474s` / `T6020`, iBoot-11881.140.96.701.1) over m1n1's proxy
//! on 2026-08-16, 491,520 bytes, and asserts values that were observed
//! independently on the running hardware.
//!
//! The load-bearing assertion is `dockchannel_uart_translates_to_the_address_
//! m1n1_reported`. m1n1 printed
//!
//! ```text
//! Initialized dockchannel UART at 0x29e528000
//! ```
//!
//! while the tree states that peripheral's `reg` as `0x9E528000`. The
//! `0x2_0000_0000` difference is the `/arm-io` ranges translation. A parser
//! that returns the raw value passes every self-authored test and hands a
//! driver a valid-looking physical address that points at the wrong place --
//! which is the exact failure this crate's `translated_reg` exists to prevent,
//! and until now nothing checked it against a real answer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use brainix_adt::DeviceTree;

/// The real tree, from the machine BraiNIX is being brought up on.
static MINI_ADT: &[u8] = include_bytes!("fixtures/mac14-12-j474s-adt.bin");

fn tree() -> DeviceTree<'static> {
    DeviceTree::parse(MINI_ADT).expect("the target machine's ADT must parse")
}

#[test]
fn the_real_tree_parses() {
    let tree = tree();
    // A tree that "parses" by consuming nothing would satisfy a weaker test.
    assert!(tree.tree_len() > 0x0007_0000, "tree_len = {}", tree.tree_len());
    assert!(tree.tree_len() <= MINI_ADT.len());
}

#[test]
fn the_nodes_the_boot_stub_looks_for_are_present() {
    let tree = tree();
    for path in [
        &b"/arm-io"[..],
        &b"/arm-io/uart0"[..],
        &b"/arm-io/dockchannel-uart"[..],
        &b"/chosen"[..],
    ] {
        assert!(
            tree.node_exists(path).expect("lookup must not error"),
            "{} is missing from the real ADT",
            core::str::from_utf8(path).unwrap()
        );
    }
}

#[test]
fn uart0_reg_matches_the_hardware() {
    let path = tree()
        .resolve(b"/arm-io/uart0")
        .expect("uart0 must resolve");
    let reg = path.reg(0).expect("uart0 must have a reg");
    assert_eq!(reg.address, 0x1_9B20_0000, "uart0 base");
    assert_eq!(reg.size, 0x4000, "uart0 window");
}

#[test]
fn dockchannel_uart_reg_matches_the_hardware() {
    let path = tree()
        .resolve(b"/arm-io/dockchannel-uart")
        .expect("dockchannel-uart must resolve");

    let first = path.reg(0).expect("dockchannel reg[0]");
    assert_eq!(first.address, 0x9E52_8000);
    assert_eq!(first.size, 0x0001_0004);

    let second = path.reg(1).expect("dockchannel reg[1]");
    assert_eq!(second.address, 0x9E50_C000);
    assert_eq!(second.size, 0x18);
}

/// The one that matters: our translation against a number the hardware printed.
#[test]
fn dockchannel_uart_translates_to_the_address_m1n1_reported() {
    let path = tree()
        .resolve(b"/arm-io/dockchannel-uart")
        .expect("dockchannel-uart must resolve");

    let translated = path
        .translated_reg(0)
        .expect("/arm-io must carry a ranges entry covering this peripheral");

    // Observed live: "Initialized dockchannel UART at 0x29e528000".
    assert_eq!(
        translated.address, 0x2_9E52_8000,
        "translated dockchannel base disagrees with what m1n1 printed on the machine"
    );
    assert_eq!(translated.size, 0x0001_0004, "translation must not alter the size");
    assert_ne!(
        translated.address,
        path.reg(0).unwrap().address,
        "translation that returns the raw address is the bug this test exists to catch"
    );
}

#[test]
fn uart0_translation_applies_the_same_arm_io_window() {
    let path = tree()
        .resolve(b"/arm-io/uart0")
        .expect("uart0 must resolve");
    let raw = path.reg(0).expect("uart0 reg");
    let translated = path.translated_reg(0).expect("uart0 must translate");

    // Not asserted against an independently observed constant, because m1n1
    // never initialised uart0 and so never printed its live address. What is
    // assertable is that the same window applies as for the peripheral that
    // *was* observed, and that translation moved the address at all.
    assert_eq!(
        translated.address.checked_sub(raw.address),
        Some(0x2_0000_0000),
        "uart0 must translate through the same /arm-io window as dockchannel-uart"
    );
    assert_eq!(translated.size, raw.size);
}
