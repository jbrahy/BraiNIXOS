//! The transmit path, against a recording MMIO fake.
//!
//! These tests exist because the real hardware cannot be reached, and the
//! sequencing they pin down (poll status, then write the byte, and never the
//! other order) is the part a wrong implementation would get wrong silently.

mod common;

use brainix_boot_stub_apple::registers::{TX_POLL_LIMIT, TX_READY_MASK, UTRSTAT_OFFSET, UTXH_OFFSET};
use brainix_boot_stub_apple::uart::{TransmitOutcome, Uart};
use common::{Access, FakeMmio};

#[test]
fn a_ready_transmitter_takes_one_write_to_the_transmit_register() {
    let mut uart = Uart::new(FakeMmio::ready(UTRSTAT_OFFSET, TX_READY_MASK));

    let outcome = uart.write_byte(b'A');

    assert_eq!(outcome, TransmitOutcome::ReadyThenWritten);
    let mmio = uart.into_inner();
    assert_eq!(
        mmio.accesses,
        vec![Access::Write {
            offset: UTXH_OFFSET,
            value: u32::from(b'A'),
        }],
        "a ready transmitter must produce exactly one write, to UTXH"
    );
}

#[test]
fn the_byte_goes_to_the_transmit_register_and_never_to_the_status_register() {
    let mut uart = Uart::new(FakeMmio::ready(UTRSTAT_OFFSET, TX_READY_MASK));
    uart.write_str("hi");

    let offsets = uart.into_inner().write_offsets();

    assert!(
        offsets.iter().all(|offset| *offset == UTXH_OFFSET),
        "every write must target UTXH ({UTXH_OFFSET:#x}), got {offsets:?}"
    );
}

#[test]
fn a_transmitter_that_becomes_ready_is_waited_for_rather_than_written_early() {
    let mut uart = Uart::new(FakeMmio::ready_after(UTRSTAT_OFFSET, TX_READY_MASK, 5));

    let outcome = uart.write_byte(b'Z');

    assert_eq!(
        outcome,
        TransmitOutcome::ReadyThenWritten,
        "becoming ready within the poll limit is the ready path, not the timeout path"
    );
    assert_eq!(uart.into_inner().written_bytes(), vec![b'Z']);
}

#[test]
fn write_str_transmits_every_byte_in_order() {
    let mut uart = Uart::new(FakeMmio::ready(UTRSTAT_OFFSET, TX_READY_MASK));

    uart.write_str("BraiNIX\r\n");

    assert_eq!(uart.into_inner().written_text(), "BraiNIX\r\n");
}

/// The property that keeps a wrong `TX_READY_MASK` (fact table OQ-1) from
/// becoming a silent hang on a machine with no debugger.
#[test]
fn a_transmitter_that_never_reports_ready_still_transmits_rather_than_hanging() {
    let mut uart = Uart::new(FakeMmio::never_ready(UTRSTAT_OFFSET));

    let outcome = uart.write_byte(b'X');

    assert_eq!(
        outcome,
        TransmitOutcome::TimedOutThenWritten,
        "the timeout must be reported, so garbled output is diagnosable"
    );
    assert_eq!(
        uart.into_inner().written_bytes(),
        vec![b'X'],
        "the byte must still be transmitted: garbled output identifies the \
         fault, silence identifies nothing"
    );
}

#[test]
fn the_poll_loop_is_bounded_by_the_documented_limit() {
    let mut uart = Uart::new(FakeMmio::never_ready(UTRSTAT_OFFSET));
    uart.write_byte(b'X');

    // Reaching this line at all is the assertion: an unbounded loop would not
    // return. The limit is asserted to be finite so the constant cannot be
    // changed to u32::MAX without this failing.
    assert!(
        TX_POLL_LIMIT < u32::MAX,
        "TX_POLL_LIMIT must stay finite; an unbounded wait is the hang this \
         design exists to prevent"
    );
}

#[test]
fn a_string_containing_a_slow_byte_reports_the_timeout_for_the_whole_string() {
    let mut uart = Uart::new(FakeMmio::never_ready(UTRSTAT_OFFSET));

    let outcome = uart.write_str("ab");

    assert_eq!(outcome, TransmitOutcome::TimedOutThenWritten);
    assert_eq!(uart.into_inner().written_text(), "ab");
}

#[test]
fn hex_rendering_is_fixed_width_and_lowercase() {
    let mut uart = Uart::new(FakeMmio::ready(UTRSTAT_OFFSET, TX_READY_MASK));

    uart.write_hex_u64(0x2_8920_0000);

    assert_eq!(
        uart.into_inner().written_text(),
        "0x0000000289200000",
        "addresses are compared by eye during bring-up, so width must be fixed"
    );
}

#[test]
fn hex_rendering_covers_the_full_64_bit_range() {
    let mut uart = Uart::new(FakeMmio::ready(UTRSTAT_OFFSET, TX_READY_MASK));
    uart.write_hex_u64(u64::MAX);
    assert_eq!(uart.into_inner().written_text(), "0xffffffffffffffff");
}
