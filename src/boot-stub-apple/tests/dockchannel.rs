//! The DockChannel transmit path, against a recording MMIO fake.
//!
//! DockChannel is the console this hardware actually presents on the Type-C SBU
//! pins — see `docs/platform-specs/apple-s5l-uart.md` OQ-5, resolved on the
//! machine on 2026-08-16. These tests pin the sequencing that a wrong
//! implementation gets wrong *silently*: poll the free-space register, then
//! write the byte, and never the other order.
//!
//! The offsets under test came from m1n1's driver and were corroborated by the
//! target printing `Initialized dockchannel UART at 0x29e528000`, so unlike the
//! s5l path there is no unconfirmed bit mask here to design around.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use brainix_boot_stub_apple::dockchannel::{DockChannel, DockChannelOutcome};
use brainix_boot_stub_apple::registers::{DOCKCHANNEL_TX_DATA_OFFSET, DOCKCHANNEL_TX_FREE_OFFSET};
use common::{Access, FakeMmio};

/// Any nonzero free-space count means "room for a byte".
const SOME_FREE_SPACE: u32 = 1;

fn ready() -> FakeMmio {
    FakeMmio::ready(DOCKCHANNEL_TX_FREE_OFFSET, SOME_FREE_SPACE)
}

#[test]
fn a_free_fifo_takes_one_write_to_the_data_register() {
    let mut channel = DockChannel::new(ready());

    let outcome = channel.write_byte(b'A');

    assert_eq!(outcome, DockChannelOutcome::FreeThenWritten);
    assert_eq!(
        channel.into_inner().accesses,
        vec![Access::Write {
            offset: DOCKCHANNEL_TX_DATA_OFFSET,
            value: u32::from(b'A'),
        }],
        "a free FIFO must produce exactly one write, to the data register"
    );
}

#[test]
fn the_byte_never_goes_to_the_free_space_register() {
    let mut channel = DockChannel::new(ready());
    channel.write_bytes(b"hi");

    let offsets = channel.into_inner().write_offsets();

    assert!(
        !offsets.contains(&DOCKCHANNEL_TX_FREE_OFFSET),
        "writing to the free-space register would corrupt the FIFO state; \
         offsets written were {offsets:?}"
    );
    assert!(offsets.iter().all(|o| *o == DOCKCHANNEL_TX_DATA_OFFSET));
}

#[test]
fn a_busy_fifo_is_waited_for_and_then_written() {
    let mut channel = DockChannel::new(FakeMmio::ready_after(
        DOCKCHANNEL_TX_FREE_OFFSET,
        SOME_FREE_SPACE,
        5,
    ));

    let outcome = channel.write_byte(b'Z');

    assert_eq!(
        outcome,
        DockChannelOutcome::FreeThenWritten,
        "waiting five reads is normal back-pressure, not a timeout"
    );
    assert_eq!(channel.into_inner().written_bytes(), vec![b'Z']);
}

/// The property that keeps a wrong offset diagnosable instead of fatal.
#[test]
fn a_fifo_that_never_frees_transmits_anyway_and_says_so() {
    let mut channel = DockChannel::new(FakeMmio::never_ready(DOCKCHANNEL_TX_FREE_OFFSET));

    let outcome = channel.write_byte(b'!');

    assert_eq!(
        outcome,
        DockChannelOutcome::TimedOutThenWritten,
        "a stuck FIFO must be reported, not silently tolerated"
    );
    assert_eq!(
        channel.into_inner().written_bytes(),
        vec![b'!'],
        "the byte must still be written: garbled output names its cause, \
         silence names nothing"
    );
}

/// Termination *is* the assertion here.
///
/// m1n1 spins unbounded on this register. If our loop did the same, this test
/// would never return rather than fail, so the bound is what makes a wrong
/// offset a diagnosable garble instead of a dead machine with no debugger.
#[test]
fn polling_is_bounded_so_a_wrong_offset_cannot_hang_the_machine() {
    let mut channel = DockChannel::new(FakeMmio::never_ready(DOCKCHANNEL_TX_FREE_OFFSET));

    let outcome = channel.write_byte(b'x');

    assert_eq!(outcome, DockChannelOutcome::TimedOutThenWritten);
}

#[test]
fn one_timeout_anywhere_in_a_run_is_reported() {
    let mut channel = DockChannel::new(FakeMmio::never_ready(DOCKCHANNEL_TX_FREE_OFFSET));

    let outcome = channel.write_bytes(b"abc");

    assert_eq!(
        outcome,
        DockChannelOutcome::TimedOutThenWritten,
        "reporting only the last byte's outcome would hide an earlier stall"
    );
    assert_eq!(channel.into_inner().written_bytes(), b"abc".to_vec());
}

#[test]
fn write_line_terminates_with_crlf() {
    let mut channel = DockChannel::new(ready());

    channel.write_line("ok");

    assert_eq!(
        channel.into_inner().written_bytes(),
        b"ok\r\n".to_vec(),
        "a raw CDC-ACM reader inserts no carriage return of its own"
    );
}

#[test]
fn write_line_expands_embedded_newlines_too() {
    let mut channel = DockChannel::new(ready());

    channel.write_line("a\nb");

    assert_eq!(
        channel.into_inner().written_bytes(),
        b"a\r\nb\r\n".to_vec(),
        "an embedded newline left bare makes every later line start mid-column, \
         which reads as corruption rather than as a missing carriage return"
    );
}

#[test]
fn hex64_prints_sixteen_uppercase_digits_most_significant_first() {
    let mut channel = DockChannel::new(ready());

    // The address m1n1 printed for this very peripheral.
    channel.write_hex64(0x2_9E52_8000);

    assert_eq!(
        channel.into_inner().written_text(),
        "000000029E528000",
        "addresses are the entire point of first light; a reversed or \
         truncated one is worse than none"
    );
}

#[test]
fn hex64_prints_zero_and_all_ones_without_shortening() {
    let mut zero = DockChannel::new(ready());
    zero.write_hex64(0);
    assert_eq!(zero.into_inner().written_text(), "0000000000000000");

    let mut ones = DockChannel::new(ready());
    ones.write_hex64(u64::MAX);
    assert_eq!(ones.into_inner().written_text(), "FFFFFFFFFFFFFFFF");
}
