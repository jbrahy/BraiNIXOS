//! AS-1a "first light": the smallest Apple Silicon payload that proves the
//! delivery chain.
//!
//! Its exit criterion is the ROADMAP's own AS-1 criterion, unchanged — BraiNIX
//! prints its banner over serial on the Mac mini M2 Pro. See
//! `docs/architecture/AS-1a-first-light-boot-stub.md`.
//!
//! # What this crate is not
//!
//! No MMU, no page tables, no exception vectors, no EL2→EL1 drop, no timer, no
//! SVC entry, no PAC-BTI, no watchdog, no secondary-CPU release. Those are
//! later AS-1 slices. This crate establishes a stack, writes a banner, and
//! spins.
//!
//! # Why it is host-testable at all
//!
//! Every unit of logic is written against the [`uart::Mmio`] trait and takes
//! the ADT as a byte slice, so the only code that cannot run on a host is the
//! entry assembly and a pair of volatile accessors. That is the whole point of
//! the split: the parts with decisions in them are tested, and the untested
//! remainder has no branches.
//!
//! # Platform facts
//!
//! Every register offset, bit mask, address, and node path comes from
//! [`registers`], which mirrors `docs/platform-specs/apple-s5l-uart.md` and the
//! AS-0 table's §8.6. Nothing else in this crate may define one.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod console;
pub mod discover;
pub mod registers;
pub mod uart;

pub use console::{bring_up, MmioFactory, Outcome, BANNER, LIVENESS_MARKER};
pub use discover::{uart_base_from_adt, DiscoverError, SelectedNode, UartLocation};
pub use uart::{Mmio, TransmitOutcome, Uart};
