//! Transmit-only DockChannel writer — the console this hardware actually has.
//!
//! Structurally a twin of [`crate::uart`], and deliberately so: same [`Mmio`]
//! trait, same bounded polling, same host tests against a recording fake. What
//! differs is which peripheral is on the other end of the Type-C SBU pins.
//!
//! # Why this exists next to a working s5l driver
//!
//! [`crate::uart`] may be entirely correct. It is also inapplicable to `T6020`.
//! The debug-serial mux presents **DockChannel**, so an s5l implementation with
//! no defects at all writes bytes into a peripheral nothing is listening to and
//! the host sees silence — which is indistinguishable from the payload never
//! running. That ambiguity cost this project two days before m1n1 printed
//! `Initialized dockchannel UART at 0x29e528000` and settled it.
//!
//! # The protocol
//!
//! Simpler than the s5l block, and with no configuration step at all:
//!
//! - poll [`DOCKCHANNEL_TX_FREE_OFFSET`] until it reports space;
//! - write the byte to [`DOCKCHANNEL_TX_DATA_OFFSET`].
//!
//! There is no baud divisor, no line-control register, and no enable bit. The
//! transmitter is already running when a boot object receives control, which is
//! why m1n1's own driver does nothing but resolve the base address.
//!
//! # Bounded polling, unlike m1n1
//!
//! m1n1 spins forever on the free-space register. This does not, for the same
//! reason [`crate::uart`] does not: on a machine with no debugger attached an
//! unbounded wait converts a wrong offset into a silent hang, and silence is
//! the single outcome that identifies nothing. Transmitting anyway produces
//! either correct output or garbage, and garbage names its own cause.

use crate::registers::{
    DOCKCHANNEL_TX_DATA_OFFSET, DOCKCHANNEL_TX_FREE_OFFSET, DOCKCHANNEL_TX_POLL_LIMIT,
};
use crate::uart::Mmio;

/// How a byte reached the transmit register.
///
/// Kept distinct from [`crate::uart::TransmitOutcome`] rather than shared: the
/// two drivers report on different peripherals, and a caller that has fallen
/// back from one to the other must not be able to confuse their results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockChannelOutcome {
    /// The FIFO reported free space and the byte was written.
    FreeThenWritten,
    /// The FIFO never reported free space within
    /// [`DOCKCHANNEL_TX_POLL_LIMIT`] polls, and the byte was written anyway.
    ///
    /// The signature of a wrong [`DOCKCHANNEL_TX_FREE_OFFSET`], or of a base
    /// address that resolved to the wrong window. Not a failure: see the module
    /// documentation on why silence is worse than garbage.
    TimedOutThenWritten,
}

/// A transmit-only DockChannel bound to one MMIO window.
pub struct DockChannel<M: Mmio> {
    mmio: M,
}

impl<M: Mmio> DockChannel<M> {
    /// Bind a DockChannel transmitter to an MMIO window.
    ///
    /// The window's base must be the **translated** `reg` of
    /// `/arm-io/dockchannel-uart`. An untranslated `/arm-io` address is a
    /// valid-looking physical address pointing at the wrong place; see
    /// `brainix_adt::NodePath::translated_reg` and the hardware test that pins
    /// it to the address m1n1 printed.
    pub fn new(mmio: M) -> Self {
        Self { mmio }
    }

    /// Release the underlying MMIO window.
    pub fn into_inner(self) -> M {
        self.mmio
    }

    /// Transmit one byte, waiting for FIFO space first.
    pub fn write_byte(&mut self, byte: u8) -> DockChannelOutcome {
        let mut polls: u32 = 0;
        while polls < DOCKCHANNEL_TX_POLL_LIMIT {
            if self.mmio.read_u32(DOCKCHANNEL_TX_FREE_OFFSET) != 0 {
                self.mmio
                    .write_u32(DOCKCHANNEL_TX_DATA_OFFSET, u32::from(byte));
                return DockChannelOutcome::FreeThenWritten;
            }
            polls = polls.saturating_add(1);
        }

        self.mmio
            .write_u32(DOCKCHANNEL_TX_DATA_OFFSET, u32::from(byte));
        DockChannelOutcome::TimedOutThenWritten
    }

    /// Transmit every byte of `bytes`, in order.
    ///
    /// Reports [`DockChannelOutcome::TimedOutThenWritten`] if **any** byte timed
    /// out. One timeout in a run is the interesting signal; reporting only the
    /// last byte's outcome would hide it.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> DockChannelOutcome {
        let mut worst = DockChannelOutcome::FreeThenWritten;
        for &byte in bytes {
            if self.write_byte(byte) == DockChannelOutcome::TimedOutThenWritten {
                worst = DockChannelOutcome::TimedOutThenWritten;
            }
        }
        worst
    }

    /// Transmit `text`, translating `\n` to `\r\n`.
    ///
    /// The host end is a terminal reading a raw CDC-ACM stream, which does not
    /// insert the carriage return itself. Without this every line after the
    /// first starts at the column the previous one ended on, which reads as
    /// corrupted output rather than as a missing `\r`.
    pub fn write_line(&mut self, text: &str) -> DockChannelOutcome {
        let mut worst = DockChannelOutcome::FreeThenWritten;
        for &byte in text.as_bytes() {
            if byte == b'\n' && self.write_byte(b'\r') == DockChannelOutcome::TimedOutThenWritten {
                worst = DockChannelOutcome::TimedOutThenWritten;
            }
            if self.write_byte(byte) == DockChannelOutcome::TimedOutThenWritten {
                worst = DockChannelOutcome::TimedOutThenWritten;
            }
        }
        if self.write_byte(b'\r') == DockChannelOutcome::TimedOutThenWritten {
            worst = DockChannelOutcome::TimedOutThenWritten;
        }
        if self.write_byte(b'\n') == DockChannelOutcome::TimedOutThenWritten {
            worst = DockChannelOutcome::TimedOutThenWritten;
        }
        worst
    }

    /// Transmit `value` as 16 uppercase hex digits, most significant first.
    ///
    /// No allocator and no formatting machinery: this crate is `no_std` on the
    /// target and the whole point of first light is to report addresses.
    pub fn write_hex64(&mut self, value: u64) -> DockChannelOutcome {
        const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
        let mut worst = DockChannelOutcome::FreeThenWritten;
        let mut shift: u32 = 60;
        loop {
            let nibble = ((value >> shift) & 0xF) as usize;
            // `nibble` is masked to 0..=15, so this index is always in range;
            // written with `get` anyway because the crate forbids indexing.
            let digit = *DIGITS.get(nibble).unwrap_or(&b'?');
            if self.write_byte(digit) == DockChannelOutcome::TimedOutThenWritten {
                worst = DockChannelOutcome::TimedOutThenWritten;
            }
            if shift == 0 {
                break;
            }
            shift = shift.saturating_sub(4);
        }
        worst
    }
}
