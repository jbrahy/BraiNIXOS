//! Transmit-only s5l UART writer.
//!
//! Every access goes through the [`Mmio`] trait rather than a raw pointer, so
//! the whole of this module is exercised on the host against a recording fake.
//! The only untested code in the transmit path is the real [`Mmio`] impl in
//! `main.rs`, which is a pair of volatile accesses and nothing else.
//!
//! This driver **writes** an already-initialized UART. It never configures one:
//! see [`crate::registers`] for why, and the fact table's §1.

use crate::registers::{TX_POLL_LIMIT, TX_READY_MASK, UTRSTAT_OFFSET, UTXH_OFFSET};

/// A 32-bit memory-mapped register window.
///
/// Offsets are relative to the window's base. Implementations are responsible
/// for the base; nothing in this module knows an absolute address.
pub trait Mmio {
    /// Read the 32-bit register at `offset` from the window base.
    fn read_u32(&self, offset: usize) -> u32;

    /// Write the 32-bit register at `offset` from the window base.
    fn write_u32(&mut self, offset: usize, value: u32);
}

/// How a byte was transmitted.
///
/// Distinguishing these is what makes a wrong [`TX_READY_MASK`] diagnosable
/// rather than merely survivable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransmitOutcome {
    /// The transmitter reported ready and the byte was written.
    ReadyThenWritten,
    /// The transmitter never reported ready within [`TX_POLL_LIMIT`] polls and
    /// the byte was written anyway.
    ///
    /// This is the signature of a wrong [`TX_READY_MASK`] (fact table OQ-1). It
    /// is deliberately not a failure: transmitting produces possibly-garbled
    /// output that identifies the fault, whereas refusing to transmit produces
    /// silence that identifies nothing.
    TimedOutThenWritten,
}

/// A transmit-only UART bound to one MMIO window.
pub struct Uart<M: Mmio> {
    mmio: M,
}

impl<M: Mmio> Uart<M> {
    /// Bind a UART to an MMIO window.
    pub fn new(mmio: M) -> Self {
        Self { mmio }
    }

    /// Release the underlying MMIO window.
    pub fn into_inner(self) -> M {
        self.mmio
    }

    /// Transmit one byte, polling the transmit-ready bit first.
    ///
    /// Polling is **bounded**. An unbounded wait would turn a wrong
    /// [`TX_READY_MASK`] into a silent hang on a machine with no debugger
    /// attached, which is the single worst outcome during first light.
    pub fn write_byte(&mut self, byte: u8) -> TransmitOutcome {
        let mut polls: u32 = 0;
        while polls < TX_POLL_LIMIT {
            if self.mmio.read_u32(UTRSTAT_OFFSET) & TX_READY_MASK != 0 {
                self.mmio.write_u32(UTXH_OFFSET, u32::from(byte));
                return TransmitOutcome::ReadyThenWritten;
            }
            polls += 1;
        }

        self.mmio.write_u32(UTXH_OFFSET, u32::from(byte));
        TransmitOutcome::TimedOutThenWritten
    }

    /// Transmit every byte of `text` in order.
    ///
    /// Returns [`TransmitOutcome::TimedOutThenWritten`] if **any** byte timed
    /// out, so a caller sees the condition even when only some bytes were slow.
    pub fn write_str(&mut self, text: &str) -> TransmitOutcome {
        self.write_bytes(text.as_bytes())
    }

    /// Transmit every byte of `bytes` in order.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> TransmitOutcome {
        let mut outcome = TransmitOutcome::ReadyThenWritten;
        for &byte in bytes {
            if self.write_byte(byte) == TransmitOutcome::TimedOutThenWritten {
                outcome = TransmitOutcome::TimedOutThenWritten;
            }
        }
        outcome
    }

    /// Transmit `value` as lowercase hexadecimal with a `0x` prefix.
    ///
    /// Present because reporting an address disagreement (the fact table's §6)
    /// requires printing two addresses, and `core::fmt` is more machinery than
    /// first light should carry.
    pub fn write_hex_u64(&mut self, value: u64) -> TransmitOutcome {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";

        let mut buffer = [0u8; 18];
        buffer[0] = b'0';
        buffer[1] = b'x';
        for index in 0..16 {
            let shift = 60 - (index * 4);
            let nibble = ((value >> shift) & 0xf) as usize;
            buffer[2 + index] = DIGITS[nibble];
        }

        self.write_bytes(&buffer)
    }
}
