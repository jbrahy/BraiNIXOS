//! The ARM generic timer.
//!
//! # Why this is a separate module from `registers`
//!
//! `registers` reports what the hardware *is*. This turns two of those numbers
//! into a clock, which is a different kind of claim and the first place a wrong
//! reading becomes a wrong behaviour: every timeout, every scheduler tick and
//! every watchdog interval downstream is derived from `CNTFRQ_EL0`.
//!
//! # The frequency is read, never assumed
//!
//! `CNTFRQ_EL0` is *firmware-programmed*, not architectural. Published values
//! for Apple Silicon differ across SoCs, and a constant that is right on one
//! machine silently doubles or halves every interval on another. Anything
//! derived from a hardcoded frequency is a bug that only shows up as
//! "everything is slightly wrong".

use super::registers::{counter_frequency_hz, physical_counter};

/// A monotonic clock over the generic timer.
#[derive(Debug, Clone, Copy)]
pub struct Timer {
    frequency_hz: u64,
}

impl Timer {
    /// Read the timer's configuration from the CPU.
    ///
    /// Returns `None` when `CNTFRQ_EL0` reads zero, which means firmware did
    /// not program it. That is a refusal rather than a fallback: a clock with a
    /// made-up rate is worse than no clock, because it silently mis-scales
    /// every interval derived from it instead of failing where it is wrong.
    pub fn current() -> Option<Self> {
        let frequency_hz = counter_frequency_hz();
        if frequency_hz == 0 {
            return None;
        }
        Some(Self { frequency_hz })
    }

    /// The timer frequency in Hz.
    pub fn frequency_hz(&self) -> u64 {
        self.frequency_hz
    }

    /// The raw counter.
    pub fn ticks(&self) -> u64 {
        physical_counter()
    }

    /// Convert a tick count to microseconds.
    ///
    /// Multiplies before dividing, and uses `u128` for the intermediate: at
    /// 24 MHz a `u64` tick count overflows `ticks * 1_000_000` after about
    /// thirteen hours of uptime. Dividing first instead would quantise every
    /// interval to whole seconds, which is worse and much harder to notice.
    pub fn ticks_to_micros(&self, ticks: u64) -> u64 {
        let micros = (u128::from(ticks) * 1_000_000) / u128::from(self.frequency_hz);
        // Saturating rather than wrapping: a clock that jumps backwards is a
        // class of bug that takes days to find.
        u64::try_from(micros).unwrap_or(u64::MAX)
    }

    /// Microseconds since the counter started.
    pub fn micros(&self) -> u64 {
        self.ticks_to_micros(self.ticks())
    }
}
