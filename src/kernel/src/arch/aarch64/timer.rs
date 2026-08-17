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

#![allow(unsafe_code)]

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

// ---------------------------------------------------------------------------
// The comparator.
// ---------------------------------------------------------------------------

/// `CNTP_CTL_EL0` bit 0: the timer is enabled.
const CTL_ENABLE: u64 = 1 << 0;
/// `CNTP_CTL_EL0` bit 1: the interrupt is **masked**.
const CTL_IMASK: u64 = 1 << 1;
/// `CNTP_CTL_EL0` bit 2: the condition has been met. Read-only.
const CTL_ISTATUS: u64 = 1 << 2;

/// What an armed countdown did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Countdown {
    /// Whether `ISTATUS` was observed set before the poll budget ran out.
    pub fired: bool,
    /// Counter ticks that actually elapsed between arming and firing.
    pub elapsed_ticks: u64,
    /// Ticks the countdown was armed for.
    pub requested_ticks: u64,
    /// Polls consumed. A budget rather than a spin: an unbounded wait on a
    /// timer that never fires is a hang, and a hang is the one failure mode
    /// this platform cannot report.
    pub polls: u64,
}

impl Timer {
    /// Arm the physical timer for `ticks` and wait for the condition, with the
    /// interrupt **masked**.
    ///
    /// # Why masked
    ///
    /// `IMASK` set means the comparator still fires and `ISTATUS` still
    /// reports it, but no interrupt is signalled to the interrupt controller.
    /// That separates two things which are usually brought up together and fail
    /// together: *does the timer count and compare*, and *does an interrupt get
    /// delivered and routed*. The first needs no interrupt controller, no
    /// vector wiring and no unmasking, and it cannot deliver a spurious
    /// interrupt into a machine hosting the measurement.
    ///
    /// Delivery is the next step and needs the AIC. This is the half that can
    /// be proved on its own, so it is proved on its own.
    ///
    /// # Safety
    ///
    /// Writes the physical timer's control and comparator. The previous control
    /// value is restored before returning, but any timer the caller had armed
    /// is lost.
    pub unsafe fn armed_countdown(&self, ticks: u64, poll_budget: u64) -> Countdown {
        let saved_control: u64;
        // SAFETY: reading the timer control register has no side effects.
        unsafe {
            core::arch::asm!("mrs {}, CNTP_CTL_EL0", out(reg) saved_control, options(nomem, nostack))
        }

        let start = self.ticks();

        // SAFETY: arming the physical timer. `isb` so the write is in effect
        // before the counter is read for the elapsed measurement.
        unsafe {
            core::arch::asm!(
                "msr CNTP_TVAL_EL0, {ticks}",
                "msr CNTP_CTL_EL0, {control}",
                "isb",
                ticks = in(reg) ticks,
                control = in(reg) CTL_ENABLE | CTL_IMASK,
                options(nomem, nostack)
            )
        }

        let mut polls = 0u64;
        let mut fired = false;
        while polls < poll_budget {
            let control: u64;
            // SAFETY: as above.
            unsafe {
                core::arch::asm!("mrs {}, CNTP_CTL_EL0", out(reg) control, options(nomem, nostack))
            }
            if control & CTL_ISTATUS != 0 {
                fired = true;
                break;
            }
            polls = polls.saturating_add(1);
        }

        let elapsed_ticks = self.ticks().wrapping_sub(start);

        // SAFETY: restoring what was read.
        unsafe {
            core::arch::asm!(
                "msr CNTP_CTL_EL0, {control}",
                "isb",
                control = in(reg) saved_control,
                options(nomem, nostack)
            )
        }

        Countdown {
            fired,
            elapsed_ticks,
            requested_ticks: ticks,
            polls,
        }
    }
}
