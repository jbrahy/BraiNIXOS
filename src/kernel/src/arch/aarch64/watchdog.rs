//! The system watchdog: reset, and a signalling channel.
//!
//! Raw MMIO over an ADT-discovered register block.
//!
//! # Two purposes, and the second is the interesting one
//!
//! The obvious use is reset. The other is **reporting on a machine with no
//! output device**, which is the situation the moment m1n1 is chainloaded away:
//! this rig's SBU serial path delivers nothing, the framebuffer handed to a
//! custom boot object is a dummy that is never scanned out, and m1n1's USB
//! gadget leaves with m1n1.
//!
//! `docs/operations/BRINGUP_PLAN.md` anticipated exactly this and named the
//! fallback: *"a machine that power-cycles on a rhythm proves execution with no
//! output device at all."* A payload that reaches a given point and then arms
//! the watchdog for a chosen interval signals that point by **when the machine
//! reboots**, observed from the workstation as the USB port disappearing and
//! coming back. One arm is one bit; distinct intervals carry more.
//!
//! That is a poor channel and it is better than silence, which is the only
//! alternative currently on offer.
//!
//! # Register layout
//!
//! From m1n1 `src/wdt.c`, MIT-licensed, read 2026-08-16. Offsets from the
//! translated `reg[0]` of `/arm-io/wdt`.

#![allow(unsafe_code)]

use brainix_adt::DeviceTree;

/// Counter. Cleared before arming so the alarm measures from now.
const WDT_COUNT: u64 = 0x10;
/// Alarm threshold. The counter reaching this triggers the configured action.
const WDT_ALARM: u64 = 0x14;
/// Control. `4` enables reset-on-alarm; `0` disables the watchdog.
const WDT_CTL: u64 = 0x1C;

/// Control value that makes the alarm reset the machine.
const CTL_RESET_ON_ALARM: u32 = 4;
/// Control value that disables it.
const CTL_DISABLED: u32 = 0;

/// ADT path of the primary watchdog.
pub const WDT_ADT_PATH: &[u8] = b"/arm-io/wdt";

/// Find the watchdog's translated register base in `adt_blob`.
///
/// Translated, never raw: an untranslated `/arm-io` address is a valid-looking
/// physical address pointing at the wrong device, and the wrong device here is
/// one we would be writing a reset command to.
pub fn locate(adt_blob: &[u8]) -> Option<u64> {
    let tree = DeviceTree::parse(adt_blob).ok()?;
    let node = tree.resolve(WDT_ADT_PATH).ok()?;
    // The parent must carry `ranges`, or `translated_reg` returns the raw
    // address successfully -- the same trap `discover` documents.
    node.parent()?.find_property(b"ranges").ok()??;
    Some(node.translated_reg(0).ok()?.address)
}

/// Arm the watchdog to reset the machine after `alarm` counter ticks.
///
/// # Safety
///
/// `base` must be the watchdog's translated register base, and the machine
/// must be ours: this resets it. Under m1n1 that costs the debugging loop for
/// about fifteen seconds; under anything else it costs whatever was running.
pub unsafe fn arm_reset(base: u64, alarm: u32) {
    // SAFETY: MMIO writes to the watchdog block at ADT-derived, translated
    // offsets. Ordered COUNT-after-ALARM and CTL last, matching m1n1's own
    // sequence: enabling before the threshold is set would arm against
    // whatever value the alarm register happened to hold.
    unsafe {
        core::ptr::write_volatile((base + WDT_ALARM) as *mut u32, alarm);
        core::ptr::write_volatile((base + WDT_COUNT) as *mut u32, 0);
        core::ptr::write_volatile((base + WDT_CTL) as *mut u32, CTL_RESET_ON_ALARM);
    }
}

/// Disable the watchdog.
///
/// # Safety
///
/// `base` must be the watchdog's translated register base.
pub unsafe fn disable(base: u64) {
    // SAFETY: as above.
    unsafe { core::ptr::write_volatile((base + WDT_CTL) as *mut u32, CTL_DISABLED) }
}

/// Read the control register, for reporting without changing anything.
///
/// # Safety
///
/// `base` must be the watchdog's translated register base.
pub unsafe fn control(base: u64) -> u32 {
    // SAFETY: a read of an MMIO register with no side effects.
    unsafe { core::ptr::read_volatile((base + WDT_CTL) as *const u32) }
}
