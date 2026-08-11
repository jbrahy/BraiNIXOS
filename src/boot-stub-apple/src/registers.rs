//! Apple s5l UART register facts.
//!
//! This module is the in-code mirror of
//! [`docs/platform-specs/apple-s5l-uart.md`](../../../../docs/platform-specs/apple-s5l-uart.md).
//! It exists so that **every value hardware can invalidate lives in one file**
//! rather than scattered through the driver. Nothing else in this crate may
//! define a register offset, a bit mask, or an MMIO address.
//!
//! Each constant carries its confidence, using the marker convention of the
//! platform-specs directory:
//!
//! - **P** — established by published prose or vendor documentation.
//! - **UNCONFIRMED** — not established by any source consulted, and not yet
//!   observed on hardware. See the fact table's §3 and §8.

/// Confidence in a platform fact.
///
/// Carried alongside the values so that a caller can refuse to present an
/// unconfirmed value as fact. `INV-BOOT-AS-001` forbids claiming more than is
/// known, and the fallback UART base is precisely a value we do not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Established by vendor documentation or published prose.
    Documented,
    /// Not established by any consulted source. Must never be reported as fact.
    Unconfirmed,
}

// ---------------------------------------------------------------------------
// Register offsets — P, confirmed.
//
// Source: Samsung S3C2410X 32-Bit RISC Microprocessor User's Manual, rev 1.2,
// UART chapter. First-party silicon vendor documentation.
//
// The Apple block is functionally identical to the Samsung S5L8900 UART, and
// only the base address changes across Apple SoC generations. Offsets within
// the block therefore carry the vendor manual's confidence, not a guess.
// ---------------------------------------------------------------------------

/// Transmit/receive status register. **P.**
pub const UTRSTAT_OFFSET: usize = 0x10;

/// Transmit buffer register. Takes the outgoing byte in its low 8 bits. **P.**
pub const UTXH_OFFSET: usize = 0x20;

// Offsets deliberately omitted: ULCON (0x00), UCON (0x04), UFCON (0x08),
// UMCON (0x0C), UERSTAT (0x14), UFSTAT (0x18), UMSTAT (0x1C), URXH (0x24),
// UBRDIV (0x28).
//
// AS-1a is delivered by m1n1 chainload, and m1n1 drives this same UART for its
// own console before handing off. The payload writes an already-initialized
// UART; it does not configure one. Defining the configuration offsets here
// would invite an implementation that writes them, which the fact table's §1
// names as a defect.

// ---------------------------------------------------------------------------
// Values no consulted source established. See the fact table's §3.
// ---------------------------------------------------------------------------

/// Bit mask polled in [`UTRSTAT_OFFSET`] to decide the transmitter can accept a
/// byte. **UNCONFIRMED** — see the fact table's OQ-1.
///
/// The Samsung block exposes distinct "transmit buffer empty" and "transmitter
/// empty" states in `UTRSTAT`, but the manual's bit table was not successfully
/// retrieved, so this index is **not** asserted by any source.
///
/// Being wrong here does **not** hang the payload. [`crate::uart`] polls a
/// bounded number of times and then transmits regardless, so an incorrect mask
/// degrades to possibly-garbled output rather than to silence. Garbled output
/// identifies this constant as the fault; silence identifies nothing.
pub const TX_READY_MASK: u32 = 1 << 2;

/// Number of times to poll [`TX_READY_MASK`] before transmitting anyway.
///
/// Chosen so that a wrong [`TX_READY_MASK`] cannot deadlock first light. This
/// is a bring-up affordance and is expected to disappear once OQ-1 closes.
pub const TX_POLL_LIMIT: u32 = 100_000;

/// Emergency-fallback MMIO base for the UART. **UNCONFIRMED for the target.**
///
/// This is the **`T6030` observation** recorded in the AS-0 fact table
/// (`apple-device-tree-format.md` §8.6): translated base `0x2_8920_0000`. The
/// deployment target is `T6020`, and that table states plainly that **the
/// `T6020` value will differ.**
///
/// It is a real measurement from a different SoC rather than an invented
/// number, which is the most honest fallback available. It exists for exactly
/// one purpose: to have *some* console on which to report that ADT resolution
/// failed.
///
/// **The ADT is authoritative** — see [`crate::discover`]. This value is read
/// only when ADT resolution has already failed, so being wrong costs the error
/// message on an already-failing path, never correct operation. It must never
/// be presented anywhere as the target's UART base.
pub const UART_BASE_FALLBACK: u64 = 0x2_8920_0000;

/// Confidence in [`UART_BASE_FALLBACK`] *for the deployment target*.
pub const UART_BASE_FALLBACK_CONFIDENCE: Confidence = Confidence::Unconfirmed;

/// ADT `compatible` value identifying the debug UART. **Observed on hardware.**
///
/// Source: AS-0 fact table `apple-device-tree-format.md` §8.6, marked `[O]`.
///
/// **This is not `apple,s5l-uart`.** That string is the *Linux FDT binding*
/// name, a different namespace used by the Linux driver. Matching on it would
/// find nothing on every machine, and the failure would present as a broken ADT
/// parser rather than as a wrong constant. The ADT's own value is this one.
pub const UART_ADT_COMPATIBLE: &[u8] = b"uart-1,samsung";

/// Preferred debug-console node path, used when [`UART_DEBUG_CONSOLE_MARKER`]
/// exists beneath it. **Observed.** AS-0 fact table §8.6.
pub const UART_PREFERRED_PATH: &[u8] = b"/arm-io/uart6";

/// Child node whose **mere existence** beneath [`UART_PREFERRED_PATH`] selects
/// it as the debug console. Its contents are never read. AS-0 fact table §8.6.
pub const UART_DEBUG_CONSOLE_MARKER: &[u8] = b"/arm-io/uart6/debug-console";

/// Fallback node path, used when [`UART_DEBUG_CONSOLE_MARKER`] is absent.
/// **Observed.** AS-0 fact table §8.6.
pub const UART_DEFAULT_PATH: &[u8] = b"/arm-io/uart0";
