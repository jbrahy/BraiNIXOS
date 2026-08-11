//! Console bring-up ordering, and the base-address cross-check.
//!
//! # Why the ordering is what it is
//!
//! Fail-closed reporting is circular at boot: if the UART base comes from the
//! ADT and the ADT denies, there is no console on which to say so, and the
//! payload dies silently. Silence on a machine with no debugger is the worst
//! available outcome — it is indistinguishable from "never started".
//!
//! So the ordering is:
//!
//! 1. Emit a **liveness marker** on the fallback base. Cheap, no parsing, no
//!    failure mode beyond the address being wrong. Proves we are executing.
//! 2. Resolve the UART from the ADT ([`crate::discover`]).
//! 3. On success, everything further goes to the **ADT-derived** base, which is
//!    authoritative.
//! 4. On failure, fall back to the constant purely so the error is reportable.
//!
//! Silence therefore requires **two independent failures** — a wrong fallback
//! constant *and* a failed ADT resolution — rather than one.
//!
//! When both bases resolve and **disagree**, both values are printed and the
//! payload halts. Neither is silently preferred. This mirrors AS-0-T4's
//! ADT-versus-boot-args memory-range cross-check.

use crate::discover::{uart_base_from_adt, DiscoverError, SelectedNode, UartLocation};
use crate::registers::UART_BASE_FALLBACK;
use crate::uart::{Mmio, Uart};

/// The banner. Its appearance on a terminal *is* the AS-1a exit criterion.
pub const BANNER: &str = "\r\n[OK] BraiNIX: first light\r\n";

/// Emitted before anything can fail, to prove the payload is executing.
pub const LIVENESS_MARKER: &str = "\r\n[..] BraiNIX: alive\r\n";

/// How console bring-up ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The ADT resolved and its base matched [`UART_BASE_FALLBACK`].
    ///
    /// On the `T6020` target this is **not** the expected result: the fallback
    /// is a `T6030` observation and that SoC's base differs. Agreement here
    /// would mean the two SoCs happen to share a base.
    Agreed { base: u64, selected: SelectedNode },

    /// The ADT resolved and its base differs from the fallback constant.
    ///
    /// **This is the expected outcome on the target**, and it is not an error:
    /// it means the ADT did its job and the stale constant did not mislead us.
    /// Both values are reported.
    Disagreed {
        adt_base: u64,
        fallback_base: u64,
        selected: SelectedNode,
    },

    /// The ADT did not resolve. The error was reported on the fallback console.
    AdtFailed(DiscoverError),
}

/// Anything that can hand out an MMIO window for a given physical base.
///
/// Exists so bring-up is testable: the host test supplies fakes, the payload
/// supplies real volatile accessors.
pub trait MmioFactory {
    /// The MMIO window type produced.
    type Window: Mmio;

    /// Produce a window whose offset 0 is the physical address `base`.
    fn window_at(&mut self, base: u64) -> Self::Window;
}

/// Bring the console up and report the banner.
///
/// `adt_blob` is the already-located ADT. Locating it from `boot_args` is the
/// caller's job, because that step needs a physical-memory read the host cannot
/// perform.
pub fn bring_up<F: MmioFactory>(factory: &mut F, adt_blob: &[u8]) -> Outcome {
    // Step 1 — liveness, before anything that can deny.
    let mut fallback = Uart::new(factory.window_at(UART_BASE_FALLBACK));
    fallback.write_str(LIVENESS_MARKER);

    // Step 2 — the authoritative source.
    match uart_base_from_adt(adt_blob) {
        Ok(UartLocation { base, selected }) => {
            // Step 3 — everything further goes to the ADT-derived base.
            let mut authoritative = Uart::new(factory.window_at(base));
            authoritative.write_str(BANNER);
            authoritative.write_str("     uart base (adt): ");
            authoritative.write_hex_u64(base);
            authoritative.write_str("\r\n     node: ");
            authoritative.write_str(match selected {
                SelectedNode::PreferredWithMarker => "/arm-io/uart6 (debug-console present)",
                SelectedNode::Default => "/arm-io/uart0 (no debug-console marker)",
            });
            authoritative.write_str("\r\n");

            if base == UART_BASE_FALLBACK {
                Outcome::Agreed { base, selected }
            } else {
                // Not an error. Report both, prefer neither implicitly — the
                // ADT is authoritative by design, and saying so out loud is
                // what keeps the fallback from being mistaken for a fact.
                authoritative.write_str("     note: fallback constant differs: ");
                authoritative.write_hex_u64(UART_BASE_FALLBACK);
                authoritative
                    .write_str("\r\n     the adt value above is authoritative (t6030 constant)\r\n");
                Outcome::Disagreed {
                    adt_base: base,
                    fallback_base: UART_BASE_FALLBACK,
                    selected,
                }
            }
        }
        Err(error) => {
            // Step 4 — the fallback console exists for exactly this.
            fallback.write_str("[!!] BraiNIX: adt uart discovery denied: ");
            fallback.write_str(describe(error));
            fallback.write_str("\r\n");
            Outcome::AdtFailed(error)
        }
    }
}

/// A stable, allocation-free description of a discovery failure.
pub fn describe(error: DiscoverError) -> &'static str {
    match error {
        DiscoverError::AdtParse(_) => "adt parse denied",
        DiscoverError::MarkerProbe(_) => "debug-console probe denied",
        DiscoverError::NoUartNode => "neither /arm-io/uart6 nor /arm-io/uart0 resolved",
        DiscoverError::CompatibleMissing => "selected node has no compatible property",
        DiscoverError::CompatibleMismatch => "selected node is not uart-1,samsung",
        DiscoverError::RegUntranslatable(_) => "reg absent or untranslatable through /arm-io ranges",
        DiscoverError::TranslationUnavailable => "/arm-io has no ranges: reg cannot be translated",
    }
}
