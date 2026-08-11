//! Resolve the debug UART's MMIO base from the Apple Device Tree.
//!
//! The algorithm is **not invented here**. It is specified by the AS-0 fact
//! table, `docs/platform-specs/apple-device-tree-format.md` §8.6, and mirrored
//! in [`crate::registers`]:
//!
//! 1. If `/arm-io/uart6/debug-console` exists, use `/arm-io/uart6`.
//! 2. Otherwise use `/arm-io/uart0`.
//! 3. If neither exists, **fail**. There is no third candidate and no default
//!    address.
//!
//! The node's `reg` address is **translated through `/arm-io`'s `ranges`**.
//! §8.6 is explicit about why: an untranslated `/arm-io` address is a
//! valid-looking physical address pointing at the wrong place, which is exactly
//! the input an attacker wants a driver to MMIO-map.
//!
//! Everything in this module is pure and takes the ADT as a byte slice, so all
//! of it is exercised on the host.

use brainix_adt::{AdtError, DeviceTree};

use crate::registers::{
    UART_ADT_COMPATIBLE, UART_DEBUG_CONSOLE_MARKER, UART_DEFAULT_PATH, UART_PREFERRED_PATH,
};

/// Why UART discovery denied.
///
/// Every variant is a distinct, reportable cause. Discovery never falls back to
/// a guess and never returns a partially validated address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverError {
    /// The ADT blob did not parse. Carries the decoder's own reason.
    AdtParse(AdtError),

    /// Testing for the `debug-console` marker failed for a reason other than
    /// its absence.
    MarkerProbe(AdtError),

    /// Neither `/arm-io/uart6` nor `/arm-io/uart0` resolved.
    ///
    /// §8.6: there is no third candidate and no default address, so this
    /// denies rather than guessing.
    NoUartNode,

    /// The selected node carries no `compatible` property.
    CompatibleMissing,

    /// The selected node's `compatible` does not contain `uart-1,samsung`.
    ///
    /// Reaching this means the node selection found *a* node that is not the
    /// UART, which is a stronger signal of a wrong assumption than silence.
    CompatibleMismatch,

    /// The node's `reg` was absent, malformed, or untranslatable through
    /// `/arm-io`'s `ranges`.
    RegUntranslatable(AdtError),

    /// The UART's parent carries no `ranges` property, so no translation could
    /// have happened.
    ///
    /// This is **not** redundant with [`Self::RegUntranslatable`], and the
    /// difference is security-relevant. `NodePath::translated_reg` documents
    /// that the *absence* of `ranges` on an ancestor **terminates** translation
    /// rather than failing it — it "does not mean identity and it does not mean
    /// error" — so it returns the raw address successfully.
    ///
    /// That is correct in general: a missing `ranges` marks an address-space
    /// boundary. It is wrong *here*, because §8.6 states that a `/arm-io`
    /// child's `reg` **must** be translated, and that untranslated it "points
    /// nowhere". Mapping such an address would hand MMIO a valid-looking
    /// physical address aimed at the wrong device — precisely the outcome §8.5
    /// exists to prevent.
    ///
    /// So a successful return from `translated_reg` is not on its own evidence
    /// that translation occurred, and this variant is the check that closes the
    /// gap.
    TranslationUnavailable,
}

/// Which path the selection algorithm chose.
///
/// Reported on the console so that a bring-up session can tell "took the
/// debug-console branch" from "fell through to uart0" without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedNode {
    /// `/arm-io/uart6`, selected because its `debug-console` child exists.
    PreferredWithMarker,
    /// `/arm-io/uart0`, selected because the marker was absent.
    Default,
}

/// A resolved UART, and how it was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UartLocation {
    /// Translated physical MMIO base of the UART register block.
    pub base: u64,
    /// Which branch of the §8.6 algorithm produced it.
    pub selected: SelectedNode,
}

/// Resolve the debug UART's translated MMIO base from an ADT blob.
pub fn uart_base_from_adt(adt_blob: &[u8]) -> Result<UartLocation, DiscoverError> {
    let tree = DeviceTree::parse(adt_blob).map_err(DiscoverError::AdtParse)?;

    // Step 1: the marker's mere existence is the signal. Its contents are never
    // read (§8.6).
    let marker_present = tree
        .node_exists(UART_DEBUG_CONSOLE_MARKER)
        .map_err(DiscoverError::MarkerProbe)?;

    let (path, selected) = if marker_present {
        (UART_PREFERRED_PATH, SelectedNode::PreferredWithMarker)
    } else {
        (UART_DEFAULT_PATH, SelectedNode::Default)
    };

    // Step 2 and 3. `resolve` keeps the ancestor chain, which is what makes the
    // `/arm-io` `ranges` translation below possible at all.
    let node_path = match tree.resolve(path) {
        Ok(resolved) => resolved,
        Err(AdtError::NodeNotFound) => return Err(DiscoverError::NoUartNode),
        Err(error) => return Err(DiscoverError::AdtParse(error)),
    };

    // Cross-check that the node selection landed on something that actually
    // claims to be this UART. A wrong path that happens to resolve is worse
    // than one that does not, because its `reg` would MMIO-map a real device.
    let node = node_path.node();
    let compatible = node
        .find_property(b"compatible")
        .map_err(DiscoverError::AdtParse)?
        .ok_or(DiscoverError::CompatibleMissing)?;
    if !compatible.has_string(UART_ADT_COMPATIBLE) {
        return Err(DiscoverError::CompatibleMismatch);
    }

    // Establish that translation is even possible before trusting its result.
    // `translated_reg` returns the *raw* address when an ancestor has no
    // `ranges`, which is right in general and wrong for `/arm-io` — see
    // `DiscoverError::TranslationUnavailable`.
    let parent = node_path
        .parent()
        .ok_or(DiscoverError::TranslationUnavailable)?;
    let parent_has_ranges = parent
        .find_property(b"ranges")
        .map_err(DiscoverError::AdtParse)?
        .is_some();
    if !parent_has_ranges {
        return Err(DiscoverError::TranslationUnavailable);
    }

    // Translated, never raw. §8.6 and §8.5.
    let range = node_path
        .translated_reg(0)
        .map_err(DiscoverError::RegUntranslatable)?;

    Ok(UartLocation {
        base: range.address,
        selected,
    })
}
