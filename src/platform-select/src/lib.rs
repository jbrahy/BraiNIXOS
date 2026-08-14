#![no_std]
#![deny(unsafe_code)]

//! Selecting a driver from an ADT `compatible` string, and refusing when it is
//! one we do not know (AS-2a).
//!
//! The roadmap's note on AIC is where this rule comes from: *"select the AIC
//! revision from ADT compatible strings at runtime; **fail closed on an unknown
//! string**."* The same sentence applies to DART, whose PTE formats differ
//! across SoC generations, and to every other device discovered from firmware.
//!
//! # Why unknown must mean refuse rather than default
//!
//! The tempting alternative is to fall back to the newest revision we know, on
//! the theory that a newer SoC is probably compatible. It is the wrong theory
//! and the failure is silent: an unrecognised DART variant driven by the wrong
//! PTE format programs *something*, the write succeeds, and the device gets a
//! translation window nobody intended — which is a DMA escape produced by
//! optimism. The threat model ranks that seventh among deployment threats and
//! says the mitigation in one clause: "an unrecognized DART variant fails
//! closed rather than falling back."
//!
//! Firmware-supplied strings are hostile input (`INV-PARSE-003`), so this is a
//! parser with the discipline that implies: exact matching, no prefixes, no
//! normalisation, and no interpretation of a string it does not hold.
//!
//! # What this module is not
//!
//! It knows no register offsets, no PTE formats, and nothing about what a
//! revision *does*. Those come from a `docs/platform-specs/` fact table written
//! by the spec-author role under the clean-room procedure, and none exists for
//! AIC yet. This is the selection rule, which needs only the ADT format that is
//! already specified.

/// A device this build knows how to drive.
///
/// Adding a variant means adding a driver, which means adding a spec file.
/// The enum is deliberately the narrow part: a string that maps to no variant
/// is a device we cannot drive, whatever else is true about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownDevice {
    /// The exact `compatible` string, as firmware spells it.
    pub compatible: &'static str,
    /// What this build calls the revision, for logs and for the driver to match.
    pub revision: &'static str,
}

/// Why no driver was selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionError {
    /// The string names a device this build does not know.
    ///
    /// Not "probably close to one we know". Fail closed.
    UnknownCompatible,
    /// The node carried no `compatible` string at all.
    MissingCompatible,
    /// The string is not valid UTF-8, so it names nothing.
    NotText,
}

/// Selects the device whose `compatible` string matches exactly.
///
/// # Errors
///
/// [`SelectionError`], and every variant is a refusal rather than a fallback.
///
/// Matching is **exact**: no prefix match, no case folding, no trimming beyond
/// the trailing NUL the ADT stores. A prefix match is how `aic,3` would select
/// the driver for `aic,3-experimental`, and a fold is how a string that differs
/// from a known one only in case would look like it.
pub fn select<'a>(
    compatible: Option<&[u8]>,
    known: &'a [KnownDevice],
) -> Result<&'a KnownDevice, SelectionError> {
    let bytes = compatible.ok_or(SelectionError::MissingCompatible)?;
    if bytes.is_empty() {
        return Err(SelectionError::MissingCompatible);
    }

    // The ADT stores C strings: take everything before the first NUL, and treat
    // a string that is all NUL as absent rather than as the empty device.
    let text_bytes = match bytes.iter().position(|byte| *byte == 0) {
        Some(end) => bytes.get(..end).ok_or(SelectionError::NotText)?,
        None => bytes,
    };
    if text_bytes.is_empty() {
        return Err(SelectionError::MissingCompatible);
    }

    let text = core::str::from_utf8(text_bytes).map_err(|_| SelectionError::NotText)?;

    known
        .iter()
        .find(|device| device.compatible == text)
        .ok_or(SelectionError::UnknownCompatible)
}

/// The AIC revisions this build knows.
///
/// Empty, and that is the honest state: selecting an AIC revision requires a
/// driver for it, a driver requires register offsets, and those require a
/// `docs/platform-specs/` fact table that the clean-room procedure has not yet
/// produced. An empty table means every AIC node fails closed, which is exactly
/// what a build with no AIC driver should do — and it is a table that grows by
/// adding a spec, not by adding a guess.
pub const KNOWN_AIC_REVISIONS: [KnownDevice; 0] = [];
