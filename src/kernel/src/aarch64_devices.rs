//! Resolving a device's register base from the Apple Device Tree.
//!
//! Pure over a byte slice, so it is host-testable against the real tree read
//! off the target. Same split as `aarch64_ident`, `aarch64_walk` and
//! `aarch64_tables`: the arithmetic lives here, the MMIO lives in
//! `arch::aarch64`.
//!
//! # Why this is worth its own module
//!
//! Three call sites now need "the translated `reg` of an `/arm-io` node": the
//! console, the watchdog, and whatever comes next. Each one previously carried
//! its own copy of the same two guards, and the guards are the entire content:
//!
//! - the address must be **translated** through `/arm-io`'s `ranges`, because
//!   an untranslated one is a valid-looking physical address pointing at the
//!   wrong device;
//! - `translated_reg` returns the **raw** address successfully when an ancestor
//!   has no `ranges`, which is right in general and wrong here, so the presence
//!   of `ranges` has to be checked separately.
//!
//! A copy of that pair which drops the second guard looks correct, passes, and
//! hands a driver an address that points nowhere. For the watchdog, what gets
//! written to that address is a machine reset.

use brainix_adt::DeviceTree;

/// Resolve the translated base of `path`'s `reg[index]`.
///
/// Returns `None` rather than a raw address if translation was not possible.
pub fn translated_reg(adt_blob: &[u8], path: &[u8], index: usize) -> Option<u64> {
    let tree = DeviceTree::parse(adt_blob).ok()?;
    let node = tree.resolve(path).ok()?;
    // Establish that translation could happen before trusting its result.
    node.parent()?.find_property(b"ranges").ok()??;
    Some(node.translated_reg(index).ok()?.address)
}
