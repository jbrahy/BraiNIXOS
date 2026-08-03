//! Bounds-checked little-endian readers and the float bit-pattern classifier.
//!
//! Every field of a BXW1 blob is assembled from a byte slice by an explicit
//! little-endian reader (§2). There is no `#[repr(C)]` struct cast, no
//! `transmute`, and no pointer cast over blob bytes -- which is why the
//! 160-byte tensor record need not be a power of two: record alignment is
//! irrelevant when nothing is read through a typed pointer.
//!
//! Two offset bases are in play and are never mixed:
//!
//! - **blob offsets** are `u64`, because they come from the blob's own fields
//!   and §7.6 requires all arithmetic over blob-supplied values to be checked
//!   `u64` arithmetic. They become `usize` only through [`slice_at`], which
//!   fails rather than truncating;
//! - **record-relative offsets** are `usize` compile-time constants inside a
//!   slice whose length is already known.

use crate::error::Bxw1Error;

/// Bytes in a little-endian `u16`.
const U16_LEN: usize = 2;

/// Bytes in a little-endian `u32`.
const U32_LEN: usize = 4;

/// Bytes in a little-endian `u64`.
const U64_LEN: usize = 8;

/// Bytes in a SHA-256 digest.
pub(crate) const DIGEST_LEN: usize = 32;

/// Reads a little-endian `u16` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(U16_LEN)?;
    match bytes.get(offset..end)? {
        [b0, b1] => Some(u16::from_le_bytes([*b0, *b1])),
        _ => None,
    }
}

/// Reads a little-endian `u32` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(U32_LEN)?;
    match bytes.get(offset..end)? {
        [b0, b1, b2, b3] => Some(u32::from_le_bytes([*b0, *b1, *b2, *b3])),
        _ => None,
    }
}

/// Reads a little-endian `u64` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(U64_LEN)?;
    let field = bytes.get(offset..end)?;
    match field {
        [b0, b1, b2, b3, b4, b5, b6, b7] => {
            Some(u64::from_le_bytes([*b0, *b1, *b2, *b3, *b4, *b5, *b6, *b7]))
        }
        _ => None,
    }
}

/// Borrows the fixed-size field of `length` bytes at `offset`.
pub(crate) fn read_field(bytes: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    let end = offset.checked_add(length)?;
    bytes.get(offset..end)
}

/// Borrows `length` bytes at blob offset `offset`, both `u64`.
///
/// This is the single place a blob-supplied `u64` becomes a `usize`. The
/// conversion is fallible and never truncates: the target's `usize` is 64 bits
/// and the specification deliberately does not rely on that (§7.6).
pub(crate) fn slice_at(blob: &[u8], offset: u64, length: u64) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let count = usize::try_from(length).ok()?;
    let end = start.checked_add(count)?;
    blob.get(start..end)
}

/// Refuses a run of pad bytes that is not entirely zero (rule D19).
pub(crate) fn require_zero(bytes: &[u8]) -> Result<(), Bxw1Error> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(Bxw1Error::NonZeroPadByte);
    }
    Ok(())
}

/// The §4.7 bit-pattern rule for a value whose **sign must be clear**: a
/// scale, `rope_theta`, or `norm_eps`.
///
/// Accepts exactly `+0.0` or a positive finite normal, and therefore rejects
/// NaN, ±Inf, subnormals, negatives and `-0.0` in a single pair of integer
/// comparisons. `+0.0` is admitted because §4.2 makes it the canonical scale
/// of an all-zero `Q8_0` block.
///
/// Classification is done on the `u32` **before** any value is interpreted as
/// a float, because comparing an unvalidated float is itself the bug: `NaN < x`
/// and `NaN > x` are both false, so a float-comparison range check accepts NaN
/// silently.
pub(crate) fn is_positive_finite(bits: u32) -> bool {
    /// Smallest positive normal, 2^-126.
    const MIN_NORMAL: u32 = 0x0080_0000;
    /// `f32::MAX`; `0x7F80_0000` is `+Inf` and everything above is Inf or NaN.
    const MAX_FINITE: u32 = 0x7F7F_FFFF;
    /// The sign bit.
    const SIGN: u32 = 0x8000_0000;

    if bits & SIGN != 0 {
        return false;
    }
    bits == 0 || (MIN_NORMAL..=MAX_FINITE).contains(&bits)
}

/// The §4.7 bit-pattern rule for an `F32` **element**: the same rule with the
/// sign bit unconstrained, since weights are legitimately negative.
///
/// Rejects NaN, ±Inf and subnormals. Admits `±0.0`.
pub(crate) fn is_finite_element(bits: u32) -> bool {
    /// Everything but the sign bit.
    const MAGNITUDE: u32 = 0x7FFF_FFFF;
    is_positive_finite(bits & MAGNITUDE)
}

/// Compares a computed SHA-256 against a 32-byte field from the blob.
pub(crate) fn digests_equal(computed: &[u8], declared: &[u8]) -> bool {
    computed.len() == DIGEST_LEN && declared.len() == DIGEST_LEN && computed == declared
}
