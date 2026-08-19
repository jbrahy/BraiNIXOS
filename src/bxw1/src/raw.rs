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

/// Bytes in a SHA-256 digest.
pub(crate) const DIGEST_LEN: usize = 32;

/// Reads a little-endian `u16` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u16_le(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(*bytes.get(offset..)?.first_chunk()?))
}

/// Reads a little-endian `u32` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u32_le(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(*bytes.get(offset..)?.first_chunk()?))
}

/// Reads a little-endian `u64` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u64_le(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(*bytes.get(offset..)?.first_chunk()?))
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

/// The readers at both ends of their input.
///
/// # Why these are tests and not exemptions any more
///
/// These three used to be written as `bytes.get(offset..end)?` followed by a
/// slice pattern, with an `_ => None` arm the compiler could not prove
/// unreachable. That arm carried an exemption in every one of them.
///
/// `first_chunk` removes the arm rather than excusing it: it returns
/// `Option<&[u8; N]>` directly, so there is no "wrong length" case to write.
/// What is left are two `?`s that can BOTH fail for real -- an offset past the
/// end, and too few bytes remaining -- so the bounds check is reachable instead
/// of defensive, and the `checked_add` that computed `end` is gone with it.
///
/// Making the impossible state unrepresentable is better than justifying it.
// A flat list of boundary asserts reads as high cognitive complexity and is
// what a table of boundaries should look like; one function per case would
// hide the symmetry the cases exist to show.
#[cfg(test)]
#[allow(clippy::cognitive_complexity)]
mod tests {
    use super::{read_u16_le, read_u32_le, read_u64_le};

    #[test]
    fn the_widths_decode_little_endian_at_an_offset() {
        let bytes = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        assert_eq!(read_u16_le(&bytes, 1), Some(0x0201));
        assert_eq!(read_u32_le(&bytes, 1), Some(0x0403_0201));
        assert_eq!(read_u64_le(&bytes, 1), Some(0x0807_0605_0403_0201));
    }

    #[test]
    fn an_offset_past_the_end_reads_nothing() {
        // The first `?`. A tensor record's offset comes off the wire, so this
        // is hostile input rather than a programming error.
        let bytes = [0u8; 4];
        assert_eq!(read_u16_le(&bytes, 5), None);
        assert_eq!(read_u32_le(&bytes, 99), None);
        assert_eq!(read_u64_le(&bytes, usize::MAX), None);

        // Exactly at the end is past it for a read of any width: there are
        // zero bytes there.
        assert_eq!(read_u16_le(&bytes, 4), None);
        assert_eq!(read_u32_le(&bytes, 4), None);
    }

    #[test]
    fn a_field_that_runs_off_the_end_reads_nothing() {
        // The second `?`, which the old slice-pattern arm could never reach
        // because the range `get` had already refused. One byte short in each
        // case -- the boundary a truncated blob actually lands on.
        let bytes = [0u8; 8];
        assert_eq!(read_u16_le(&bytes, 7), None);
        assert_eq!(read_u32_le(&bytes, 5), None);
        assert_eq!(read_u64_le(&bytes, 1), None);

        // And exactly enough succeeds, so the refusals above are the boundary
        // rather than the function refusing everything near the end.
        assert_eq!(read_u16_le(&bytes, 6), Some(0));
        assert_eq!(read_u32_le(&bytes, 4), Some(0));
        assert_eq!(read_u64_le(&bytes, 0), Some(0));
    }

    #[test]
    fn an_empty_input_reads_nothing_at_offset_zero() {
        // Zero-length is the degenerate case a truncated blob presents, and
        // offset 0 is the one place a bounds check written as `offset < len`
        // would wave through.
        assert_eq!(read_u16_le(&[], 0), None);
        assert_eq!(read_u32_le(&[], 0), None);
        assert_eq!(read_u64_le(&[], 0), None);
    }
}
