//! `Q4_0`: four-bit weights, 32-element blocks, one `f32` scale each.
//!
//! # The trade this makes, stated before the code
//!
//! `Q4_0` costs **0.625 bytes per weight** -- half a byte of nibble plus 4/32 of
//! a scale -- against `Q8_0`'s 1.125. That is 1.8x fewer bytes moved, and on a
//! purely bandwidth-bound kernel it would be a 1.8x speedup.
//!
//! **It is not free, and the cost lands exactly where this kernel is weakest.**
//! `SDOT` consumes `i8` lanes, so every nibble must be unpacked to a byte before
//! the dot product can run. `Q8_0` hands the instruction its operands directly;
//! `Q4_0` pays a shift, a mask and a sign-extend per pair first. So `Q4_0`
//! trades memory traffic for arithmetic, and whether that is a win depends
//! entirely on which of the two the caller is short of:
//!
//! - **Bandwidth-bound** (measured on this project: four or more cores, past
//!   ~110 GB/s) -- fewer bytes is the whole game and `Q4_0` should win.
//! - **Compute-bound** (measured: one core, ~44 GB/s against that ceiling) --
//!   the unpack is added work against a bus that was not the constraint, and
//!   `Q4_0` may well **lose**.
//!
//! Both regimes exist in this system at once, which is why this module ships
//! with a benchmark rather than a recommendation.
//!
//! # Layout
//!
//! Deliberately the same shape as `Q8_0` -- a padded scale plane followed by a
//! quant plane -- so the two can be read by the same traversal and compared
//! without a second code path for the sake of a second format.
//!
//! Nibble order within a byte is **low nibble first**: byte `k` holds element
//! `2k` in bits [3:0] and element `2k+1` in bits [7:4]. Stated because it is
//! pure convention and a reader who assumes the other order gets plausible
//! garbage rather than an error.
//!
//! # The quantized range is -7..=7, not -8..=7
//!
//! Four bits hold sixteen values and the natural signed range is asymmetric.
//! Using -8 would make the scale `absmax / 8` in one direction and `absmax / 7`
//! in the other, so a symmetric round trip needs the smaller magnitude anyway.
//! Giving up the -8 encoding costs one representable level and buys an exactly
//! symmetric quantizer, which is worth more than 1/15th of the range.

use crate::error::TensorError;

/// Elements per `Q4_0` block. The same 32 as `Q8_0`, so a block of one format
/// covers the same span of a row as a block of the other.
pub const Q4_0_BLOCK: usize = 32;
/// Bytes of packed nibbles per block.
const Q4_0_BLOCK_BYTES: usize = Q4_0_BLOCK / 2;
/// Bytes in a little-endian binary32 scale.
const SCALE_BYTES: usize = 4;
/// Alignment the scale plane is padded to, matching BXW1's 128.
const ALIGN: usize = 128;

/// A borrowed `Q4_0` matrix, `[n_out, n_in]`.
#[derive(Debug, Clone, Copy)]
pub struct Q4Weights<'a> {
    scales: &'a [u8],
    quants: &'a [u8],
    n_out: usize,
    n_in: usize,
    blocks_per_row: usize,
}

impl<'a> Q4Weights<'a> {
    /// Byte length a `Q4_0` payload of this shape must have.
    pub fn derived_payload_len(n_out: usize, n_in: usize) -> Result<usize, TensorError> {
        if n_out == 0 || n_in == 0 {
            return Err(TensorError::ZeroDimension);
        }
        if !n_in.is_multiple_of(Q4_0_BLOCK) {
            return Err(TensorError::NotBlockAligned);
        }
        let blocks = n_out
            .checked_mul(n_in / Q4_0_BLOCK)
            .ok_or(TensorError::DimensionOverflow)?;
        let scales = blocks
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        let quants = blocks
            .checked_mul(Q4_0_BLOCK_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        scales
            .next_multiple_of(ALIGN)
            .checked_add(quants)
            .ok_or(TensorError::DimensionOverflow)
    }

    /// Views `payload` as `[n_out, n_in]`.
    pub fn new(payload: &'a [u8], n_out: usize, n_in: usize) -> Result<Self, TensorError> {
        let required = Self::derived_payload_len(n_out, n_in)?;
        if payload.len() != required {
            return Err(TensorError::PayloadLengthMismatch);
        }
        let blocks_per_row = n_in / Q4_0_BLOCK;
        let blocks = n_out
            .checked_mul(blocks_per_row)
            .ok_or(TensorError::DimensionOverflow)?;
        let scale_len = blocks
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_start = scale_len.next_multiple_of(ALIGN);
        let (scales, quants) = payload.split_at(quant_start);
        Ok(Self {
            scales: scales
                .get(..scale_len)
                .ok_or(TensorError::PayloadLengthMismatch)?,
            quants,
            n_out,
            n_in,
            blocks_per_row,
        })
    }

    /// Output features.
    #[must_use]
    pub const fn n_out(&self) -> usize {
        self.n_out
    }

    /// Input features.
    #[must_use]
    pub const fn n_in(&self) -> usize {
        self.n_in
    }

    /// `(scales, packed quants)` per row.
    pub(crate) fn rows(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.scales
            .chunks_exact(self.blocks_per_row.saturating_mul(SCALE_BYTES))
            .zip(
                self.quants
                    .chunks_exact(self.blocks_per_row.saturating_mul(Q4_0_BLOCK_BYTES)),
            )
    }
}

/// Unpacks one 16-byte block into 32 signed bytes.
///
/// Written as a straight loop over the packed bytes so the compiler can see
/// sixteen independent lane computations. This is the work `Q4_0` adds and
/// `Q8_0` does not pay, so it is the whole of the trade.
#[inline(always)]
pub(crate) fn unpack_block(packed: &[u8], out: &mut [u8; Q4_0_BLOCK]) {
    for (index, byte) in packed.iter().enumerate().take(Q4_0_BLOCK_BYTES) {
        // Sign-extend each nibble from four bits: shift into the top of a byte
        // and back down arithmetically. Cheaper than a branch and constant-time.
        let low = (((byte << 4) as i8) >> 4) as u8;
        let high = ((*byte as i8) >> 4) as u8;
        if let Some(slot) = out.get_mut(index.saturating_mul(2)) {
            *slot = low;
        }
        if let Some(slot) = out.get_mut(index.saturating_mul(2).saturating_add(1)) {
            *slot = high;
        }
    }
}

/// Quantizes `f32` values into a `Q4_0` payload.
///
/// # Errors
///
/// [`TensorError::ShapeMismatch`] if the slices disagree with the shape.
pub fn quantize_q4_0(
    n_out: usize,
    n_in: usize,
    values: &[f32],
    payload: &mut [u8],
) -> Result<(), TensorError> {
    let required_values = n_out
        .checked_mul(n_in)
        .ok_or(TensorError::DimensionOverflow)?;
    if values.len() != required_values {
        return Err(TensorError::ShapeMismatch);
    }
    let required = Q4Weights::derived_payload_len(n_out, n_in)?;
    if payload.len() != required {
        return Err(TensorError::ShapeMismatch);
    }
    let blocks = n_out
        .checked_mul(n_in / Q4_0_BLOCK)
        .ok_or(TensorError::DimensionOverflow)?;
    let quant_start = blocks
        .checked_mul(SCALE_BYTES)
        .ok_or(TensorError::DimensionOverflow)?
        .next_multiple_of(ALIGN);
    let (scale_plane, quant_plane) = payload.split_at_mut(quant_start);

    for (index, block) in values.chunks_exact(Q4_0_BLOCK).enumerate() {
        let mut peak = 0.0_f32;
        for value in block {
            let magnitude = if *value < 0.0 { -*value } else { *value };
            if magnitude > peak {
                peak = magnitude;
            }
        }
        // -7..=7, not -8..=7: see the module note on symmetry.
        let scale = peak / 7.0;
        let usable = peak > 0.0 && scale >= f32::MIN_POSITIVE;
        let at = index
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        // COVERAGE-EXEMPT: `payload` was checked against
        // `Q4Weights::derived_payload_len` at entry and `at` is derived from
        // the same block count, so this range is always in bounds. The guard is
        // defence in depth behind a check one frame up.
        let Some(slot) = scale_plane.get_mut(at..at.saturating_add(SCALE_BYTES)) else {
            return Err(TensorError::ShapeMismatch);
        };
        slot.copy_from_slice(&if usable { scale } else { 0.0 }.to_le_bytes());

        let packed_at = index
            .checked_mul(Q4_0_BLOCK_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        // COVERAGE-EXEMPT: as the scale plane above.
        let Some(packed) =
            quant_plane.get_mut(packed_at..packed_at.saturating_add(Q4_0_BLOCK_BYTES))
        else {
            return Err(TensorError::ShapeMismatch);
        };
        for (byte_index, byte) in packed.iter_mut().enumerate() {
            let encode = |offset: usize| -> u8 {
                if !usable {
                    return 0;
                }
                // COVERAGE-EXEMPT: `block` is a `chunks_exact(Q4_0_BLOCK)`
                // item and `byte_index` runs over `Q4_0_BLOCK / 2` bytes, so
                // both nibble offsets are in range for every block.
                let Some(value) = block.get(byte_index.saturating_mul(2).saturating_add(offset))
                else {
                    return 0;
                };
                let scaled = value / scale;
                let rounded = if scaled >= 0.0 {
                    scaled + 0.5
                } else {
                    scaled - 0.5
                } as i32;
                (rounded.clamp(-7, 7) as i8 as u8) & 0x0F
            };
            *byte = encode(0) | (encode(1) << 4);
        }
    }
    Ok(())
}
