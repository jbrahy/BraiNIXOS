//! The `Q8_0` split-plane weight view (BXW1 §4.2).
//!
//! A `Q8_0` tensor's payload is **two contiguous planes**, not an interleaved
//! sequence of blocks:
//!
//! ```text
//! data_off  ──►  scale plane   nblocks × 4 bytes, little-endian f32
//!                zero pad      0..127 bytes, up to BXW1_ALIGN
//! quant_off ──►  quant plane   nblocks × 32 bytes, two's-complement i8
//! ```
//!
//! [`Q8Weights`] borrows those bytes and does the arithmetic that turns a
//! declared `[n_out, n_in]` shape into the two plane slices, once, at
//! construction. Every kernel then walks the planes with `chunks_exact`, so no
//! offset is ever recomputed and no index is ever formed in an inner loop.
//!
//! # What this view validates, and what it does not
//!
//! It validates exactly what it needs to be memory-safe and shape-correct:
//! non-zero extents, `n_in % 32 == 0` (BXW1 rule D8), and a payload length
//! equal to the length §4.3 derives. It does **not** re-verify the loader's
//! obligations — rule C3 (every scale is a positive finite normal), rule D19
//! (the inter-plane pad is zero), or the per-tensor digest. Those belong to the
//! Full-tier BXW1 loader (P3-T3), which reads every payload byte anyway during
//! the digest pass; repeating them per matmul would be a second full pass over
//! the weights on a bandwidth-bound machine, which is the single most expensive
//! thing this crate could do. The precondition is stated here rather than
//! assumed silently: **a `Q8_0` payload reaching this crate has already been
//! validated by the loader.** A NaN scale that slips through produces NaN
//! outputs, not unsafety.

use crate::error::TensorError;

/// Elements per `Q8_0` block (BXW1 §4.2, `BXW1_Q8_0_BLOCK`).
pub const Q8_0_BLOCK: usize = 32;

/// Tensor-data alignment in bytes (BXW1 §4.4, `BXW1_ALIGN`).
///
/// The reference machine's cache-line size, not its page size. It governs the
/// pad between a `Q8_0` tensor's scale and quant planes.
pub const BXW1_ALIGN: usize = 128;

/// `BXW1_ALIGN - 1`, as its own constant so the round-up needs no subtraction.
const BXW1_ALIGN_MASK: usize = 127;

/// Bytes in a little-endian binary32 scale.
const SCALE_BYTES: usize = 4;

/// Rounds `value` up to a multiple of [`BXW1_ALIGN`], refusing rather than
/// wrapping.
fn round_up_to_align(value: usize) -> Result<usize, TensorError> {
    let raised = value
        .checked_add(BXW1_ALIGN_MASK)
        .ok_or(TensorError::DimensionOverflow)?;
    Ok(raised & !BXW1_ALIGN_MASK)
}

/// Reads a little-endian binary32 from exactly four bytes.
///
/// The slice pattern is what makes this total: there is no indexing, no
/// `copy_from_slice`, and no `try_into().unwrap()`. On a little-endian target
/// the whole function is one load.
pub(crate) fn read_f32_le(bytes: &[u8]) -> Option<f32> {
    match bytes {
        [b0, b1, b2, b3] => Some(f32::from_le_bytes([*b0, *b1, *b2, *b3])),
        _ => None,
    }
}

/// A borrowed, shape-validated `Q8_0` weight matrix stored `[n_out, n_in]`
/// row-major (BXW1 §6.1).
///
/// Holds no buffer and owns nothing. Constructing one is `O(1)`: it computes
/// plane offsets and splits the payload, and reads no weight byte.
#[derive(Debug, Clone, Copy)]
pub struct Q8Weights<'a> {
    /// The scale plane: exactly `n_blocks × 4` bytes.
    scales: &'a [u8],
    /// The quant plane: exactly `n_blocks × 32` bytes.
    quants: &'a [u8],
    /// Rows — output features.
    n_out: usize,
    /// Columns — input features. A multiple of [`Q8_0_BLOCK`].
    n_in: usize,
    /// `n_in / Q8_0_BLOCK`, precomputed so no inner loop divides.
    blocks_per_row: usize,
    /// `blocks_per_row × 4`, the scale-plane stride of one output row.
    scale_stride: usize,
    /// `blocks_per_row × 32`, the quant-plane stride of one output row.
    quant_stride: usize,
}

impl<'a> Q8Weights<'a> {
    /// Splits a BXW1 `Q8_0` payload into its two planes against a declared
    /// `[n_out, n_in]` shape.
    ///
    /// # Errors
    ///
    /// - [`TensorError::ZeroDimension`] if either extent is zero.
    /// - [`TensorError::NotBlockAligned`] if `n_in` is not a multiple of
    ///   [`Q8_0_BLOCK`] — BXW1 rule D8, which is what guarantees no block
    ///   straddles a row boundary.
    /// - [`TensorError::DimensionOverflow`] if the derived length overflows.
    /// - [`TensorError::PayloadLengthMismatch`] if `payload.len()` is not
    ///   exactly the derived length, **in either direction**. A short payload
    ///   would truncate; a long one means the caller and the shape disagree,
    ///   and BXW1 §7.5 refuses rather than picking a winner.
    pub fn new(payload: &'a [u8], n_out: usize, n_in: usize) -> Result<Self, TensorError> {
        if n_out == 0 || n_in == 0 {
            return Err(TensorError::ZeroDimension);
        }
        if !n_in.is_multiple_of(Q8_0_BLOCK) {
            return Err(TensorError::NotBlockAligned);
        }

        let blocks_per_row = n_in / Q8_0_BLOCK;
        let n_blocks = n_out
            .checked_mul(blocks_per_row)
            .ok_or(TensorError::DimensionOverflow)?;
        let scale_len = n_blocks
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_off = round_up_to_align(scale_len)?;
        let quant_len = n_blocks
            .checked_mul(Q8_0_BLOCK)
            .ok_or(TensorError::DimensionOverflow)?;
        let derived_len = quant_off
            .checked_add(quant_len)
            .ok_or(TensorError::DimensionOverflow)?;

        if payload.len() != derived_len {
            return Err(TensorError::PayloadLengthMismatch);
        }

        let scales = payload
            .get(..scale_len)
            .ok_or(TensorError::MalformedPayload)?;
        let quants = payload
            .get(quant_off..derived_len)
            .ok_or(TensorError::MalformedPayload)?;

        let scale_stride = blocks_per_row
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_stride = blocks_per_row
            .checked_mul(Q8_0_BLOCK)
            .ok_or(TensorError::DimensionOverflow)?;

        Ok(Self {
            scales,
            quants,
            n_out,
            n_in,
            blocks_per_row,
            scale_stride,
            quant_stride,
        })
    }

    /// The byte length a `Q8_0` payload of this shape must have (BXW1 §4.3).
    ///
    /// Exposed so a caller can size or check a payload without constructing a
    /// view, and so the derivation lives in exactly one place.
    ///
    /// # Errors
    ///
    /// The same shape errors [`Q8Weights::new`] returns, minus the
    /// payload-length check.
    pub fn derived_payload_len(n_out: usize, n_in: usize) -> Result<usize, TensorError> {
        if n_out == 0 || n_in == 0 {
            return Err(TensorError::ZeroDimension);
        }
        if !n_in.is_multiple_of(Q8_0_BLOCK) {
            return Err(TensorError::NotBlockAligned);
        }
        let n_blocks = n_out
            .checked_mul(n_in / Q8_0_BLOCK)
            .ok_or(TensorError::DimensionOverflow)?;
        let scale_len = n_blocks
            .checked_mul(SCALE_BYTES)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_len = n_blocks
            .checked_mul(Q8_0_BLOCK)
            .ok_or(TensorError::DimensionOverflow)?;
        round_up_to_align(scale_len)?
            .checked_add(quant_len)
            .ok_or(TensorError::DimensionOverflow)
    }

    /// Output features — the number of rows.
    #[must_use]
    pub const fn n_out(&self) -> usize {
        self.n_out
    }

    /// Input features — the number of columns, a multiple of [`Q8_0_BLOCK`].
    #[must_use]
    pub const fn n_in(&self) -> usize {
        self.n_in
    }

    /// Blocks in one output row.
    #[must_use]
    pub const fn blocks_per_row(&self) -> usize {
        self.blocks_per_row
    }

    /// Iterates the rows of the matrix as `(scale bytes, quant bytes)` pairs.
    ///
    /// This is the accessor the matmul is built on: one `chunks_exact` walk per
    /// plane, zipped, so the whole traversal is two sequential streams with no
    /// index arithmetic.
    pub(crate) fn rows(&self) -> impl Iterator<Item = (&'a [u8], &'a [u8])> {
        self.scales
            .chunks_exact(self.scale_stride)
            .zip(self.quants.chunks_exact(self.quant_stride))
    }

    /// Materializes the whole tensor as `f32`, row-major, applying the
    /// normative dequantization of BXW1 §4.2:
    ///
    /// ```text
    /// x[b*32 + j] = scale[b] × (f32) q[b*32 + j]
    /// ```
    ///
    /// **This is not the inference path and must not be used as one.** It
    /// writes `n_out × n_in × 4` bytes — 3.56× the tensor's stored size — which
    /// is precisely the cost `Q8_0` exists to avoid (BXW1 §4.5). It exists so
    /// the round-trip and matmul-agreement tests have a reference, and so a
    /// future debugging path can dump a tensor. [`crate::matmul_q8_0`]
    /// dequantizes against activations already in registers and never
    /// materializes anything.
    ///
    /// # Errors
    ///
    /// [`TensorError::ShapeMismatch`] if `out.len()` is not exactly
    /// `n_out × n_in`; [`TensorError::MalformedPayload`] if a scale could not be
    /// read, which the constructor's length check makes unreachable.
    pub fn dequantize_into(&self, out: &mut [f32]) -> Result<(), TensorError> {
        let elements = self
            .n_out
            .checked_mul(self.n_in)
            .ok_or(TensorError::DimensionOverflow)?;
        if out.len() != elements {
            return Err(TensorError::ShapeMismatch);
        }

        for ((scale_row, quant_row), out_row) in self.rows().zip(out.chunks_exact_mut(self.n_in)) {
            for ((scale_bytes, quant_block), out_block) in scale_row
                .chunks_exact(SCALE_BYTES)
                .zip(quant_row.chunks_exact(Q8_0_BLOCK))
                .zip(out_row.chunks_exact_mut(Q8_0_BLOCK))
            {
                let scale = read_f32_le(scale_bytes).ok_or(TensorError::MalformedPayload)?;
                for (quant, slot) in quant_block.iter().zip(out_block.iter_mut()) {
                    *slot = scale * f32::from(*quant as i8);
                }
            }
        }
        Ok(())
    }

    /// Dequantizes **one row** into a caller-supplied `n_in`-long slice.
    ///
    /// This is the accessor a token-embedding lookup needs, and the reason it
    /// exists rather than being expressed through
    /// [`Q8Weights::dequantize_into`]: BXW1 §6.2 permits
    /// `tok_embeddings.weight` to be `Q8_0`, and the embedding of one token is
    /// one row of a `[vocab_size, d_model]` matrix. Reaching that row through
    /// the whole-matrix path would materialize `vocab_size × d_model` floats —
    /// 3.56× the tensor's stored size, in a buffer nothing here may allocate
    /// (`INV-MEM`) — in order to read `d_model` of them. Without this accessor a
    /// `Q8_0` embedding table is format-legal and unservable.
    ///
    /// **It reads only the row.** Each plane is cut at `row × stride` and no
    /// other byte is touched, so the traffic is `n_in × 1.125` bytes and the
    /// work is `n_in` multiplies, both independent of `n_out`. It allocates
    /// nothing and owns nothing.
    ///
    /// The arithmetic is the same normative BXW1 §4.2 formula
    /// [`Q8Weights::dequantize_into`] applies, over the same bytes in the same
    /// order, so the two agree element for element on every row — `tests/edges.rs`
    /// asserts that bit for bit rather than leaving the two derivations to drift.
    ///
    /// # Errors
    ///
    /// - [`TensorError::RowOutOfRange`] if `row` is not less than `n_out`.
    /// - [`TensorError::ShapeMismatch`] if `out.len()` is not exactly `n_in`,
    ///   **in either direction** — a short slice would truncate the row, and a
    ///   long one means the caller and the shape disagree (BXW1 §7.5).
    /// - [`TensorError::DimensionOverflow`] if a plane offset overflows.
    /// - [`TensorError::MalformedPayload`] if a plane slice or a scale could not
    ///   be read, which the constructor's length check makes unreachable.
    ///
    /// Nothing is written on any error path: both agreements are established
    /// before the first output element.
    pub fn dequantize_row_into(&self, row: usize, out: &mut [f32]) -> Result<(), TensorError> {
        if row >= self.n_out {
            return Err(TensorError::RowOutOfRange);
        }
        if out.len() != self.n_in {
            return Err(TensorError::ShapeMismatch);
        }

        let scale_start = row
            .checked_mul(self.scale_stride)
            .ok_or(TensorError::DimensionOverflow)?;
        let scale_end = scale_start
            .checked_add(self.scale_stride)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_start = row
            .checked_mul(self.quant_stride)
            .ok_or(TensorError::DimensionOverflow)?;
        let quant_end = quant_start
            .checked_add(self.quant_stride)
            .ok_or(TensorError::DimensionOverflow)?;

        let scale_row = self
            .scales
            .get(scale_start..scale_end)
            .ok_or(TensorError::MalformedPayload)?;
        let quant_row = self
            .quants
            .get(quant_start..quant_end)
            .ok_or(TensorError::MalformedPayload)?;

        for ((scale_bytes, quant_block), out_block) in scale_row
            .chunks_exact(SCALE_BYTES)
            .zip(quant_row.chunks_exact(Q8_0_BLOCK))
            .zip(out.chunks_exact_mut(Q8_0_BLOCK))
        {
            let scale = read_f32_le(scale_bytes).ok_or(TensorError::MalformedPayload)?;
            for (quant, slot) in quant_block.iter().zip(out_block.iter_mut()) {
                *slot = scale * f32::from(*quant as i8);
            }
        }
        Ok(())
    }
}
