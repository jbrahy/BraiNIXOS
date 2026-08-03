//! The two matrix multiplications: `f32` reference and `Q8_0`-dequantizing.
//!
//! # Orientation
//!
//! Both take weights stored `[n_out, n_in]` row-major — BXW1 §6.1's storage
//! convention — and activations stored `[n_tokens, n_in]` row-major, producing
//! `[n_tokens, n_out]`. A projection `y = W x` is therefore `n_out` dot
//! products, each over a *contiguous* row of `n_in` values. Nothing is
//! transposed here and there is no transpose flag; a producer with the other
//! orientation transposes once at conversion time rather than at every token.
//!
//! # Loop order, and why it is weights-outer
//!
//! Inference on the reference machine is memory-bandwidth-bound: single-stream
//! decode reads essentially the whole weight set per token, so the ceiling is
//! (model bytes ÷ memory bandwidth). Both kernels therefore run **one output
//! row of the weight matrix at a time, and all tokens inside it**:
//!
//! ```text
//! for each weight row r:                  ← the DRAM stream, touched once
//!     for each token t:                   ← re-reads x from cache, not DRAM
//!         y[t][r] = dot(w[r], x[t])
//! ```
//!
//! The alternative — tokens outer, weights inner — re-reads the whole weight
//! matrix once per token. For a `[4096, 4096]` `Q8_0` matrix that is 18.9 MB
//! per token instead of 18.9 MB per call. The order above pays for that with
//! activation re-reads, `n_out × n_tokens × n_in × 4` bytes of them, but the
//! working set is only `n_tokens × n_in × 4` — 131 KB for eight tokens of a
//! 4096-wide model — so those re-reads are served from cache and never reach
//! memory. **Weight bytes: read exactly once per call. Activation bytes: read
//! once from memory, then resident.**
//!
//! # Where tiling goes
//!
//! Two seams, both currently untiled and both marked here rather than guessed
//! at:
//!
//! 1. **The token dimension.** The order above holds while
//!    `n_tokens × n_in × 4` fits in the last-level cache. A long prefill
//!    exceeds that, and the fix is to strip-mine the token loop into tiles of
//!    `T` and run the weight sweep once per tile — trading `ceil(n_tokens/T)`
//!    weight sweeps for a resident activation block. `T` is a cache-geometry
//!    parameter and has no place being guessed before the machine is measured.
//! 2. **The `n_in` dimension.** For a weight row wider than L1, blocking `n_in`
//!    into panels and carrying partial sums keeps both the weight panel and the
//!    activation panel resident. For `Q8_0` the natural panel boundary is a
//!    whole number of 32-element blocks, which the layout already guarantees.
//!
//! Neither is implemented, because a tile size chosen without a measurement is
//! a guess, and NORTH_STAR's performance section is explicit that the wins are
//! in bytes moved rather than instructions issued.

use crate::error::TensorError;
use crate::q8::{read_f32_le, Q8Weights, Q8_0_BLOCK};

/// Bytes in a little-endian binary32 scale.
const SCALE_BYTES: usize = 4;

/// The three extents of a matrix multiply.
///
/// Passed as one value rather than three parameters so that a caller cannot
/// transpose two of them at a call site and still typecheck.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MatMulShape {
    /// Rows of the activation matrix — one per token in flight. `1` for
    /// single-stream decode.
    pub n_tokens: usize,
    /// Input features. The reduction dimension, and the fastest-varying axis of
    /// both the weights and the activations.
    pub n_in: usize,
    /// Output features. The number of rows of the weight matrix.
    pub n_out: usize,
}

impl MatMulShape {
    /// Checks that every extent is non-zero and that the supplied slices are
    /// exactly the lengths the shape requires.
    ///
    /// Runs to completion **before** any output element is written, so a
    /// refused call leaves `y` untouched.
    fn validate(&self, x_len: usize, y_len: usize) -> Result<(), TensorError> {
        if self.n_tokens == 0 || self.n_in == 0 || self.n_out == 0 {
            return Err(TensorError::ZeroDimension);
        }
        let required_x = self
            .n_tokens
            .checked_mul(self.n_in)
            .ok_or(TensorError::DimensionOverflow)?;
        let required_y = self
            .n_tokens
            .checked_mul(self.n_out)
            .ok_or(TensorError::DimensionOverflow)?;
        if x_len != required_x || y_len != required_y {
            return Err(TensorError::ShapeMismatch);
        }
        Ok(())
    }
}

/// `y = W xᵀ` with `f32` weights — the reference path.
///
/// `weights` is `[n_out, n_in]` row-major, `x` is `[n_tokens, n_in]`, `y` is
/// `[n_tokens, n_out]`. Accumulation is `f32`, matching what a NEON pass will
/// do, so the reference and the vectorized successor round identically in the
/// only respect that is under this crate's control — the order of the additions
/// within a row.
///
/// This path exists because BXW1 permits `F32` for every tensor and mandates it
/// for the norm weights, and because it is what [`matmul_q8_0`] is tested
/// against. It moves 4 bytes per weight, 3.56× what `Q8_0` moves, and on a
/// bandwidth-bound machine that ratio is the token-rate ratio directly.
///
/// # Errors
///
/// [`TensorError::ZeroDimension`], [`TensorError::DimensionOverflow`], or
/// [`TensorError::ShapeMismatch`] if the slices disagree with `shape`. Nothing
/// is written on any error.
pub fn matmul_f32(
    shape: MatMulShape,
    weights: &[f32],
    x: &[f32],
    y: &mut [f32],
) -> Result<(), TensorError> {
    shape.validate(x.len(), y.len())?;
    let required_weights = shape
        .n_out
        .checked_mul(shape.n_in)
        .ok_or(TensorError::DimensionOverflow)?;
    if weights.len() != required_weights {
        return Err(TensorError::ShapeMismatch);
    }

    for (out_index, weight_row) in weights.chunks_exact(shape.n_in).enumerate() {
        for (x_row, y_row) in x
            .chunks_exact(shape.n_in)
            .zip(y.chunks_exact_mut(shape.n_out))
        {
            let mut acc = 0.0_f32;
            for (w, xv) in weight_row.iter().zip(x_row.iter()) {
                acc += w * xv;
            }
            let slot = y_row.get_mut(out_index).ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` with `Q8_0` weights and `f32` activations — the hot path.
///
/// The weights are **never materialized**. Each 32-element block is
/// dequantized against activations already in registers, and the block's scale
/// is factored out of the inner 32 multiplies:
///
/// ```text
/// acc += scale[b] × Σ_j (i8) q[b][j] × x[b*32 + j]
/// ```
///
/// which is algebraically the §4.2 formula `Σ_j scale[b]·q · x` and
/// numerically slightly better, since the 32 products are summed before the
/// scale's rounding is applied once instead of 32 times.
///
/// # Bytes moved
///
/// Per weight element: **1 byte of quant plus 4/32 = 0.125 bytes of scale =
/// 1.125 bytes**, read exactly once per call, in two purely sequential,
/// 128-aligned streams. That is BXW1 §4.5's figure exactly, and it is 3.556×
/// less than [`matmul_f32`] moves. A dequantize-then-`f32`-matmul
/// implementation would move 1.125 bytes to read the weights, then **write**
/// 4 bytes and **read** 4 bytes back per element — 8× the traffic of the `f32`
/// path it was trying to beat. That is why [`Q8Weights::dequantize_into`]
/// exists only as a test reference.
///
/// # Errors
///
/// [`TensorError::ShapeMismatch`] if `shape` disagrees with the weight view's
/// own extents — BXW1 §7.5's rule that disagreeing sources fail closed with no
/// precedence rule — or if a slice length disagrees with `shape`. Nothing is
/// written on any error.
pub fn matmul_q8_0(
    shape: MatMulShape,
    weights: &Q8Weights<'_>,
    x: &[f32],
    y: &mut [f32],
) -> Result<(), TensorError> {
    shape.validate(x.len(), y.len())?;
    if shape.n_in != weights.n_in() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }

    for (out_index, (scale_row, quant_row)) in weights.rows().enumerate() {
        for (x_row, y_row) in x
            .chunks_exact(shape.n_in)
            .zip(y.chunks_exact_mut(shape.n_out))
        {
            let mut acc = 0.0_f32;
            for ((scale_bytes, quant_block), x_block) in scale_row
                .chunks_exact(SCALE_BYTES)
                .zip(quant_row.chunks_exact(Q8_0_BLOCK))
                .zip(x_row.chunks_exact(Q8_0_BLOCK))
            {
                let scale = read_f32_le(scale_bytes).ok_or(TensorError::MalformedPayload)?;
                let mut block_dot = 0.0_f32;
                for (quant, xv) in quant_block.iter().zip(x_block.iter()) {
                    block_dot += f32::from(*quant as i8) * xv;
                }
                acc += scale * block_dot;
            }
            let slot = y_row.get_mut(out_index).ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}
