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
//! a guess.
//!
//! # Measured, 2026-08-17: this kernel is compute-bound, not bandwidth-bound
//!
//! The paragraph above used to end by citing NORTH_STAR's claim that the wins
//! are in bytes moved rather than instructions issued. **On this kernel that is
//! not yet true, and the benchmark says so.** `benches/matmul.rs` reports
//! weight-byte throughput against the machine's memory bandwidth:
//!
//! | | before | after lane split |
//! | --- | --- | --- |
//! | `4096x4096`, 1 token | 2.64 GB/s | **6.03 GB/s** |
//! | fraction of a 200 GB/s bus | 1.3% | 3.0% |
//!
//! The discriminating measurement is the 8-token row, which needs no vendor
//! bandwidth figure to interpret: weight bytes per call are identical at 1 and 8
//! tokens because the loop order above reads each row once, while the arithmetic
//! is 8x. Time came out **103% linear in tokens**. Time tracks arithmetic, not
//! bytes.
//!
//! So the loop order documented above is doing its job — weights really are read
//! once — and it is the inner arithmetic underneath it that is the constraint.
//! Tiling, which addresses byte traffic, is therefore **still not the next
//! thing**; it becomes worth measuring once the arithmetic stops dominating.
//!
//! What remains between here and the bus, in order of expected effect:
//!
//! 1. **`SDOT`**, which does 16 `i8` multiply-accumulates in one instruction and
//!    needs no conversion at all — but requires the *activations* to be `i8`
//!    too, which is an algorithm and format change rather than a kernel tweak.
//! 2. **NEON intrinsics** for the current `i8`x`f32` shape, which would need
//!    `unsafe` and so a change to this crate's `#![forbid(unsafe_code)]`.
//! 3. **Multiple cores**, which multiplies whatever a single core achieves.

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

/// Lanes the block dot product accumulates in parallel.
///
/// Four is one 128-bit NEON register of `f32`, which is what the target's
/// vector unit is. It is a source-level constant rather than a target feature
/// because nothing here is architecture-specific: on a machine without SIMD the
/// four accumulators are four registers and the code is still correct.
///
/// **Measured, not assumed.** 4, 8 and 16 lanes were benchmarked on
/// `aarch64-apple-darwin`: 5.96, 5.17 and 5.76 GB/s respectively. The width
/// barely matters, which is itself the finding — the remaining cost is not lane
/// occupancy but the per-element `i8`→`f32` conversion chain (`sxtl`, `sxtl`,
/// `scvtf`) that stands between a quantized weight and an `f32` multiply. Going
/// wider cannot remove work that is per-element by construction. See the module
/// note on what *would*.
const DOT_LANES: usize = 4;

/// Dot product of one `Q8_0` block against `Q8_0_BLOCK` activations.
///
/// # Why the accumulator is split into lanes
///
/// This function exists because of a measurement. Written as the obvious
/// single-accumulator loop —
///
/// ```text
/// let mut dot = 0.0;
/// for (q, x) in quant.iter().zip(activations) { dot += f32::from(*q as i8) * x; }
/// ```
///
/// — it compiled to **six scalar instructions per weight byte** on aarch64:
/// a one-byte load, two widenings, a convert, a multiply and an add, using
/// vector *registers* but only their lowest lane. Measured 2.64 GB/s, which is
/// 1.3% of the reference machine's memory bandwidth.
///
/// The cause is the last of those instructions. `dot += ...` is a **serial
/// dependency chain**: every add waits for the previous one, and since floating
/// point addition is not associative the compiler is *forbidden* from splitting
/// the sum into independent partial sums. It was not failing to vectorize; it
/// was not permitted to.
///
/// Writing the lanes out gives that permission explicitly. The reassociation is
/// then a choice made in the source, where it is visible and documented, rather
/// than something a compiler flag does silently to every float expression in the
/// crate — which is why this is preferable to `-ffast-math` even where that is
/// available.
///
/// # Numerics
///
/// The result is **not** bit-identical to the single-accumulator form, and
/// cannot be: summing in a different order rounds differently. It is not worse.
/// Four partial sums of eight terms each, combined pairwise, has a shorter
/// dependency chain than one sum of thirty-two, so the worst-case accumulated
/// rounding error is *smaller* than the serial form's. The `Q8_0` inputs are
/// exact small integers scaled by one binary32, so the products are exact and
/// only the additions round at all.
fn block_dot(quant_block: &[u8], x_block: &[f32]) -> f32 {
    let mut lanes = [0.0_f32; DOT_LANES];
    // Four independent accumulator updates with no loop-carried dependency
    // between them, which is the whole point of the function -- stated by
    // destructuring rather than by a runtime index whose bound check had to be
    // excused. `as_chunks` gives `[_; DOT_LANES]` on both sides, so the lanes
    // come out by name and the constant subscripts below are the same ones the
    // reduction already uses.
    let (quant_lanes, _) = quant_block.as_chunks::<DOT_LANES>();
    let (activation_lanes, _) = x_block.as_chunks::<DOT_LANES>();
    for (quant_lane, activation_lane) in quant_lanes.iter().zip(activation_lanes) {
        let [q0, q1, q2, q3] = *quant_lane;
        let [a0, a1, a2, a3] = *activation_lane;
        lanes[0] += f32::from(q0 as i8) * a0;
        lanes[1] += f32::from(q1 as i8) * a1;
        lanes[2] += f32::from(q2 as i8) * a2;
        lanes[3] += f32::from(q3 as i8) * a3;
    }
    // Pairwise, not left-to-right: one fewer step in the dependency chain, and
    // it mirrors how the lanes were accumulated. Written out for the measured
    // best width rather than as a loop over `DOT_LANES` -- the sweep that chose
    // 4 is recorded above, and a generic reduction for a constant that is not
    // going to change is complexity with no reader.
    (lanes[0] + lanes[1]) + (lanes[2] + lanes[3])
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
                acc += scale * block_dot(quant_block, x_block);
            }
            let slot = y_row.get_mut(out_index).ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// Dot product of two `Q8_0` blocks, in `i32`.
///
/// # Why this is the fast path
///
/// [`block_dot`] converts each `i8` weight to `f32` before multiplying, which
/// costs a widen, a widen and a convert **per element** and is what
/// `benches/matmul.rs` measured as the remaining constraint after the
/// accumulator was split into lanes. When *both* sides are `i8` no conversion is
/// needed at all: aarch64's `SDOT` performs sixteen `i8` multiply-accumulates
/// into four `i32` lanes in one instruction.
///
/// Written in exactly the lane shape `SDOT` wants, and **verified to produce it**
/// -- compiling this to aarch64 emits `ldp q0, q1 / ldp q2, q3 / sdot / sdot /
/// addv`, six instructions for a thirty-two element block against roughly a
/// hundred and ninety for the `f32` form. No intrinsics, no `unsafe`, and no
/// target feature flag: `dotprod` is already in the default CPU for the targets
/// this project builds.
///
/// Accumulating in `i32` is exact. Thirty-two products of two `i8` values reach
/// at most `32 x 127 x 127 = 516,128`, so nothing rounds and nothing overflows.
///
/// # No `#[inline(always)]`, and that is measured rather than assumed
///
/// This has four callers, and the four-caller case is exactly what cost
/// `unpack_block` 5x until it was forced inline (see `matmul_q4_0_q8a_rows`).
/// The same fix was tried here on 2026-08-19 and does nothing: interleaved
/// best-of-four, end to end, across seven configurations gave 1.04, 1.01,
/// 0.86, 0.95, 1.08, 1.06 and 1.02 -- scattered around 1.0 and inside the
/// noise band, with the per-kernel bench disagreeing with itself by 1.8x
/// between runs on the same binary.
///
/// The difference between the two helpers is worth keeping: `unpack_block`
/// writes a 32-byte buffer the caller then reads, so it only pays off when
/// specialised into the caller's loop, and the cost model stopped doing that
/// at two callers. This one returns a scalar and is already being inlined --
/// there is nothing for the attribute to buy.
fn block_dot_i8(quant_block: &[u8], x_block: &[u8]) -> i32 {
    let mut lanes = [0i32; DOT_LANES];
    // `as_chunks` yields `[u8; DOT_LANES]`, so each lane comes out of a
    // destructuring bind rather than a runtime index. That removes the `get_mut`
    // whose `None` arm no input could reach, and it states the four independent
    // accumulator updates that were the point of indexing in the first place --
    // the constant subscripts below are the same ones the reduction already
    // uses, and a constant subscript on a fixed array is not a panic path.
    let (weight_lanes, _) = quant_block.as_chunks::<DOT_LANES>();
    let (activation_lanes, _) = x_block.as_chunks::<DOT_LANES>();
    for (weight_lane, activation_lane) in weight_lanes.iter().zip(activation_lanes) {
        let [w0, w1, w2, w3] = *weight_lane;
        let [a0, a1, a2, a3] = *activation_lane;
        lanes[0] = lanes[0].saturating_add(i32::from(w0 as i8).saturating_mul(i32::from(a0 as i8)));
        lanes[1] = lanes[1].saturating_add(i32::from(w1 as i8).saturating_mul(i32::from(a1 as i8)));
        lanes[2] = lanes[2].saturating_add(i32::from(w2 as i8).saturating_mul(i32::from(a2 as i8)));
        lanes[3] = lanes[3].saturating_add(i32::from(w3 as i8).saturating_mul(i32::from(a3 as i8)));
    }
    (lanes[0].saturating_add(lanes[1])).saturating_add(lanes[2].saturating_add(lanes[3]))
}

/// Quantizes `f32` activations into the `Q8_0` layout, in place in `scratch`.
///
/// The output is byte-for-byte a `Q8_0` payload of shape `[n_tokens, n_in]`, so
/// [`Q8Weights`] views it without a second format. Sizing comes from
/// [`Q8Weights::derived_payload_len`], and the caller owns the buffer because
/// this crate allocates nothing.
///
/// # The scale
///
/// Per 32-element block, `absmax / 127`, matching how the weights themselves
/// were quantized. A block whose values are all zero, or whose scale would be
/// subnormal, emits a zero scale and zero quants -- the same rule BXW1 §4.2
/// applies to weights, and for the same reason: a subnormal scale multiplies
/// into noise.
///
/// # Errors
///
/// [`TensorError::ShapeMismatch`] if `x` or `scratch` disagrees with the shape.
pub fn quantize_activations(
    n_tokens: usize,
    n_in: usize,
    x: &[f32],
    scratch: &mut [u8],
) -> Result<(), TensorError> {
    let required_x = n_tokens
        .checked_mul(n_in)
        .ok_or(TensorError::DimensionOverflow)?;
    if x.len() != required_x {
        return Err(TensorError::ShapeMismatch);
    }
    let required_scratch = Q8Weights::derived_payload_len(n_tokens, n_in)?;
    if scratch.len() != required_scratch {
        return Err(TensorError::ShapeMismatch);
    }

    let blocks_total = n_tokens
        .checked_mul(n_in / Q8_0_BLOCK)
        .ok_or(TensorError::DimensionOverflow)?;
    let scale_bytes = blocks_total
        .checked_mul(SCALE_BYTES)
        .ok_or(TensorError::DimensionOverflow)?;
    // The quant plane begins where the padded scale plane ends; the payload
    // length derivation above already accounts for that padding.
    let quant_start = required_scratch
        .checked_sub(
            blocks_total
                .checked_mul(Q8_0_BLOCK)
                .ok_or(TensorError::DimensionOverflow)?,
        )
        .ok_or(TensorError::ShapeMismatch)?;
    let (scale_plane, quant_plane) = scratch.split_at_mut(quant_start);

    for (index, block) in x.chunks_exact(Q8_0_BLOCK).enumerate() {
        quantize_one_block(index, block, scale_plane, quant_plane)?;
    }
    let _ = scale_bytes;
    Ok(())
}

/// Quantizes one `Q8_0` block of activations into the two planes.
///
/// Split out of [`quantize_activations`] rather than inlined, because the outer
/// function is otherwise shape validation and plane arithmetic wrapped around a
/// numeric kernel, and the two read as one thing only to whoever just wrote
/// them. Clippy's cognitive-complexity gate is what said so out loud.
///
/// # Errors
///
/// [`TensorError::ShapeMismatch`] if either plane is too short for `index`,
/// [`TensorError::DimensionOverflow`] if the offsets do not fit.
fn quantize_one_block(
    index: usize,
    block: &[f32],
    scale_plane: &mut [u8],
    quant_plane: &mut [u8],
) -> Result<(), TensorError> {
    let mut peak = 0.0_f32;
    for value in block {
        let magnitude = if *value < 0.0 { -*value } else { *value };
        if magnitude > peak {
            peak = magnitude;
        }
    }
    let scale = peak / 127.0;
    let usable = peak > 0.0 && scale >= f32::MIN_POSITIVE;
    let scale_at = index
        .checked_mul(SCALE_BYTES)
        .ok_or(TensorError::DimensionOverflow)?;
    let quant_at = index
        .checked_mul(Q8_0_BLOCK)
        .ok_or(TensorError::DimensionOverflow)?;

    let emitted = if usable { scale } else { 0.0 };
    // The planes were split from a payload whose length `quantize_activations`
    // already checked against `Q8Weights::derived_payload_len`, and `scale_at`
    // is derived from the same block count, so this range is always in bounds.
    let Some(scale_slot) = scale_plane.get_mut(scale_at..scale_at.saturating_add(SCALE_BYTES))
    else {
        // COVERAGE-EXEMPT: unreachable behind the entry check one frame up.
        // Defence in depth: reaching it needs a caller that bypassed those
        // checks, which is exactly the refactor this guard is here to survive.
        return Err(TensorError::ShapeMismatch);
    };
    scale_slot.copy_from_slice(&emitted.to_le_bytes());

    // COVERAGE-EXEMPT: as the scale plane above -- same derivation, same
    // already-validated payload length.
    let Some(quant_slot) = quant_plane.get_mut(quant_at..quant_at.saturating_add(Q8_0_BLOCK))
    else {
        return Err(TensorError::ShapeMismatch);
    };
    for (slot, value) in quant_slot.iter_mut().zip(block.iter()) {
        *slot = if usable {
            // Round to nearest; the reciprocal is not used because
            // `peak / 127` then `value / scale` keeps the endpoints exact.
            //
            // The divide is not the cost it looks like. Measured 2026-08-19
            // against a per-block reciprocal multiply: 1.03x to 1.09x, with an
            // A-vs-A control in the same binary reading 0.98x to 1.03x. This
            // loop already runs at ~1500 M elem/s, so quantizing every
            // activation a decode needs costs about 0.76 ms/token at the
            // reference shape -- 1% of a decode, against `softmax`'s 12%.
            // Trading the exact endpoints for 5% of 1% is not a trade.
            let scaled = *value / scale;
            let rounded = if scaled >= 0.0 {
                scaled + 0.5
            } else {
                scaled - 0.5
            } as i32;
            rounded.clamp(-127, 127) as i8 as u8
        } else {
            0
        };
    }
    Ok(())
}

/// `y = W xᵀ` with `Q8_0` weights **and** `Q8_0` activations.
///
/// The activation payload comes from [`quantize_activations`]. Both operands
/// being `i8` is what lets the inner loop reach `SDOT`; see [`block_dot_i8`].
///
/// # Errors
///
/// As [`matmul_q8_0`], plus [`TensorError::ShapeMismatch`] if the activation
/// view disagrees with `shape`.
pub fn matmul_q8_0_q8a(
    shape: MatMulShape,
    weights: &Q8Weights<'_>,
    activations: &Q8Weights<'_>,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if shape.n_tokens == 0 || shape.n_in == 0 || shape.n_out == 0 {
        return Err(TensorError::ZeroDimension);
    }
    let required_y = shape
        .n_tokens
        .checked_mul(shape.n_out)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != weights.n_in() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != activations.n_in() || shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }

    for (out_index, (weight_scales, weight_quants)) in weights.rows().enumerate() {
        for (token_index, (x_scales, x_quants)) in activations.rows().enumerate() {
            // Two blocks per iteration: same kernel, half the loop overhead.
            //
            // **Worth 1.30x here, and measured to help nowhere else.** The same
            // unroll on `matmul_q8_0` (f32 activations) is consistently SLOWER
            // -- 5.76 to 5.11 GB/s across three interleaved rounds -- and on
            // `matmul_q4_0_q8a` it does nothing, 21.31 against 21.11.
            //
            // The reason is the ratio between the per-block body and the
            // per-block overhead. This kernel does two `sdot`s per block, so
            // the scale reads, bounds checks and loop arithmetic around them
            // are a large fraction of the work and halving them shows.
            // `block_dot` widens and converts every element; `unpack_block`
            // un-nibbles a whole block. In those two the body dwarfs the
            // overhead and there is nothing to amortize, so unrolling only
            // costs registers.
            //
            // Do not "finish the job" by unrolling the other two. It was tried.
            let mut acc = 0.0_f32;
            let mut wsp = weight_scales.chunks_exact(SCALE_BYTES * 2);
            let mut wqp = weight_quants.chunks_exact(Q8_0_BLOCK * 2);
            let mut xsp = x_scales.chunks_exact(SCALE_BYTES * 2);
            let mut xqp = x_quants.chunks_exact(Q8_0_BLOCK * 2);
            for (((a, b), c), d) in wsp
                .by_ref()
                .zip(wqp.by_ref())
                .zip(xsp.by_ref())
                .zip(xqp.by_ref())
            {
                let ws0 = read_f32_le(&a[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let xs0 = read_f32_le(&c[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let ws1 = read_f32_le(&a[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let xs1 = read_f32_le(&c[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let d0 = block_dot_i8(&b[..Q8_0_BLOCK], &d[..Q8_0_BLOCK]) as f32;
                let d1 = block_dot_i8(&b[Q8_0_BLOCK..], &d[Q8_0_BLOCK..]) as f32;
                acc += ws0 * xs0 * d0 + ws1 * xs1 * d1;
            }
            for (((weight_scale, weight_block), x_scale), x_block) in wsp
                .remainder()
                .chunks_exact(SCALE_BYTES)
                .zip(wqp.remainder().chunks_exact(Q8_0_BLOCK))
                .zip(xsp.remainder().chunks_exact(SCALE_BYTES))
                .zip(xqp.remainder().chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                acc += ws * xs * block_dot_i8(weight_block, x_block) as f32;
            }
            let row_start = token_index
                .checked_mul(shape.n_out)
                .ok_or(TensorError::DimensionOverflow)?;
            let slot = y
                .get_mut(row_start.saturating_add(out_index))
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` over a **contiguous range of output rows**, for one worker of a
/// parallel decomposition.
///
/// # Why the split is over output rows
///
/// Each output row is an independent dot product against the same activations.
/// Splitting there needs no reduction, no synchronization and no shared mutable
/// state: worker `k` reads all of `x`, its own slice of the weights, and writes
/// its own slice of `y`. The activations are re-read by every worker, which is
/// exactly the trade the weights-outer loop order already makes for tokens --
/// they are small and cache-resident, and the weights are the DRAM stream.
///
/// # Measured, and why the caller should not spawn one worker per core
///
/// On `aarch64-apple-darwin`, six threads streaming a 151 MB matrix reach
/// 108 GB/s against 26.6 for one -- **4.1x from six cores, not 6x** -- and
/// eight threads are *slower* than six. The bus saturates. A caller that sizes
/// its worker pool from the core count rather than from a measurement will pay
/// for contention it cannot use.
///
/// # `n_tokens` and the output layout
///
/// `y` holds this worker's rows only, as `[n_tokens, row_count]` row-major. For
/// single-stream decode (`n_tokens == 1`) that makes the full output splittable
/// with `chunks_mut`, so the disjointness is checked by the borrow checker
/// rather than argued for in a comment.
///
/// # Errors
///
/// As [`matmul_q8_0_q8a`], plus [`TensorError::ShapeMismatch`] if the row range
/// runs past the weight matrix or `y` is not sized for it.
pub fn matmul_q8_0_q8a_rows(
    shape: MatMulShape,
    weights: &Q8Weights<'_>,
    activations: &Q8Weights<'_>,
    row_start: usize,
    row_count: usize,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if shape.n_tokens == 0 || shape.n_in == 0 || row_count == 0 {
        return Err(TensorError::ZeroDimension);
    }
    let row_end = row_start
        .checked_add(row_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if row_end > weights.n_out() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != weights.n_in() || shape.n_in != activations.n_in() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    let required_y = shape
        .n_tokens
        .checked_mul(row_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }

    for (local_index, (weight_scales, weight_quants)) in
        weights.rows().skip(row_start).take(row_count).enumerate()
    {
        for (token_index, (x_scales, x_quants)) in activations.rows().enumerate() {
            // Two blocks per iteration, identical to `matmul_q8_0_q8a`.
            //
            // It has to be identical, not merely equivalent: the two kernels
            // are required to agree BIT FOR BIT, and
            // `splitting_the_output_rows_reproduces_the_whole` asserts it with
            // `assert_eq!`. Unrolling only one of them changes the association
            // of one f32 sum and that test fails immediately -- which is
            // exactly what it is for, and what caught this.
            let mut acc = 0.0_f32;
            let mut wsp = weight_scales.chunks_exact(SCALE_BYTES * 2);
            let mut wqp = weight_quants.chunks_exact(Q8_0_BLOCK * 2);
            let mut xsp = x_scales.chunks_exact(SCALE_BYTES * 2);
            let mut xqp = x_quants.chunks_exact(Q8_0_BLOCK * 2);
            for (((a, b), c), d) in wsp
                .by_ref()
                .zip(wqp.by_ref())
                .zip(xsp.by_ref())
                .zip(xqp.by_ref())
            {
                let ws0 = read_f32_le(&a[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let xs0 = read_f32_le(&c[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let ws1 = read_f32_le(&a[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let xs1 = read_f32_le(&c[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let d0 = block_dot_i8(&b[..Q8_0_BLOCK], &d[..Q8_0_BLOCK]) as f32;
                let d1 = block_dot_i8(&b[Q8_0_BLOCK..], &d[Q8_0_BLOCK..]) as f32;
                acc += ws0 * xs0 * d0 + ws1 * xs1 * d1;
            }
            for (((weight_scale, weight_block), x_scale), x_block) in wsp
                .remainder()
                .chunks_exact(SCALE_BYTES)
                .zip(wqp.remainder().chunks_exact(Q8_0_BLOCK))
                .zip(xsp.remainder().chunks_exact(SCALE_BYTES))
                .zip(xqp.remainder().chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                acc += ws * xs * block_dot_i8(weight_block, x_block) as f32;
            }
            let slot = y
                .get_mut(
                    token_index
                        .checked_mul(row_count)
                        .ok_or(TensorError::DimensionOverflow)?
                        .checked_add(local_index)
                        .ok_or(TensorError::DimensionOverflow)?,
                )
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` for the tokens `token_start .. token_start + token_count`.
///
/// The prefill counterpart of [`matmul_q8_0_q8a_rows`]. That one splits the
/// output rows because at one token it must: six workers each streaming the
/// whole weight set would need about three times the bus. This one splits the
/// tokens, which is only affordable once there is more than one.
///
/// # Why splitting tokens is the right axis for prefill
///
/// Measured 2026-08-20 at 4096x4096, weight-byte throughput, and what six
/// workers would each need:
///
/// | tokens | GB/s | x6 | % of a ~120 GB/s bus |
/// | --- | --- | --- | --- |
/// | 1 | 59.81 | 358.9 | 299% |
/// | 8 | 5.85 | 35.1 | 29% |
/// | 128 | 0.48 | 2.9 | 2% |
///
/// Weight bytes are constant down that column: the loop is weights-outer and
/// the traffic is amortized. What scales is the arithmetic, so past one token
/// the kernel is compute-bound, and duplicating the weight stream per worker is
/// cheap in exactly the regime where dividing the arithmetic is valuable.
///
/// # Why the output range is contiguous
///
/// Token `t` owns `y[t * n_out .. (t + 1) * n_out]`, so a range of tokens is a
/// range of `y` and `for_each_chunk` expresses it with a width of
/// `tokens_per_worker * n_out`. No strided dispatch primitive is required. The
/// row split needs one, which is why it does not have one.
///
/// # Errors
///
/// [`TensorError::ZeroDimension`], [`TensorError::ShapeMismatch`],
/// [`TensorError::DimensionOverflow`] or [`TensorError::MalformedPayload`].
pub fn matmul_q8_0_q8a_tokens(
    shape: MatMulShape,
    weights: &Q8Weights<'_>,
    activations: &Q8Weights<'_>,
    token_start: usize,
    token_count: usize,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if token_count == 0 || shape.n_in == 0 || shape.n_out == 0 {
        return Err(TensorError::ZeroDimension);
    }
    let token_end = token_start
        .checked_add(token_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if token_end > shape.n_tokens || shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != weights.n_in() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != activations.n_in() {
        return Err(TensorError::ShapeMismatch);
    }
    let required_y = token_count
        .checked_mul(shape.n_out)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }

    for (out_index, (weight_scales, weight_quants)) in weights.rows().enumerate() {
        for (local_token, (x_scales, x_quants)) in activations
            .rows()
            .skip(token_start)
            .take(token_count)
            .enumerate()
        {
            // Byte for byte the body of `matmul_q8_0_q8a`, for the same reason
            // `matmul_q8_0_q8a_rows` carries a copy of it: the split is
            // required to reproduce the whole BIT FOR BIT, and changing the
            // association of one f32 sum here breaks that. Asserted by
            // `splitting_the_tokens_reproduces_the_whole`.
            let mut acc = 0.0_f32;
            let mut wsp = weight_scales.chunks_exact(SCALE_BYTES * 2);
            let mut wqp = weight_quants.chunks_exact(Q8_0_BLOCK * 2);
            let mut xsp = x_scales.chunks_exact(SCALE_BYTES * 2);
            let mut xqp = x_quants.chunks_exact(Q8_0_BLOCK * 2);
            for (((a, b), c), d) in wsp
                .by_ref()
                .zip(wqp.by_ref())
                .zip(xsp.by_ref())
                .zip(xqp.by_ref())
            {
                let ws0 = read_f32_le(&a[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let xs0 = read_f32_le(&c[..SCALE_BYTES]).ok_or(TensorError::MalformedPayload)?;
                let ws1 = read_f32_le(&a[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let xs1 = read_f32_le(&c[SCALE_BYTES..]).ok_or(TensorError::MalformedPayload)?;
                let d0 = block_dot_i8(&b[..Q8_0_BLOCK], &d[..Q8_0_BLOCK]) as f32;
                let d1 = block_dot_i8(&b[Q8_0_BLOCK..], &d[Q8_0_BLOCK..]) as f32;
                acc += ws0 * xs0 * d0 + ws1 * xs1 * d1;
            }
            for (((weight_scale, weight_block), x_scale), x_block) in wsp
                .remainder()
                .chunks_exact(SCALE_BYTES)
                .zip(wqp.remainder().chunks_exact(Q8_0_BLOCK))
                .zip(xsp.remainder().chunks_exact(SCALE_BYTES))
                .zip(xqp.remainder().chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                acc += ws * xs * block_dot_i8(weight_block, x_block) as f32;
            }
            let slot = y
                .get_mut(
                    local_token
                        .checked_mul(shape.n_out)
                        .ok_or(TensorError::DimensionOverflow)?
                        .checked_add(out_index)
                        .ok_or(TensorError::DimensionOverflow)?,
                )
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` for the output rows `row_start .. row_start + row_count`.
///
/// The `Q4_0` counterpart of [`matmul_q8_0_q8a_rows`], and the reason `Q4_0`
/// can be worth anything on this machine at all.
///
/// # Why this had to exist before `Q4_0` could be judged
///
/// `Q4_0` moves 1.80x fewer bytes than `Q8_0` and pays for it in arithmetic:
/// every nibble is unpacked to an `i8` before `SDOT` can touch it. That trade
/// wins only when the caller is short of bandwidth rather than short of
/// compute.
///
/// Without this function it could never be short of bandwidth. The dispatcher
/// splits a projection by output rows, so a kernel with no row-split form runs
/// on the calling core however many workers are idle — which pins `Q4_0` in
/// the compute-bound regime, exactly where its own module note says it loses.
/// Measured before this existed: **0.82x of `Q8_0` on one core and 0.78x
/// pooled**, on a model that had shrunk from 172.5 MB to 103.0 MB.
///
/// # Bit-for-bit with the whole-output form
///
/// Same requirement as the `Q8_0` pair, for the same reason: the split and
/// unsplit paths must agree exactly, so `splitting_the_q4_output_rows_
/// reproduces_the_whole` compares with `assert_eq!` rather than a tolerance.
/// The inner loop below is therefore a copy of [`matmul_q4_0_q8a`]'s and must
/// stay one — changing the association of a single `f32` sum in one and not
/// the other breaks that test, which is what it is for.
///
/// # Errors
///
/// [`TensorError::ZeroDimension`], [`TensorError::ShapeMismatch`] if the row
/// range leaves the weight matrix or `y` is not `n_tokens × row_count`, or
/// [`TensorError::DimensionOverflow`].
pub fn matmul_q4_0_q8a_rows(
    shape: MatMulShape,
    weights: &crate::q4::Q4Weights<'_>,
    activations: &Q8Weights<'_>,
    row_start: usize,
    row_count: usize,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if shape.n_tokens == 0 || shape.n_in == 0 || row_count == 0 {
        return Err(TensorError::ZeroDimension);
    }
    let row_end = row_start
        .checked_add(row_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if row_end > weights.n_out() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != weights.n_in() || shape.n_in != activations.n_in() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    let required_y = shape
        .n_tokens
        .checked_mul(row_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }

    let mut unpacked = [0u8; Q8_0_BLOCK];
    for (local_index, (weight_scales, weight_packed)) in
        weights.rows().skip(row_start).take(row_count).enumerate()
    {
        for (token_index, (x_scales, x_quants)) in activations.rows().enumerate() {
            let mut acc = 0.0_f32;
            for (((weight_scale, packed_block), x_scale), x_block) in weight_scales
                .chunks_exact(SCALE_BYTES)
                .zip(weight_packed.chunks_exact(Q8_0_BLOCK / 2))
                .zip(x_scales.chunks_exact(SCALE_BYTES))
                .zip(x_quants.chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                crate::q4::unpack_block(packed_block, &mut unpacked);
                acc += ws * xs * block_dot_i8(&unpacked, x_block) as f32;
            }
            let slot = y
                .get_mut(
                    token_index
                        .checked_mul(row_count)
                        .ok_or(TensorError::DimensionOverflow)?
                        .checked_add(local_index)
                        .ok_or(TensorError::DimensionOverflow)?,
                )
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` with `Q4_0` weights over the tokens `token_start .. token_start + token_count`.
///
/// The `Q4_0` counterpart of [`matmul_q8_0_q8a_tokens`], and it exists for the
/// same reason: past one token this kernel is compute-bound, so dividing the
/// arithmetic across workers pays even though each worker streams its own copy
/// of the weight set.
///
/// `Q4_0` moves 0.625 bytes per element against `Q8_0`'s 1.125, so the traffic
/// a token split duplicates is 1.8x smaller here. The headroom argument is
/// therefore strictly easier to satisfy than the one measured for `Q8_0`, where
/// six workers over 32 tokens needed 39.1 GB/s of a ~120 GB/s ceiling.
///
/// # Errors
///
/// [`TensorError::ZeroDimension`], [`TensorError::ShapeMismatch`],
/// [`TensorError::DimensionOverflow`] or [`TensorError::MalformedPayload`].
pub fn matmul_q4_0_q8a_tokens(
    shape: MatMulShape,
    weights: &crate::q4::Q4Weights<'_>,
    activations: &Q8Weights<'_>,
    token_start: usize,
    token_count: usize,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if token_count == 0 || shape.n_in == 0 || shape.n_out == 0 {
        return Err(TensorError::ZeroDimension);
    }
    let token_end = token_start
        .checked_add(token_count)
        .ok_or(TensorError::DimensionOverflow)?;
    if token_end > shape.n_tokens || shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != weights.n_in() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != activations.n_in() {
        return Err(TensorError::ShapeMismatch);
    }
    let required_y = token_count
        .checked_mul(shape.n_out)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }

    let mut unpacked = [0u8; Q8_0_BLOCK];
    for (out_index, (weight_scales, weight_packed)) in weights.rows().enumerate() {
        for (local_token, (x_scales, x_quants)) in activations
            .rows()
            .skip(token_start)
            .take(token_count)
            .enumerate()
        {
            // Byte for byte the body of `matmul_q4_0_q8a`, for the reason the
            // `Q8_0` kernels carry copies of each other: the split must
            // reproduce the whole BIT FOR BIT. Asserted by
            // `splitting_the_q4_tokens_reproduces_the_whole`.
            let mut acc = 0.0_f32;
            for (((weight_scale, packed_block), x_scale), x_block) in weight_scales
                .chunks_exact(SCALE_BYTES)
                .zip(weight_packed.chunks_exact(Q8_0_BLOCK / 2))
                .zip(x_scales.chunks_exact(SCALE_BYTES))
                .zip(x_quants.chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                crate::q4::unpack_block(packed_block, &mut unpacked);
                acc += ws * xs * block_dot_i8(&unpacked, x_block) as f32;
            }
            let slot = y
                .get_mut(
                    local_token
                        .checked_mul(shape.n_out)
                        .ok_or(TensorError::DimensionOverflow)?
                        .checked_add(out_index)
                        .ok_or(TensorError::DimensionOverflow)?,
                )
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}

/// `y = W xᵀ` with `Q4_0` weights and `Q8_0` activations.
///
/// Each 16-byte weight block is unpacked to 32 signed bytes and then fed to the
/// same [`block_dot_i8`] the `Q8_0` path uses, so the two kernels differ by
/// exactly one step: the unpack. That is deliberate -- it makes the benchmark a
/// measurement of the unpack rather than of two unrelated implementations.
///
/// # Errors
///
/// As [`matmul_q8_0_q8a`].
pub fn matmul_q4_0_q8a(
    shape: MatMulShape,
    weights: &crate::q4::Q4Weights<'_>,
    activations: &Q8Weights<'_>,
    y: &mut [f32],
) -> Result<(), TensorError> {
    if shape.n_tokens == 0 || shape.n_in == 0 || shape.n_out == 0 {
        return Err(TensorError::ZeroDimension);
    }
    if shape.n_in != weights.n_in() || shape.n_out != weights.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    if shape.n_in != activations.n_in() || shape.n_tokens != activations.n_out() {
        return Err(TensorError::ShapeMismatch);
    }
    let required_y = shape
        .n_tokens
        .checked_mul(shape.n_out)
        .ok_or(TensorError::DimensionOverflow)?;
    if y.len() != required_y {
        return Err(TensorError::ShapeMismatch);
    }

    let mut unpacked = [0u8; Q8_0_BLOCK];
    for (out_index, (weight_scales, weight_packed)) in weights.rows().enumerate() {
        for (token_index, (x_scales, x_quants)) in activations.rows().enumerate() {
            let mut acc = 0.0_f32;
            for (((weight_scale, packed_block), x_scale), x_block) in weight_scales
                .chunks_exact(SCALE_BYTES)
                .zip(weight_packed.chunks_exact(Q8_0_BLOCK / 2))
                .zip(x_scales.chunks_exact(SCALE_BYTES))
                .zip(x_quants.chunks_exact(Q8_0_BLOCK))
            {
                let ws = read_f32_le(weight_scale).ok_or(TensorError::MalformedPayload)?;
                let xs = read_f32_le(x_scale).ok_or(TensorError::MalformedPayload)?;
                crate::q4::unpack_block(packed_block, &mut unpacked);
                acc += ws * xs * block_dot_i8(&unpacked, x_block) as f32;
            }
            let slot = y
                .get_mut(
                    token_index
                        .checked_mul(shape.n_out)
                        .ok_or(TensorError::DimensionOverflow)?
                        .checked_add(out_index)
                        .ok_or(TensorError::DimensionOverflow)?,
                )
                .ok_or(TensorError::ShapeMismatch)?;
            *slot = acc;
        }
    }
    Ok(())
}
