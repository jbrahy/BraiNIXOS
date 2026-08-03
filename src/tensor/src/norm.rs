//! Root-mean-square layer normalization.
//!
//! ```text
//! out[i] = x[i] × rsqrt(mean(x²) + ε) × weight[i]
//! ```
//!
//! **ε is added to the mean square, inside the root**, not to the root's result
//! and not to the normalized output. BXW1 §5.1 states that convention
//! explicitly, and it does so because the alternatives differ numerically and
//! none of them crashes — the wrong one produces a model that runs and is
//! subtly wrong.

use crate::error::TensorError;
use crate::math::rsqrt;

/// Bit pattern of the smallest positive normal `f32`, `2⁻¹²⁶`.
const F32_MIN_POSITIVE_NORMAL_BITS: u32 = 0x0080_0000;

/// Bit pattern of `f32::MAX`. Anything above it is `+Inf` or NaN.
const F32_MAX_BITS: u32 = 0x7f7f_ffff;

/// Classifies an `f32` as a positive, finite, normal number **by integer
/// comparison on its bit pattern**, before it is ever compared as a float.
///
/// This is BXW1 §4.7's rule, and the reason for it is that comparing an
/// unvalidated float is itself the bug: `NaN < x` and `NaN > x` are both false,
/// so a range check written with float comparisons accepts NaN silently. The
/// rule rejects NaN, ±Inf, subnormals, negatives, and −0.0 in a single pair of
/// integer comparisons.
///
/// **Published, and re-exported as [`crate::is_positive_normal`].** It is three
/// lines, and three lines is exactly the size at which a consumer reimplements
/// it rather than asking — which is what `brainix_transformer` did while this
/// was private, giving two copies of a rule whose whole value is that every
/// float in the system is classified the same way. One copy is the point.
pub fn is_positive_normal(value: f32) -> bool {
    let bits = value.to_bits();
    (F32_MIN_POSITIVE_NORMAL_BITS..=F32_MAX_BITS).contains(&bits)
}

/// RMSNorm over one or more rows.
///
/// `weight` defines the row width: `x` is treated as
/// `x.len() / weight.len()` consecutive rows, each normalized independently
/// against the same weight vector. Passing a single row is the `n_tokens == 1`
/// case and needs no separate entry point.
///
/// The sum of squares accumulates in `f64`. That is not a micro-optimization in
/// reverse: a `d_model`-wide `f32` accumulation of squares over 4096 or 8192
/// terms loses several digits before the reciprocal square root ever sees it,
/// and RMSNorm runs twice per layer over a single vector — it is nowhere near
/// the bandwidth-bound path, so the wider accumulator is free.
///
/// # Errors
///
/// - [`TensorError::ZeroDimension`] if `weight` or `x` is empty.
/// - [`TensorError::ShapeMismatch`] if `out.len() != x.len()`, or if `x.len()`
///   is not a whole multiple of `weight.len()`.
/// - [`TensorError::InvalidEpsilon`] if `eps` is not a positive finite normal
///   `f32`.
/// - [`TensorError::NonFiniteInput`] if a row's mean square is not finite —
///   which is how a NaN or infinite activation is caught, since it is exactly
///   the value the reciprocal square root's domain depends on.
///
/// Nothing is written on any error: every check above completes before the
/// first output element, and the per-row mean square is computed for all rows
/// in a first pass so that a bad row later in the batch does not leave earlier
/// rows written.
pub fn rmsnorm(x: &[f32], weight: &[f32], eps: f32, out: &mut [f32]) -> Result<(), TensorError> {
    let width = weight.len();
    if width == 0 || x.is_empty() {
        return Err(TensorError::ZeroDimension);
    }
    if out.len() != x.len() || !x.len().is_multiple_of(width) {
        return Err(TensorError::ShapeMismatch);
    }
    if !is_positive_normal(eps) {
        return Err(TensorError::InvalidEpsilon);
    }

    // Pass one: validate every row's mean square, so a non-finite activation in
    // the last row cannot leave the first rows written.
    for row in x.chunks_exact(width) {
        if !row_scale(row, width, eps).is_finite() {
            return Err(TensorError::NonFiniteInput);
        }
    }

    // Pass two: write. Nothing here can fail.
    for (row, out_row) in x.chunks_exact(width).zip(out.chunks_exact_mut(width)) {
        let scale = row_scale(row, width, eps);
        for ((xv, w), slot) in row.iter().zip(weight.iter()).zip(out_row.iter_mut()) {
            *slot = xv * scale * w;
        }
    }
    Ok(())
}

/// `rsqrt(mean(row²) + ε)` as an `f32`, or a non-finite value if the row is.
///
/// Split out so the validation pass and the writing pass cannot drift apart.
fn row_scale(row: &[f32], width: usize, eps: f32) -> f32 {
    let mut sum_squares = 0.0_f64;
    for value in row {
        let v = f64::from(*value);
        sum_squares += v * v;
    }
    let mean_square = sum_squares / (width as f64);
    let denominator = mean_square + f64::from(eps);
    if !(denominator.is_finite() && denominator > 0.0) {
        return f32::NAN;
    }
    rsqrt(denominator) as f32
}
