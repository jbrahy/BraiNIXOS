//! Numerically stable softmax over one row.
//!
//! ```text
//! out[i] = exp(x[i] − max(x)) / Σ_j exp(x[j] − max(x))
//! ```
//!
//! Subtracting the row maximum is the whole point and is not optional. A naive
//! `exp(x[i]) / Σ exp(x[j])` overflows to `Inf/Inf = NaN` for attention scores
//! above about 88, and underflows to `0/0 = NaN` for scores below about −104 —
//! both of which are reachable from an unremarkable model on an unremarkable
//! prompt. With the maximum subtracted, every argument is `≤ 0`, so no term can
//! overflow, and **at least one term is `exp(0) = 1`, so the denominator is
//! always `≥ 1`** and the division is never by zero. That last property is what
//! makes the kernel total rather than merely usually-fine.
//!
//! One row per call. Attention softmaxes one query's scores at a time, and a
//! batched entry point would have to carry a row length that the caller already
//! knows, which is one more thing to get wrong for no saving.

use crate::error::TensorError;
use crate::math::exp_f32;

/// Softmax of `x` into `out`.
///
/// # Errors
///
/// - [`TensorError::ZeroDimension`] if `x` is empty. An empty softmax has no
///   defined value — the denominator would be an empty sum — so it is refused
///   rather than treated as a no-op.
/// - [`TensorError::ShapeMismatch`] if `out.len() != x.len()`.
/// - [`TensorError::NonFiniteInput`] if any element is NaN or ±Inf. This check
///   is load bearing rather than defensive: the algorithm's stability rests on
///   the row maximum, and NaN is unordered so it never becomes the maximum,
///   while `+Inf` makes `x[i] − max` an `Inf − Inf = NaN` for the maximal
///   element itself. Refusing is the only honest option, and it happens on the
///   pass that computes the maximum, so it costs one integer comparison per
///   element and no extra traversal.
///
/// Nothing is written on any error.
pub fn softmax(x: &[f32], out: &mut [f32]) -> Result<(), TensorError> {
    if x.is_empty() {
        return Err(TensorError::ZeroDimension);
    }
    if out.len() != x.len() {
        return Err(TensorError::ShapeMismatch);
    }

    // Pass one: the row maximum, rejecting non-finite input as we go.
    let mut max = f32::NEG_INFINITY;
    for value in x {
        if !value.is_finite() {
            return Err(TensorError::NonFiniteInput);
        }
        if *value > max {
            max = *value;
        }
    }

    // Pass two: exponentiate the shifted values. Every argument is <= 0, so no
    // term overflows; the maximal element contributes exactly exp(0) = 1.
    //
    // The sum accumulates the *rounded* f32 terms, in f64, rather than the f64
    // terms before rounding. Summing what was actually stored is what makes the
    // outputs sum to 1 to within f32 rounding instead of to within f32 rounding
    // plus a systematic bias.
    let mut sum = 0.0_f64;
    let max_wide = f64::from(max);
    for (value, slot) in x.iter().zip(out.iter_mut()) {
        // Widened before the subtraction: `x[i] − max` can overflow f32 when
        // the row spans the whole exponent range, and f64 has the headroom.
        let term = exp_f32(f64::from(*value) - max_wide) as f32;
        *slot = term;
        sum += f64::from(term);
    }

    // sum >= 1 by construction, so this is never a division by zero and the
    // reciprocal is always finite.
    let inverse = (1.0_f64 / sum) as f32;
    for slot in out.iter_mut() {
        *slot *= inverse;
    }
    Ok(())
}
