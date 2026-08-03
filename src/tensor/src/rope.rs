//! Rotary position embedding.
//!
//! For dimension pair `i` of a head, with `θ_i = base^(−2i / rope_dim)` and
//! angle `a = position × θ_i`:
//!
//! ```text
//! out[2i]   = x[2i]·cos(a) − x[2i+1]·sin(a)
//! out[2i+1] = x[2i]·sin(a) + x[2i+1]·cos(a)
//! ```
//!
//! Dimensions `rope_dim .. d_head` are copied through unrotated, which is what
//! `rope_dim ≤ d_head` means (BXW1 §5.1: "leading per-head dimensions RoPE
//! rotates").
//!
//! # The base comes from the model, never from this file
//!
//! `base` is BXW1's `rope_theta`, a header field. BXW1 §5.1 pins its meaning:
//! it *is* the base in `θ_i = rope_theta^(−2i/rope_dim)`, not a precomputed
//! frequency and not an inverse. There is no `10000.0` anywhere in this crate;
//! a model constant compiled into the engine is a model the engine cannot
//! serve.
//!
//! # The pairing convention is an assumption, and it is recorded as one
//!
//! BXW1 §5.1 defines `θ_i` for `i` in `0 .. rope_dim/2` and says RoPE "rotates
//! dimension pairs", but it **never says which two components form pair `i`**.
//! Two conventions are in use and they are not interchangeable:
//!
//! - **interleaved** — pair `i` is `(x[2i], x[2i+1])`, the original paper's and
//!   the LLaMA family's convention;
//! - **half-split** — pair `i` is `(x[i], x[i + rope_dim/2])`, the
//!   GPT-NeoX/HuggingFace convention.
//!
//! This implementation uses **interleaved**. It is the convention that matches
//! BXW1's `arch_id = 1` family and the one under which "leading dimensions"
//! describes a contiguous prefix of *pairs* rather than an interleaving of two
//! halves. **A model converted under the other convention will produce fluent
//! nonsense, not an error**, so this is the assumption most worth stating: it
//! belongs in BXW1 §5.1 and P3-T1 should be amended to pin it.

use crate::error::TensorError;
use crate::math::{powf, sin_cos, MAX_SIN_COS_ARG};
use crate::norm::is_positive_normal;

/// Largest position [`rope`] accepts.
///
/// A stated accuracy bound, not a capacity one. Frequencies are at most `1.0`
/// (at `i == 0`), so the largest angle a position can produce is the position
/// itself, and the sine/cosine argument reduction is exact only below `2²⁰`.
/// Refusing above it is the alternative to returning a quietly wrong rotation.
pub const MAX_ROPE_POSITION: u32 = MAX_SIN_COS_ARG;

/// The hyperparameters of one RoPE application, all of them model-supplied.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RopeParams {
    /// Per-head width. Also the row width of `x`, which is treated as
    /// `x.len() / d_head` consecutive heads.
    pub d_head: usize,
    /// Leading per-head dimensions that are rotated. Even, non-zero, and at
    /// most `d_head` (BXW1 §7.2 rule H17).
    pub rope_dim: usize,
    /// BXW1's `rope_theta`: the **base**, typically `1.0e4`, always read from
    /// the model header.
    pub base: f32,
    /// Absolute token position. `0` is an exact identity.
    pub position: u32,
}

impl RopeParams {
    /// Validates every field against BXW1 §5.1 and §7.2 rule H17.
    fn validate(&self) -> Result<(), TensorError> {
        if self.d_head == 0 {
            return Err(TensorError::ZeroDimension);
        }
        if self.rope_dim == 0 || !self.rope_dim.is_multiple_of(2) || self.rope_dim > self.d_head {
            return Err(TensorError::InvalidRopeDim);
        }
        // Bit-pattern classification first, exactly as BXW1 §4.7 requires, so
        // no float comparison is ever performed against a possible NaN.
        if !is_positive_normal(self.base) || self.base <= 1.0 {
            return Err(TensorError::InvalidTheta);
        }
        if self.position > MAX_ROPE_POSITION {
            return Err(TensorError::PositionTooLarge);
        }
        Ok(())
    }
}

/// Applies RoPE to every head in `x`, writing `out`.
///
/// `x` is `[n_heads, d_head]` row-major, and every head gets the same angles —
/// the position is a property of the token, not of the head. Query and key
/// vectors are rotated by separate calls; the caller knows which is which.
///
/// The angles are computed once per dimension pair and reused across all heads,
/// which is the only reason the head loop is inside the pair loop rather than
/// outside it: `d_head/2` transcendental evaluations per call instead of
/// `n_heads × d_head/2`.
///
/// # Errors
///
/// - [`TensorError::ZeroDimension`] if `d_head` is zero or `x` is empty.
/// - [`TensorError::InvalidRopeDim`] if `rope_dim` is zero, odd, or larger than
///   `d_head`.
/// - [`TensorError::InvalidTheta`] if `base` is not a positive finite normal
///   greater than one.
/// - [`TensorError::PositionTooLarge`] above [`MAX_ROPE_POSITION`].
/// - [`TensorError::ShapeMismatch`] if `out.len() != x.len()` or `x.len()` is
///   not a whole multiple of `d_head`.
///
/// Nothing is written on any error.
pub fn rope(x: &[f32], params: &RopeParams, out: &mut [f32]) -> Result<(), TensorError> {
    params.validate()?;
    if x.is_empty() {
        return Err(TensorError::ZeroDimension);
    }
    if out.len() != x.len() || !x.len().is_multiple_of(params.d_head) {
        return Err(TensorError::ShapeMismatch);
    }

    // Untouched dimensions first: rope_dim..d_head is a straight copy, and
    // doing it up front keeps the rotation loop free of a tail branch.
    for (head_in, head_out) in x
        .chunks_exact(params.d_head)
        .zip(out.chunks_exact_mut(params.d_head))
    {
        let tail_in = head_in
            .get(params.rope_dim..)
            .ok_or(TensorError::ShapeMismatch)?;
        let tail_out = head_out
            .get_mut(params.rope_dim..)
            .ok_or(TensorError::ShapeMismatch)?;
        for (value, slot) in tail_in.iter().zip(tail_out.iter_mut()) {
            *slot = *value;
        }
    }

    let base = f64::from(params.base);
    let position = f64::from(params.position);
    let inverse_rope_dim = 1.0 / (params.rope_dim as f64);
    let pairs = params.rope_dim / 2;

    for pair_index in 0..pairs {
        // θ_i = base^(−2i / rope_dim). At i = 0 the exponent is exactly 0 and
        // powf returns exactly 1.0, so pair 0's angle is exactly the position.
        let frequency = powf(base, -2.0 * (pair_index as f64) * inverse_rope_dim);
        let (sin, cos) = sin_cos(position * frequency);
        let (sin, cos) = (sin as f32, cos as f32);

        // Element index of this pair within a head. `pair_index < rope_dim/2` and
        // `rope_dim <= d_head`, so both are in range; the checked forms are
        // here because "in range" is an argument and `checked_mul` is a
        // property of the program.
        let low = pair_index
            .checked_mul(2)
            .ok_or(TensorError::DimensionOverflow)?;
        let high = low.checked_add(1).ok_or(TensorError::DimensionOverflow)?;

        for (head_in, head_out) in x
            .chunks_exact(params.d_head)
            .zip(out.chunks_exact_mut(params.d_head))
        {
            let a = *head_in.get(low).ok_or(TensorError::ShapeMismatch)?;
            let b = *head_in.get(high).ok_or(TensorError::ShapeMismatch)?;
            *head_out.get_mut(low).ok_or(TensorError::ShapeMismatch)? = a * cos - b * sin;
            *head_out.get_mut(high).ok_or(TensorError::ShapeMismatch)? = a * sin + b * cos;
        }
    }
    Ok(())
}
