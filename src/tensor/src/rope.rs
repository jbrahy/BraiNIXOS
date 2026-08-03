//! Rotary position embedding.
//!
//! For dimension pair `i` of a head, with `θ_i = base^(−2i / rope_dim)` and
//! angle `a = position × θ_i`:
//!
//! ```text
//! out[lo] = x[lo]·cos(a) − x[hi]·sin(a)
//! out[hi] = x[lo]·sin(a) + x[hi]·cos(a)
//! ```
//!
//! where `(lo, hi)` is decided by [`RopePairing`] and **nothing else about the
//! rotation differs between the two conventions**.
//!
//! Dimensions `rope_dim .. d_head` are copied through unrotated — not zeroed,
//! and not rotated at an extrapolated frequency. BXW1 §5.1 pins that reading of
//! "leading per-head dimensions RoPE rotates". Both pairings cover exactly
//! `0 .. rope_dim`, so the untouched tail is the same set either way.
//!
//! # Everything model-specific comes from the parameters, never from this file
//!
//! `base` is BXW1's `rope_theta` and `pairing` is BXW1's `rope_pairing`, both
//! header fields. There is no `10000.0` and no default pairing anywhere in this
//! crate: a model constant compiled into the engine is a model the engine
//! cannot serve.

use crate::error::TensorError;
use crate::math::{powf, sin_cos, MAX_SIN_COS_ARG};
use crate::norm::is_positive_normal;

/// Which two components of a head form rotated pair `i` — BXW1's
/// `rope_pairing` (§5.5).
///
/// **Both conventions are real and in wide use, and which one is correct is a
/// property of the weight file, not of the engine.** The two differ by a
/// permutation of the Q and K projection rows, so the choice was fixed by
/// whoever converted the checkpoint. A runtime that hardcodes either produces
/// garbage on every model converted under the other.
///
/// # Why this is worth an enumerated field rather than a convention
///
/// The failure mode is the worst class BXW1 recognizes: **silent, plausible,
/// and undetectable by any unit test.** Position 0 is the identity under both;
/// both are norm-preserving per pair; both agree with any reference
/// implementation that shares their assumption. Every property a kernel test
/// can check passes under either. Only end-to-end logits parity against a
/// known-correct implementation distinguishes them — which is P3-T6, arriving
/// long after the model is loaded.
///
/// # There is no `Default`, deliberately
///
/// This type implements neither `Default` nor a `from_u32` that falls back, and
/// [`RopeParams`] has no default either — a caller must name the convention at
/// every call site. BXW1 §5.5 refuses `rope_pairing == 0` for the same reason:
/// a default would mean the one case the field exists to disambiguate — a
/// converter that never heard of it — is exactly the case it fails to catch.
///
/// # The two coincide at `rope_dim == 2`
///
/// With a single pair, interleaved gives `(x[0], x[1])` and half-split gives
/// `(x[0], x[0 + 1])`. Identical. That is a real property of the definitions,
/// not a bug, and it is why the test that proves the parameter is load bearing
/// uses `rope_dim >= 4`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RopePairing {
    /// Pair `i` is `(x[2i], x[2i+1])` — BXW1 `rope_pairing == 1`.
    ///
    /// Meta's reference LLaMA, which applies the rotation through a
    /// complex-number view of adjacent components.
    Interleaved,
    /// Pair `i` is `(x[i], x[i + rope_dim/2])` — BXW1 `rope_pairing == 2`.
    ///
    /// The HuggingFace `rotate_half` formulation, which permutes Q and K at
    /// conversion time so the arithmetic comes out equivalent.
    HalfSplit,
}

impl RopePairing {
    /// BXW1 `rope_pairing` value for [`RopePairing::Interleaved`].
    pub const BXW1_INTERLEAVED: u32 = 1;

    /// BXW1 `rope_pairing` value for [`RopePairing::HalfSplit`].
    pub const BXW1_HALF_SPLIT: u32 = 2;

    /// Decodes a BXW1 `rope_pairing` header field.
    ///
    /// This is the boundary where an unvalidated `u32` from a blob becomes a
    /// value the kernel can act on. Past it the convention is a Rust enum, so
    /// an unrecognized pairing is not merely refused — it is unrepresentable.
    ///
    /// # Errors
    ///
    /// [`TensorError::InvalidRopePairing`] for **every** value other than `1`
    /// and `2`, `0` included. Zero is not a default and not "unspecified"; it
    /// is what a converter that predates the field writes, and admitting it
    /// would defeat the field's entire purpose (BXW1 §5.5, rule H17a).
    pub const fn from_bxw1(value: u32) -> Result<Self, TensorError> {
        match value {
            Self::BXW1_INTERLEAVED => Ok(Self::Interleaved),
            Self::BXW1_HALF_SPLIT => Ok(Self::HalfSplit),
            _ => Err(TensorError::InvalidRopePairing),
        }
    }

    /// The BXW1 `rope_pairing` value this convention is written as.
    #[must_use]
    pub const fn to_bxw1(self) -> u32 {
        match self {
            Self::Interleaved => Self::BXW1_INTERLEAVED,
            Self::HalfSplit => Self::BXW1_HALF_SPLIT,
        }
    }

    /// The `(lo, hi)` component indices of pair `pair_index` within a head.
    ///
    /// Both conventions cover exactly `0 .. rope_dim` over
    /// `pair_index in 0 .. rope_dim/2`, which is why the unrotated tail is the
    /// same set for both and the tail copy needs no branch on the convention.
    fn pair_indices(self, pair_index: usize, half: usize) -> Result<(usize, usize), TensorError> {
        match self {
            Self::Interleaved => {
                let lo = pair_index
                    .checked_mul(2)
                    .ok_or(TensorError::DimensionOverflow)?;
                let hi = lo.checked_add(1).ok_or(TensorError::DimensionOverflow)?;
                Ok((lo, hi))
            }
            Self::HalfSplit => {
                let hi = pair_index
                    .checked_add(half)
                    .ok_or(TensorError::DimensionOverflow)?;
                Ok((pair_index, hi))
            }
        }
    }
}

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
    /// BXW1's `rope_pairing`: which two components form a rotated pair.
    ///
    /// **No default.** The field has no `Default` impl and this struct has no
    /// `Default` impl, so a caller must name the convention at every call site
    /// (BXW1 §5.5).
    pub pairing: RopePairing,
    /// Absolute token position. `0` is an exact identity under both pairings.
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
/// `params.pairing` decides only which two components each angle is applied to;
/// the angles themselves, the frequencies, and the untouched tail are identical
/// under both conventions.
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
/// There is no error for an unrecognized pairing, because
/// [`RopePairing::from_bxw1`] has already refused it — past that boundary the
/// convention is an enum and an invalid one cannot be constructed.
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

        // Element indices of this pair within a head, per the model's pairing
        // convention. `pair_index < rope_dim/2` and `rope_dim <= d_head`, so
        // both are in range; the checked forms inside `pair_indices` are there
        // because "in range" is an argument and `checked_add` is a property of
        // the program.
        let (low, high) = params.pairing.pair_indices(pair_index, pairs)?;

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
