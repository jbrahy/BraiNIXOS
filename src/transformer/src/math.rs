//! The one number the forward pass needs that neither `core` nor
//! `brainix_tensor` will give it.
//!
//! `core` has no `sqrt` — that lives in `std`, which a `#![no_std]` crate does
//! not have — and `brainix_tensor`'s soft-float module is private. The
//! attention scale `1/√d_head` is therefore computed here, by Newton–Raphson in
//! `f64`, **once per forward call** rather than once per score.
//!
//! This is a deliberate, recorded duplication of a private helper in another
//! crate. The alternative was to make the caller supply the scale, which would
//! put a derived quantity in the hands of whoever assembles the config and
//! reintroduce exactly the class of silent, plausible, wrong-output error that
//! BXW1 §5.5 exists to eliminate.
//!
//! # Why the attention scale is `1/√d_head` and not something the format says
//!
//! **BXW1 does not specify it.** §5.1 defines `rope_theta` as a base and
//! `norm_eps` as living inside the root, and §5's closing paragraph says
//! operator semantics belong to P3-T4 and P3-T6 — but no section states the
//! attention score normalization. `arch_id = 1` is the LLaMA-family
//! decoder-only architecture, for which the scale is `1/√d_head` universally,
//! so that is what this crate implements. It is named here rather than buried
//! at the call site because a model trained under a different convention would
//! produce fluent, confident, wrong text, and the fix would be a new header
//! field on the same footing as `rope_pairing`.

use crate::error::TransformerError;

/// Newton–Raphson iterations for the square root.
///
/// Quadratic convergence from `x₀ = max(value, 1)` reaches full `f64` precision
/// in under ten iterations for every `d_head` BXW1 admits (`1 ..= 512`). The
/// count is fixed rather than convergence-tested so the function is
/// branch-free in its loop and takes the same time for every input, and it is
/// generous because it runs once per forward call and costs nothing that
/// matters.
const NEWTON_ITERATIONS: usize = 48;

/// `√value` for a positive finite `value`.
fn square_root(value: f64) -> Result<f64, TransformerError> {
    if !(value.is_finite() && value > 0.0) {
        return Err(TransformerError::ZeroDimension);
    }
    let mut estimate = if value < 1.0 { 1.0 } else { value };
    for _ in 0..NEWTON_ITERATIONS {
        estimate = 0.5 * (estimate + value / estimate);
    }
    Ok(estimate)
}

/// The attention score scale `1/√d_head`, as the `f32` the scores are in.
///
/// # Errors
///
/// [`TransformerError::ZeroDimension`] if `head_width` is zero.
pub(crate) fn attention_scale(head_width: usize) -> Result<f32, TransformerError> {
    let root = square_root(head_width as f64)?;
    Ok((1.0 / root) as f32)
}
