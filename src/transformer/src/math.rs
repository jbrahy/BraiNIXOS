//! The attention score scale, derived from `arch_id` rather than assumed.
//!
//! BXW1 §5.6 states that the attention score normalization is a property of the
//! architecture family, and that `arch_id` is what names the family: for
//! `arch_id = 1` — `BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU`, the only family the
//! format enumerates — a score is the dot product of the rotated query and key
//! multiplied by `d_head^(−1/2)`, once, for every layer and every head.
//!
//! **An `arch_id` whose convention §5.6 does not state is refused here**, and it
//! is refused at [`crate::Model::new`] rather than at the first token. The
//! alternative is the failure class §5.5 and §5.6 exist to eliminate: a wrong
//! scale does not crash and does not deny, it changes the sharpness of every
//! attention distribution, and the engine goes on producing fluent, confident,
//! wrong text. There is no "unknown architecture, assume `1/√d_head`" fallback,
//! because assuming it silently is the entire bug.
//!
//! The reciprocal square root itself is [`brainix_tensor::rsqrt`] — `core` has
//! no `sqrt`, and the kernels' Newton iteration is published precisely so this
//! crate does not carry a second one. It is evaluated **once per
//! [`crate::Model::new`]**, not once per score.

use brainix_tensor::rsqrt;

use crate::error::TransformerError;

/// BXW1 `arch_id = 1`: the decoder-only family this crate implements
/// (BXW1 §5.2).
///
/// The only `arch_id` for which BXW1 §5.6 states an attention scale, and
/// therefore the only one [`attention_scale`] can serve. It is an enumerator
/// copied from the header, not a model constant compiled into the engine — the
/// distinction BXW1 §5's opening sentence draws.
const ARCH_DECODER_ROPE_GQA_SWIGLU: u32 = 1;

/// The attention score scale BXW1 §5.6 assigns to `architecture_id`, as the
/// `f32` the scores are in.
///
/// # Errors
///
/// - [`TransformerError::UnspecifiedAttentionScale`] if BXW1 §5.6 states no
///   scale for `architecture_id`.
/// - [`TransformerError::ZeroDimension`] if `head_width` is zero.
pub(crate) fn attention_scale(
    architecture_id: u32,
    head_width: usize,
) -> Result<f32, TransformerError> {
    if architecture_id != ARCH_DECODER_ROPE_GQA_SWIGLU {
        return Err(TransformerError::UnspecifiedAttentionScale);
    }
    if head_width == 0 {
        return Err(TransformerError::ZeroDimension);
    }
    Ok(rsqrt(head_width as f64) as f32)
}
