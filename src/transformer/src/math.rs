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

/// `attention_scale` at the shape its callers cannot present.
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{attention_scale, ARCH_DECODER_ROPE_GQA_SWIGLU};
    use crate::error::TransformerError;

    #[test]
    fn a_zero_head_width_is_refused_rather_than_returning_infinity() {
        // `1/sqrt(0)` is `+inf`, and an infinite scale turns every attention
        // score into `inf` or `NaN`, which softmax then refuses -- so the
        // failure would surface three layers away from its cause. Refusing
        // here names it where it happened.
        assert_eq!(
            attention_scale(ARCH_DECODER_ROPE_GQA_SWIGLU, 0),
            Err(TransformerError::ZeroDimension)
        );
    }

    #[test]
    fn only_the_one_architecture_has_a_defined_scale() {
        // BXW1 §5.6 assigns the scale per `arch_id`. An unknown architecture
        // has no assignment, and guessing `1/sqrt(d_head)` for it would run a
        // model whose scores are silently wrong rather than refusing to run it.
        for unknown in [0u32, 2, 7, u32::MAX] {
            assert_eq!(
                attention_scale(unknown, 64),
                Err(TransformerError::UnspecifiedAttentionScale),
                "arch_id {unknown} has no assigned scale"
            );
        }
    }

    #[test]
    fn the_defined_scale_is_the_reciprocal_square_root_of_the_head_width() {
        // Exact for powers of two, which every real head width is.
        for (width, expected) in [(64usize, 0.125_f32), (16, 0.25), (256, 0.0625)] {
            let scale = attention_scale(ARCH_DECODER_ROPE_GQA_SWIGLU, width)
                .expect("the defined architecture");
            assert!(
                (scale - expected).abs() < 1e-6,
                "d_head {width} should scale by {expected}, got {scale}"
            );
        }
    }
}
