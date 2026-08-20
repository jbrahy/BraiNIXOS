//! The workspace size derivations, which nothing called.
//!
//! `quantized_activation_bytes` is a `pub const fn` on the crate's surface and
//! the coverage gate found every line of it uncovered. That is worse than an
//! untested helper: a caller sizes a buffer from it and then hands that buffer
//! to kernels that trust the size. If it is wrong, the failure is a shape
//! mismatch at best and a silently truncated activation plane at worst.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects
)]

mod common;

use brainix_tensor::RopePairing;
use brainix_transformer::{quantized_activation_bytes, workspace_floats, ModelConfig};

fn config() -> ModelConfig {
    common::fixture_config(RopePairing::HalfSplit)
}

/// The `Q8_0` layout this must agree with: per token, a scale plane of four
/// bytes per 32-element block padded to the 128-byte tensor alignment, then one
/// quant byte per element.
fn expected_bytes(widest: usize, tokens: usize) -> usize {
    let blocks = widest / 32;
    let scales = blocks * 4;
    let padded = scales.next_multiple_of(128);
    (padded + widest) * tokens
}

#[test]
fn the_quantized_plane_is_sized_for_the_widest_projection() {
    let config = config();
    // The feed-forward width is the widest thing quantized, not the model
    // width. Sizing from `model_width` would under-allocate for the gate and up
    // projections by exactly the ratio between them.
    assert!(config.feed_forward_width > config.model_width);

    for tokens in [1_usize, 3, 8] {
        let produced = quantized_activation_bytes(&config, tokens).expect("sizing");
        assert_eq!(
            produced,
            expected_bytes(config.feed_forward_width, tokens),
            "{tokens} tokens"
        );
    }
}

#[test]
fn the_plane_scales_linearly_with_the_batch() {
    let config = config();
    let one = quantized_activation_bytes(&config, 1).expect("sizing");
    let four = quantized_activation_bytes(&config, 4).expect("sizing");
    assert_eq!(four, one * 4, "the plane is per token and nothing else");
}

#[test]
fn a_model_width_wider_than_the_feed_forward_still_sizes_from_the_widest() {
    // Inverted on purpose. The function takes a max rather than assuming which
    // way round they are, and nothing in BXW1 forbids this shape.
    let mut config = config();
    config.model_width = 256;
    config.feed_forward_width = 64;
    let produced = quantized_activation_bytes(&config, 1).expect("sizing");
    assert_eq!(produced, expected_bytes(256, 1));
}

#[test]
fn a_zero_batch_is_a_zero_plane_rather_than_an_error() {
    // Zero tokens is a degenerate but representable request, and the answer is
    // zero bytes. A caller that then hands an empty scratch to the forward pass
    // selects the f32-activation kernel, which is the documented behaviour of
    // an empty `quant_scratch`.
    let config = config();
    assert_eq!(quantized_activation_bytes(&config, 0).expect("sizing"), 0);
}

#[test]
fn an_overflowing_batch_denies_rather_than_wrapping() {
    let config = config();
    assert!(
        quantized_activation_bytes(&config, usize::MAX).is_err(),
        "a multiply that would wrap must deny; a wrapped size is a buffer \
         smaller than the data written through it"
    );
}

#[test]
fn the_float_workspace_also_denies_an_overflowing_batch() {
    let config = config();
    assert!(workspace_floats(&config, 1).is_ok());
    assert!(workspace_floats(&config, usize::MAX).is_err());
}

#[test]
fn a_width_that_cannot_be_added_to_its_own_scale_plane_denies() {
    // The last overflow guard in the derivation: the padded scale plane plus
    // the quant plane. `quantized_activation_bytes` does not validate the
    // config -- callers pass one that `Model::new` already checked -- so a
    // width this large is reachable through the public surface and has to be
    // refused rather than wrapped.
    //
    // It is the ONLY one of the three guards that can fire. The block count is
    // `widest / 32` and the scale bytes are four per block, so the scale plane
    // is at most `widest / 8` and can never overflow on its own; adding it to
    // `widest` can.
    let mut config = config();
    config.feed_forward_width = usize::MAX;
    assert!(
        quantized_activation_bytes(&config, 1).is_err(),
        "a size that wraps is a buffer smaller than the data written through it"
    );
}
