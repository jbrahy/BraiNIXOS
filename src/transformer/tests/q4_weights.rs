//! `Q4_0` weights through the forward pass.
//!
//! # Why this exists
//!
//! `WeightMatrix::Quantized4` was added on 2026-08-19 so the engine could load
//! the format's new 4-bit dtype. Nothing in the existing suite could reach it:
//! `tests/common` builds every matrix as `Q8_0` or `F32`, so the whole arm --
//! shape check, activation quantization, kernel call, and the refusal when
//! there is no scratch -- was unexecuted code on the serving datapath.
//!
//! # What is asserted, and what deliberately is not
//!
//! That the arm **runs and produces finite logits of the right width**, that it
//! **agrees with `Q8_0` to within what 4-bit quantization can cost**, and that
//! it **refuses rather than substituting** when the caller supplies no
//! quantization scratch.
//!
//! Not asserted: that `Q4_0` is as accurate as `Q8_0`. It is not, by
//! construction -- 15 representable levels against 255 -- and a test that
//! demanded otherwise would be demanding the format not work as specified. The
//! bound below is loose on purpose and is a smoke test for "computing the same
//! function", not a quality gate. Quality is `examples/perplexity`'s job, and
//! it needs a real checkpoint rather than deterministic noise.

// The workspace lints are written for production code and correctly refuse
// `unwrap`/`expect` and indexing there. A test that cannot say `expect` says
// something longer and worse instead, so this mirrors `tests/adversarial.rs`
// in the bxw1 crate.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use brainix_tensor::{quantize_q4_0, Q4Weights, RopePairing};
use brainix_transformer::{
    quantized_activation_bytes, session_cache_floats, workspace_floats, CacheGeometry, Dispatch,
    KeyValueArena, LayerWeights, LogitProjection, Model, ModelWeights, Serial, WeightMatrix,
    Workspace,
};
use common::Fixture;

const MAXIMUM_BATCH: usize = 4;

/// A `Q4_0` payload for one matrix, from the fixture's dequantized values.
///
/// Requantizing the fixture's `dense` rather than its original draw is
/// deliberate: `dense` is what the `Q8_0` path actually computes with, so the
/// two runs compared below differ in the weight width and in nothing else.
fn q4_payload(dense: &[f32], out_features: usize, in_features: usize) -> Vec<u8> {
    let bytes = Q4Weights::derived_payload_len(out_features, in_features)
        .expect("the fixture shapes are block-aligned");
    let mut payload = vec![0u8; bytes];
    quantize_q4_0(out_features, in_features, dense, &mut payload).expect("quantize");
    payload
}

/// Every quantized matrix of the fixture, re-encoded as `Q4_0`.
///
/// Returned as one flat `Vec` in a fixed order so the views below can be built
/// from stable indices; the payloads must outlive the borrows.
fn q4_payloads(fixture: &Fixture) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    for layer in &fixture.layers {
        for matrix in [
            &layer.query,
            &layer.key,
            &layer.value,
            &layer.attention_output,
            &layer.gate,
            &layer.up,
            &layer.down,
        ] {
            payloads.push(q4_payload(
                &matrix.dense,
                matrix.out_features,
                matrix.in_features,
            ));
        }
    }
    payloads
}

/// The fixture's layers with every projection swapped to `Q4_0`.
fn q4_layers<'a>(fixture: &'a Fixture, payloads: &'a [Vec<u8>]) -> Vec<LayerWeights<'a>> {
    fixture
        .layers
        .iter()
        .enumerate()
        .map(|(index, layer)| {
            let base = index * 7;
            let view = |offset: usize, out_features: usize, in_features: usize| {
                WeightMatrix::Quantized4(
                    Q4Weights::new(&payloads[base + offset], out_features, in_features)
                        .expect("payload matches the shape it was built from"),
                )
            };
            LayerWeights {
                attention_norm: &layer.attention_norm,
                query_projection: view(0, layer.query.out_features, layer.query.in_features),
                key_projection: view(1, layer.key.out_features, layer.key.in_features),
                value_projection: view(2, layer.value.out_features, layer.value.in_features),
                attention_output_projection: view(
                    3,
                    layer.attention_output.out_features,
                    layer.attention_output.in_features,
                ),
                feed_forward_norm: &layer.feed_forward_norm,
                gate_projection: view(4, layer.gate.out_features, layer.gate.in_features),
                up_projection: view(5, layer.up.out_features, layer.up.in_features),
                down_projection: view(6, layer.down.out_features, layer.down.in_features),
            }
        })
        .collect()
}

/// Decodes `tokens` and returns the final logits.
///
/// `scratch_bytes` of zero is the case with no room for quantized activations,
/// which `Q4_0` must refuse rather than compute another way.
fn logits_for(quantized_to_four_bits: bool, scratch_bytes: usize) -> Result<Vec<f32>, ()> {
    logits_under(&Serial, quantized_to_four_bits, scratch_bytes)
}

/// A dispatcher that really splits, running the chunks in this thread.
///
/// Sequential on purpose, as in `split_dispatch.rs`: the question is whether
/// the DECOMPOSITION is right -- chunk boundaries, row offsets, threshold --
/// and threads would add scheduling to a test about arithmetic.
struct Chunked {
    chunks: usize,
    minimum_bytes: usize,
}

impl Dispatch for Chunked {
    fn chunks(&self) -> usize {
        self.chunks
    }

    fn minimum_split_bytes(&self) -> usize {
        self.minimum_bytes
    }

    fn for_each_chunk<F>(&self, out: &mut [f32], chunk_len: usize, body: F)
    where
        F: Fn(usize, &mut [f32]) + Sync,
    {
        for (index, chunk) in out.chunks_mut(chunk_len.max(1)).enumerate() {
            body(index, chunk);
        }
    }
}

fn logits_under<D: Dispatch>(
    dispatch: &D,
    quantized_to_four_bits: bool,
    scratch_bytes: usize,
) -> Result<Vec<f32>, ()> {
    logits_under_batch(dispatch, quantized_to_four_bits, scratch_bytes, &[2_u32])
}

/// The same, for a batch of more than one token.
///
/// Every test in this file decoded exactly one token until 2026-08-20, which
/// meant the Q4_0 prefill split had no coverage at all: planting a bug in it --
/// making every worker start at token zero -- left the whole file green. The
/// single-token path is a different branch entirely.
fn logits_under_batch<D: Dispatch>(
    dispatch: &D,
    quantized_to_four_bits: bool,
    scratch_bytes: usize,
    tokens: &[u32],
) -> Result<Vec<f32>, ()> {
    let fixture = Fixture::new(common::fixture_config(RopePairing::HalfSplit), 0x0451_0451);
    let config = fixture.config;

    let payloads = q4_payloads(&fixture);
    let q8_layers = fixture.layer_views();
    let q4_layers = q4_layers(&fixture, &payloads);
    let layers = if quantized_to_four_bits {
        &q4_layers
    } else {
        &q8_layers
    };

    let weights = ModelWeights {
        token_embeddings: &fixture.token_embeddings,
        layers,
        final_norm: &fixture.final_norm,
        logit_projection: LogitProjection::Separate(fixture.output.view()),
    };
    let model = Model::new(config, weights).map_err(|_| ())?;

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut scratch = vec![0_u8; scratch_bytes];
    let mut workspace =
        Workspace::new(&mut workspace_storage, &mut scratch, &config, MAXIMUM_BATCH).unwrap();

    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut cache = arena.issue_session().unwrap();

    let mut logits = vec![0.0_f32; config.vocabulary_size];
    model
        .forward(dispatch, &mut workspace, &mut cache, tokens, &mut logits)
        .map_err(|_| ())?;
    Ok(logits)
}

#[test]
fn four_bit_weights_produce_finite_logits_of_the_right_width() {
    let scratch = quantized_activation_bytes(
        &common::fixture_config(RopePairing::HalfSplit),
        MAXIMUM_BATCH,
    )
    .unwrap();
    let logits = logits_for(true, scratch).expect("the Q4_0 path runs");

    assert_eq!(
        logits.len(),
        common::fixture_config(RopePairing::HalfSplit).vocabulary_size
    );
    assert!(
        logits.iter().all(|value| value.is_finite()),
        "a non-finite logit means the nibble unpacking or the scale is wrong, \
         and sampling would refuse the whole distribution"
    );
    // Not all one value: a decoder that dropped the weights entirely would
    // still produce finite numbers, and they would be identical.
    let first = logits[0];
    assert!(
        logits.iter().any(|value| *value != first),
        "every logit identical means the projections contributed nothing"
    );
}

#[test]
fn four_bit_and_eight_bit_agree_to_within_what_four_bits_can_cost() {
    let config = common::fixture_config(RopePairing::HalfSplit);
    let scratch = quantized_activation_bytes(&config, MAXIMUM_BATCH).unwrap();

    let four = logits_for(true, scratch).expect("Q4_0 runs");
    let eight = logits_for(false, scratch).expect("Q8_0 runs");

    // Deliberately loose. `Q4_0` has 15 levels against `Q8_0`'s 255, so the
    // two cannot agree closely and demanding it would demand the format not
    // work. What this catches is the failure that matters: a transposed nibble
    // or an inverted scale, which does not perturb the logits, it replaces
    // them.
    let (mut worst, mut spread) = (0.0_f32, 0.0_f32);
    for (a, b) in four.iter().zip(eight.iter()) {
        worst = worst.max((a - b).abs());
        spread = spread.max(b.abs());
    }
    assert!(
        worst <= spread.max(1.0),
        "Q4_0 logits differ from Q8_0 by {worst}, which is larger than the \
         Q8_0 logits themselves ({spread}) -- that is a different function, \
         not a coarser one"
    );
}

#[test]
fn four_bit_weights_refuse_when_there_is_no_room_to_quantize_activations() {
    // `Q8_0` keeps an f32-activation kernel for exactly this case, so a caller
    // who supplies no scratch still gets an answer -- a more precise one. There
    // is no such kernel for `Q4_0`, so the only honest options are to refuse or
    // to silently compute something else. It refuses.
    assert!(
        logits_for(true, 0).is_err(),
        "Q4_0 with no activation scratch must refuse rather than substitute"
    );

    // And the same call with `Q8_0` weights does NOT refuse, which is what
    // makes the refusal specific to the missing kernel rather than to the
    // empty buffer.
    assert!(
        logits_for(false, 0).is_ok(),
        "Q8_0 falls back to the f32-activation kernel and still answers"
    );
}

#[test]
fn splitting_four_bit_output_rows_reproduces_the_serial_answer() {
    // The Q4_0 row-split path, which is the only way Q4_0 reaches the
    // bandwidth-bound regime where its fewer bytes are worth anything. Without
    // it, every Q4_0 projection runs on the calling core however many workers
    // are idle -- and measured that way Q4_0 is 0.78x of Q8_0. With it, the two
    // are level at 227.6 against 229.0 tok/s, for a model 1.67x smaller.
    //
    // Equality, not a tolerance: worker k computes its own output rows from all
    // of the activations, so the decomposition is exact. A tolerance would hide
    // an off-by-one in the row offset, which perturbs a few outputs slightly
    // and passes any bound loose enough to allow rounding.
    let config = common::fixture_config(RopePairing::HalfSplit);
    let scratch = quantized_activation_bytes(&config, MAXIMUM_BATCH).unwrap();
    let serial = logits_for(true, scratch).expect("Q4_0 runs serially");

    for chunks in [2_usize, 3, 4, 8] {
        let split = logits_under(
            &Chunked {
                chunks,
                // Zero threshold so this small fixture takes the branch at all.
                minimum_bytes: 0,
            },
            true,
            scratch,
        )
        .expect("Q4_0 runs split");
        assert_eq!(
            split, serial,
            "{chunks} chunks disagreed with one, and a row split is exact"
        );
    }
}

#[test]
fn four_bit_work_below_the_threshold_stays_on_the_calling_core() {
    // The threshold is a performance knob and never a correctness one. A
    // ceiling nothing can exceed skips the split branch entirely, and the
    // answer must be identical to the serial one.
    let config = common::fixture_config(RopePairing::HalfSplit);
    let scratch = quantized_activation_bytes(&config, MAXIMUM_BATCH).unwrap();
    let serial = logits_for(true, scratch).expect("serial");
    let unsplit = logits_under(
        &Chunked {
            chunks: 4,
            minimum_bytes: usize::MAX,
        },
        true,
        scratch,
    )
    .expect("unsplit");
    assert_eq!(unsplit, serial);
}

#[test]
fn splitting_four_bit_tokens_reproduces_the_serial_answer() {
    // The Q4_0 prefill split, added 2026-08-20 alongside the Q8_0 one.
    //
    // This test exists because the mutation check found nothing to catch a bug
    // in that branch: every other test here decodes one token, which takes the
    // ROW-split path, and a deliberate off-by-worker in the token split left
    // the file green. A branch nothing exercises is a branch nothing protects,
    // however carefully its kernel is tested in isolation.
    //
    // Equality, not a tolerance. Worker k computes whole tokens, so an
    // off-by-one in the token offset moves entire rows of the output rather
    // than perturbing a sum -- and a tolerance loose enough for rounding would
    // not notice.
    let config = common::fixture_config(RopePairing::HalfSplit);
    let scratch = quantized_activation_bytes(&config, MAXIMUM_BATCH).unwrap();
    let tokens = [1_u32, 2, 3];
    let serial = logits_under_batch(&Serial, true, scratch, &tokens).expect("Q4_0 prefill serial");

    for chunks in [2_usize, 3, 4, 8] {
        let split = logits_under_batch(
            &Chunked {
                chunks,
                minimum_bytes: 0,
            },
            true,
            scratch,
            &tokens,
        )
        .expect("Q4_0 prefill split");
        assert_eq!(
            split, serial,
            "{chunks} chunks disagreed with one over a 3-token Q4_0 batch"
        );
    }
}
