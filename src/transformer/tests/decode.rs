//! The decode loop: prefill, then incremental steps that reuse the cache.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

mod common;

use brainix_tensor::RopePairing;
use brainix_transformer::{
    sampler_scratch_floats, session_cache_floats, workspace_floats, CacheGeometry, KeyValueArena,
    Model, ModelConfig, Sampler, SamplingRequest, Workspace,
};
use common::{fixture_config, Fixture};

const MAXIMUM_BATCH: usize = 8;

/// Generates `count` tokens: one prefill call over `prompt`, then one call per
/// generated token.
fn generate(fixture: &Fixture, prompt: &[u32], count: usize, sampler: Sampler) -> Vec<u32> {
    let config: ModelConfig = fixture.config;
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace =
        Workspace::new(&mut workspace_storage, &mut [], &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    let mut logits = vec![0.0_f32; config.vocabulary_size];
    let mut sampler_scratch =
        vec![0.0_f32; sampler_scratch_floats(config.vocabulary_size).unwrap()];
    let mut request = SamplingRequest {
        scratch: &mut sampler_scratch,
        sampler,
        uniform: 0.5,
    };

    let mut generated = Vec::new();
    let mut next = model
        .next_token(
            &brainix_transformer::Serial,
            &mut workspace,
            &mut session,
            prompt,
            &mut logits,
            &mut request,
        )
        .unwrap();
    generated.push(next);
    for _ in 1..count {
        next = model
            .next_token(
                &brainix_transformer::Serial,
                &mut workspace,
                &mut session,
                &[next],
                &mut logits,
                &mut request,
            )
            .unwrap();
        generated.push(next);
    }
    assert_eq!(session.position(), prompt.len() + count - 1);
    generated
}

/// The loop must be reproducible: same weights, same prompt, same deviates,
/// same tokens. Greedy sampling makes this exact.
#[test]
fn greedy_generation_is_reproducible() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0xdec0_0001);
    let prompt = [12_u32, 5, 33];
    let first = generate(&fixture, &prompt, 5, Sampler::Greedy);
    let second = generate(&fixture, &prompt, 5, Sampler::Greedy);
    assert_eq!(first, second);
    assert_eq!(first.len(), 5);
    for token in &first {
        assert!((*token as usize) < fixture.config.vocabulary_size);
    }
}

/// Sampling with a temperature must still stay inside the vocabulary and must
/// still be reproducible for a fixed deviate — the randomness is entirely the
/// caller's.
#[test]
fn temperature_generation_is_reproducible_for_a_fixed_deviate() {
    let fixture = Fixture::new(fixture_config(RopePairing::HalfSplit), 0xdec0_0002);
    let prompt = [1_u32, 40];
    let sampler = Sampler::TopK {
        temperature: 0.7,
        top_k: 8,
    };
    let first = generate(&fixture, &prompt, 4, sampler);
    let second = generate(&fixture, &prompt, 4, sampler);
    assert_eq!(first, second);
}

/// A generation driven entirely one token at a time — no prefill batch — must
/// produce the same tokens as a prefill followed by steps. This is the
/// one-pass-versus-incremental property expressed at the loop level rather
/// than at the logits level.
#[test]
fn a_prefilled_generation_matches_a_fully_incremental_one() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0xdec0_0003);
    let prompt = [9_u32, 21, 6, 2];

    let prefilled = generate(&fixture, &prompt, 4, Sampler::Greedy);

    // Drive the same prompt one token at a time, then continue.
    let config = fixture.config;
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();
    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace =
        Workspace::new(&mut workspace_storage, &mut [], &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    let mut logits = vec![0.0_f32; config.vocabulary_size];
    let mut sampler_scratch =
        vec![0.0_f32; sampler_scratch_floats(config.vocabulary_size).unwrap()];
    let mut request = SamplingRequest {
        scratch: &mut sampler_scratch,
        sampler: Sampler::Greedy,
        uniform: 0.5,
    };

    let mut next = 0_u32;
    for token in &prompt {
        next = model
            .next_token(
                &brainix_transformer::Serial,
                &mut workspace,
                &mut session,
                core::slice::from_ref(token),
                &mut logits,
                &mut request,
            )
            .unwrap();
    }
    let mut incremental = vec![next];
    for _ in 1..4 {
        next = model
            .next_token(
                &brainix_transformer::Serial,
                &mut workspace,
                &mut session,
                &[next],
                &mut logits,
                &mut request,
            )
            .unwrap();
        incremental.push(next);
    }

    assert_eq!(prefilled, incremental);
}
