//! Whole-model correctness: the four properties a subtly wrong transformer
//! fails and every per-kernel test passes.
//!
//! A transformer that is wrong does not crash. It produces fluent, confident,
//! wrong text. Each test here states the property it establishes and, where a
//! tolerance is involved, where the tolerance comes from.

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
    session_cache_floats, workspace_floats, CacheGeometry, KeyValueArena, Model, ModelConfig,
    Workspace,
};
use common::{argmax, fixture_config, largest_difference, reference_logits, Fixture};

/// The largest batch any test here submits in one call.
const MAXIMUM_BATCH: usize = 8;

/// Absolute logits tolerance against the `f64` reference.
///
/// **Where it comes from.** The implementation accumulates every dot product in
/// `f32`; the reference accumulates the same terms in `f64`. The classical
/// forward error bound for a length-`n` `f32` dot product is
/// `γ_n · Σ|aᵢbᵢ|` with `γ_n ≈ n·u` and `u = 2⁻²⁴`, so one `d_model = 32` dot
/// product of `O(1)` terms carries about `32 · 6·10⁻⁸ ≈ 2·10⁻⁶` of absolute
/// error. The forward pass chains roughly a dozen such products per layer
/// through two layers, plus a `d_ffn = 64` reduction and a `vocab = 48 × 32`
/// output projection, and the residual stream sums them rather than averaging.
/// A few times `10⁻⁶` is therefore the expected scale, and the measured
/// maximum over this fixture is `2.15·10⁻⁶`. The bound below is `2·10⁻⁵` —
/// roughly ten times the measurement, which is loose enough not to be a
/// tripwire on ordinary rounding or on a different host's `f32` fused-multiply
/// behaviour, and tight enough that any *structural* error (a transposed
/// matrix, the wrong pairing, an off-by-one position, a dropped residual, a
/// missing attention scale) is `O(1)` and blows straight through it by four
/// orders of magnitude.
///
/// The parity test prints the figure it actually measured, so a regression that
/// merely *approaches* the bound is visible rather than silent.
const LOGITS_TOLERANCE: f64 = 2.0e-5;

/// Runs `batches` in order against a fresh session and returns the logits of
/// the final call.
fn run_batches(fixture: &Fixture, batches: &[&[u32]]) -> Vec<f32> {
    let config = fixture.config;
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace = Workspace::new(&mut workspace_storage, &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();

    let mut logits = vec![0.0_f32; config.vocabulary_size];
    for batch in batches {
        model
            .forward(&mut workspace, &mut session, batch, &mut logits)
            .unwrap();
    }
    logits
}

/// Runs a whole prompt in one call.
fn run_prompt(fixture: &Fixture, tokens: &[u32]) -> Vec<f32> {
    run_batches(fixture, &[tokens])
}

/// Feeds a prompt one token at a time.
fn run_incrementally(fixture: &Fixture, tokens: &[u32]) -> Vec<f32> {
    let singles: Vec<&[u32]> = tokens.iter().map(core::slice::from_ref).collect();
    run_batches(fixture, &singles)
}

// ------------------------------------------------------------------ parity

/// **Property: the composition is the transformer the format describes.**
///
/// Every kernel can be individually correct while the forward pass is wrong —
/// a transposed projection, a post-norm residual, values rotated along with
/// keys, the attention scale omitted. Only an end-to-end comparison against an
/// independently written reference detects those, and this is it.
#[test]
fn logits_match_an_independent_reference() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0001);
    let prompt = [7_u32, 41, 0, 13, 29];

    let actual = run_prompt(&fixture, &prompt);
    let reference = reference_logits(&fixture, &prompt);

    let difference = largest_difference(&actual, &reference);
    assert!(
        difference <= LOGITS_TOLERANCE,
        "largest logit difference {difference:e} exceeds tolerance {LOGITS_TOLERANCE:e}"
    );
    // The sampled token must agree, not merely the numbers: a difference that
    // moved the argmax would be a different generation whatever its magnitude.
    let actual_wide: Vec<f64> = actual.iter().map(|v| f64::from(*v)).collect();
    assert_eq!(argmax(&actual_wide), argmax(&reference));
    println!("reference parity: largest absolute logit difference {difference:e}");
}

/// The same property with the other RoPE convention, so neither pairing is
/// correct only by accident of which one the reference happens to share.
#[test]
fn logits_match_the_reference_under_half_split_pairing() {
    let fixture = Fixture::new(fixture_config(RopePairing::HalfSplit), 0x5eed_0002);
    let prompt = [3_u32, 3, 47, 12];

    let actual = run_prompt(&fixture, &prompt);
    let reference = reference_logits(&fixture, &prompt);

    let difference = largest_difference(&actual, &reference);
    assert!(difference <= LOGITS_TOLERANCE, "difference {difference:e}");
}

/// Grouped-query attention degenerating to ordinary multi-head attention, and
/// to multi-query attention, must both be the same code path and both be right.
#[test]
fn logits_match_the_reference_for_multi_head_and_multi_query() {
    for key_value_head_count in [1_usize, 4] {
        let mut config = fixture_config(RopePairing::Interleaved);
        config.key_value_head_count = key_value_head_count;
        let fixture = Fixture::new(config, 0x5eed_0003);
        let prompt = [5_u32, 22, 9];

        let actual = run_prompt(&fixture, &prompt);
        let reference = reference_logits(&fixture, &prompt);

        let difference = largest_difference(&actual, &reference);
        assert!(
            difference <= LOGITS_TOLERANCE,
            "n_kv_heads {key_value_head_count}: difference {difference:e}"
        );
    }
}

/// A tied output projection must be the embedding table, used as a matrix.
#[test]
fn tied_output_projection_matches_the_reference() {
    let fixture = Fixture::tied(fixture_config(RopePairing::Interleaved), 0x5eed_0004);
    let prompt = [11_u32, 2, 33];

    let actual = run_prompt(&fixture, &prompt);
    let reference = reference_logits(&fixture, &prompt);

    let difference = largest_difference(&actual, &reference);
    assert!(difference <= LOGITS_TOLERANCE, "difference {difference:e}");
}

/// A rotation past the rotated prefix must leave the tail alone. `rope_dim = 4`
/// against `d_head = 8` means half of every head passes through unrotated; the
/// reference copies it, and parity over a prompt long enough for the rotation
/// to matter is what proves the implementation does too.
#[test]
fn the_unrotated_head_tail_is_carried_through() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0005);
    let prompt = [1_u32, 2, 3, 4, 5, 6, 7, 8];

    let actual = run_prompt(&fixture, &prompt);
    let reference = reference_logits(&fixture, &prompt);

    assert!(largest_difference(&actual, &reference) <= LOGITS_TOLERANCE);
}

// --------------------------------------------------- cache: one pass vs many

/// **Property: the key/value cache is not observable.**
///
/// This is the single most valuable assertion in the crate. A prompt run in one
/// call and the same prompt fed one token at a time exercise the cache
/// completely differently — one writes `n` positions in one sweep and attends
/// with `n` distinct causal bounds, the other writes one position per call and
/// attends with a bound that grows — and nearly every key/value indexing bug
/// makes them disagree.
///
/// The comparison is **exact**, not toleranced. Both routes compute each output
/// element's dot product over the same terms in the same order — the matmuls
/// are weights-outer with an independent accumulator per (token, row), RMSNorm
/// is per row, RoPE is per token, softmax is per query — so a difference of one
/// ulp would itself be a defect worth finding.
#[test]
fn one_pass_and_incremental_decode_agree_bit_for_bit() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0011);
    let prompt = [4_u32, 18, 45, 0, 31, 7];

    let batched = run_prompt(&fixture, &prompt);
    let incremental = run_incrementally(&fixture, &prompt);

    assert_eq!(
        batched.to_vec(),
        incremental.to_vec(),
        "one-pass and incremental logits differ"
    );
}

/// The same property when the prompt is split at an arbitrary interior point,
/// which is what a real continuation does: prefill, then append.
#[test]
fn a_split_prompt_agrees_with_the_whole_prompt() {
    let fixture = Fixture::new(fixture_config(RopePairing::HalfSplit), 0x5eed_0012);
    let prompt = [2_u32, 19, 8, 44, 15, 6, 27];

    let whole = run_prompt(&fixture, &prompt);
    let split = run_batches(&fixture, &[&prompt[..3], &prompt[3..5], &prompt[5..]]);

    assert_eq!(whole.to_vec(), split.to_vec());
}

// ------------------------------------------------------- INV-SERVE isolation

/// **Property: `INV-SERVE`. No client can reach another's key/value state.**
///
/// Two sessions cut from the same arena, driven with interleaved calls, must
/// produce exactly the logits each produces alone. The interleaving is what
/// makes this a real test: if the partitions overlapped, or if any position or
/// context bound leaked between sessions, the interleaved run would differ.
#[test]
fn interleaved_sessions_are_indistinguishable_from_isolated_ones() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x5eed_0021);
    let first_prompt = [9_u32, 3, 40, 12];
    let second_prompt = [21_u32, 5, 5, 38, 1];

    let alone_first = run_prompt(&fixture, &first_prompt);
    let alone_second = run_prompt(&fixture, &second_prompt);

    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace = Workspace::new(&mut workspace_storage, &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 2).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut first = arena.issue_session().unwrap();
    let mut second = arena.issue_session().unwrap();

    let mut first_logits = vec![0.0_f32; config.vocabulary_size];
    let mut second_logits = vec![0.0_f32; config.vocabulary_size];

    // Interleave one token at a time, alternating sessions, so every step of
    // one session is separated from its predecessor by a step of the other.
    let steps = first_prompt.len().max(second_prompt.len());
    for step in 0..steps {
        if let Some(token) = first_prompt.get(step) {
            model
                .forward(
                    &mut workspace,
                    &mut first,
                    core::slice::from_ref(token),
                    &mut first_logits,
                )
                .unwrap();
        }
        if let Some(token) = second_prompt.get(step) {
            model
                .forward(
                    &mut workspace,
                    &mut second,
                    core::slice::from_ref(token),
                    &mut second_logits,
                )
                .unwrap();
        }
    }

    assert_eq!(first_logits, alone_first, "session one was perturbed");
    assert_eq!(second_logits, alone_second, "session two was perturbed");
}

/// Resetting a session must return it to a clean context, not to a context
/// whose stale rows are still reachable.
#[test]
fn a_reset_session_decodes_as_a_fresh_one() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x5eed_0022);
    let prompt = [30_u32, 14, 2];

    let fresh = run_prompt(&fixture, &prompt);

    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();
    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace = Workspace::new(&mut workspace_storage, &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    let mut logits = vec![0.0_f32; config.vocabulary_size];

    model
        .forward(&mut workspace, &mut session, &[44, 8, 19, 3], &mut logits)
        .unwrap();
    session.reset();
    assert_eq!(session.position(), 0);
    model
        .forward(&mut workspace, &mut session, &prompt, &mut logits)
        .unwrap();

    assert_eq!(logits, fresh);
}

// ------------------------------------------------- the pairing is load bearing

/// **Property: `rope_pairing` is read, not ignored.**
///
/// The two conventions are identical at position 0, norm-preserving per pair,
/// and agree with any reference that shares their assumption — every property a
/// kernel test can check passes under either (BXW1 §5.5). The only thing that
/// distinguishes them is end-to-end logits, over a prompt long enough for a
/// non-zero position to exist and with `rope_dim ≥ 4` so the pairings do not
/// coincide.
///
/// A run that hardcoded either convention, or that dropped the field, would
/// make these two equal.
#[test]
fn the_two_rope_pairings_produce_different_logits() {
    let prompt = [6_u32, 23, 11, 39];
    let interleaved = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0031);
    let half_split = Fixture::new(fixture_config(RopePairing::HalfSplit), 0x5eed_0031);

    // Same seed, so the weights are identical and the pairing is the only
    // difference between the two runs.
    assert_eq!(interleaved.token_embeddings, half_split.token_embeddings);

    let first = run_prompt(&interleaved, &prompt);
    let second = run_prompt(&half_split, &prompt);

    assert_ne!(first, second, "rope_pairing had no effect on the logits");
    let second_wide: Vec<f64> = second.iter().map(|v| f64::from(*v)).collect();
    let separation = largest_difference(&first, &second_wide);
    assert!(
        separation > 1.0e-3,
        "the pairings differ by only {separation:e}, which is rounding rather than structure"
    );
}

/// At position 0 the two conventions *must* agree — that is a real property of
/// the definitions, and asserting it keeps the test above honest: it shows the
/// difference comes from the rotation and not from an unrelated divergence.
#[test]
fn the_two_rope_pairings_agree_on_a_single_token() {
    let interleaved = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0032);
    let half_split = Fixture::new(fixture_config(RopePairing::HalfSplit), 0x5eed_0032);

    let first = run_prompt(&interleaved, &[17]);
    let second = run_prompt(&half_split, &[17]);

    assert_eq!(first, second);
}

/// A model whose configuration differs only in `max_seq_len` still decodes the
/// same prefix identically: the cache capacity must not enter the arithmetic.
#[test]
fn context_capacity_does_not_change_the_logits() {
    let mut small = fixture_config(RopePairing::Interleaved);
    small.maximum_sequence_length = 8;
    let mut large = fixture_config(RopePairing::Interleaved);
    large.maximum_sequence_length = 64;

    let prompt = [26_u32, 4, 13];
    let first = run_prompt(&Fixture::new(small, 0x5eed_0041), &prompt);
    let second = run_prompt(&Fixture::new(large, 0x5eed_0041), &prompt);

    assert_eq!(first, second);
}

/// The reference itself must not be trivially satisfiable: two different
/// prompts must produce different logits, or every parity assertion above would
/// be vacuous.
#[test]
fn different_prompts_produce_different_logits() {
    let fixture = Fixture::new(fixture_config(RopePairing::Interleaved), 0x5eed_0051);
    assert_ne!(
        run_prompt(&fixture, &[1, 2, 3]),
        run_prompt(&fixture, &[3, 2, 1])
    );
}

/// A sanity check on the fixture's own shape: the configuration it declares is
/// the one the crate accepts, and it is the one documented in `common`.
#[test]
fn the_fixture_configuration_is_valid() {
    let config: ModelConfig = fixture_config(RopePairing::Interleaved);
    assert!(config.query_width().unwrap() == config.model_width);
    assert!(config.query_heads_per_group().unwrap() == 2);
    assert!(config.rope_dimensions < config.head_width);
}
