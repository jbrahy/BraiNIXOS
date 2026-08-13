//! Every agreement the forward pass refuses, and the arena's isolation
//! arithmetic.
//!
//! Each of these is a way a caller can be wrong. None of them is a panic, none
//! is a truncation, and each names the rule it broke.

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
    TransformerError, Workspace,
};
use common::{fixture_config, Fixture};

const MAXIMUM_BATCH: usize = 4;

/// Everything a forward call needs, owned by the test.
struct Harness {
    config: ModelConfig,
    workspace_storage: Vec<f32>,
    cache_storage: Vec<f32>,
    logits: Vec<f32>,
}

impl Harness {
    fn new(config: ModelConfig, sessions: usize) -> Self {
        Self {
            config,
            workspace_storage: vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()],
            cache_storage: vec![0.0_f32; session_cache_floats(&config, sessions).unwrap()],
            logits: vec![0.0_f32; config.vocabulary_size],
        }
    }
}

// ------------------------------------------------------- configuration rules

#[test]
fn a_zero_extent_is_refused() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.layer_count = 0;
    assert_eq!(config.validate(), Err(TransformerError::ZeroDimension));
}

#[test]
fn the_model_width_must_equal_the_head_product() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.model_width = 33;
    assert_eq!(
        config.validate(),
        Err(TransformerError::ModelWidthDisagreesWithHeads)
    );
}

#[test]
fn the_key_value_head_count_must_divide_the_query_head_count() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.key_value_head_count = 3;
    assert_eq!(
        config.validate(),
        Err(TransformerError::InvalidKeyValueHeadCount)
    );
    config.key_value_head_count = 8;
    assert_eq!(
        config.validate(),
        Err(TransformerError::InvalidKeyValueHeadCount)
    );
}

#[test]
fn the_rope_dimension_count_must_be_even_and_within_the_head() {
    let mut config = fixture_config(RopePairing::Interleaved);
    for rope_dimensions in [0_usize, 3, 9] {
        config.rope_dimensions = rope_dimensions;
        assert_eq!(
            config.validate(),
            Err(TransformerError::InvalidRopeDimensions),
            "rope_dim {rope_dimensions} was accepted"
        );
    }
}

#[test]
fn the_epsilon_and_theta_are_classified_by_bit_pattern() {
    let mut config = fixture_config(RopePairing::Interleaved);
    for epsilon in [0.0_f32, -1.0e-5, f32::NAN, f32::INFINITY] {
        config.normalization_epsilon = epsilon;
        assert_eq!(
            config.validate(),
            Err(TransformerError::InvalidNormalizationEpsilon)
        );
    }
    let mut config = fixture_config(RopePairing::Interleaved);
    for theta in [0.0_f32, 1.0, -1.0e4, f32::NAN] {
        config.rope_theta = theta;
        assert_eq!(config.validate(), Err(TransformerError::InvalidRopeTheta));
    }
}

#[test]
fn an_architecture_with_no_specified_attention_scale_is_refused() {
    // BXW1 §5.6: the attention score scale is determined by `arch_id`, and the
    // format states one only for `arch_id = 1`. An architecture whose
    // convention is unspecified is refused at construction rather than served
    // with a guessed scale — a wrong scale does not crash, it changes the
    // sharpness of every attention distribution and the model goes on emitting
    // fluent, confident, wrong text.
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0021);
    let layers = fixture.layer_views();

    for architecture_id in [0_u32, 2, 3, u32::MAX] {
        let mut other = config;
        other.architecture_id = architecture_id;
        assert_eq!(
            Model::new(other, fixture.weights(&layers)).unwrap_err(),
            TransformerError::UnspecifiedAttentionScale,
            "arch_id {architecture_id} was accepted"
        );
    }
    // `arch_id = 1` is the one the format specifies, and it must still build —
    // an over-broad refusal would hide behind the loop above.
    assert!(Model::new(config, fixture.weights(&layers)).is_ok());
}

// ---------------------------------------------------------------- weight set

#[test]
fn a_missing_layer_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0001);
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers[..1]);
    assert_eq!(
        Model::new(config, weights).unwrap_err(),
        TransformerError::LayerCountDisagreesWithConfig
    );
}

#[test]
fn a_weight_matrix_of_the_wrong_shape_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let mut wider = config;
    wider.feed_forward_width = 96;
    // The fixture is built for `config`, so its feed-forward matrices are the
    // wrong shape for `wider`.
    let fixture = Fixture::new(config, 0x900d_0002);
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    assert_eq!(
        Model::new(wider, weights).unwrap_err(),
        TransformerError::WeightShapeMismatch
    );
}

#[test]
fn a_truncated_norm_vector_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let mut fixture = Fixture::new(config, 0x900d_0003);
    fixture.final_norm.pop();
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    assert_eq!(
        Model::new(config, weights).unwrap_err(),
        TransformerError::WeightShapeMismatch
    );
}

// ------------------------------------------------------------- per-call rules

/// Runs `tokens` against a fresh session, returning whatever the call returns.
fn forward_once(
    harness: &mut Harness,
    fixture: &Fixture,
    tokens: &[u32],
) -> Result<(), TransformerError> {
    let config = harness.config;
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();
    let mut workspace =
        Workspace::new(&mut harness.workspace_storage, &config, MAXIMUM_BATCH).unwrap();
    let mut arena = KeyValueArena::new(
        &mut harness.cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    model.forward(&mut workspace, &mut session, tokens, &mut harness.logits)
}

#[test]
fn an_empty_batch_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0011);
    let mut harness = Harness::new(config, 1);
    assert_eq!(
        forward_once(&mut harness, &fixture, &[]),
        Err(TransformerError::EmptyBatch)
    );
}

#[test]
fn a_batch_larger_than_the_workspace_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0012);
    let mut harness = Harness::new(config, 1);
    let tokens = [1_u32, 2, 3, 4, 5];
    assert_eq!(
        forward_once(&mut harness, &fixture, &tokens),
        Err(TransformerError::BatchExceedsWorkspace)
    );
}

#[test]
fn a_token_at_or_past_the_vocabulary_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0013);
    let mut harness = Harness::new(config, 1);
    let tokens = [1_u32, config.vocabulary_size as u32];
    assert_eq!(
        forward_once(&mut harness, &fixture, &tokens),
        Err(TransformerError::TokenOutOfRange)
    );
}

#[test]
fn a_logits_slice_of_the_wrong_length_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0014);
    let mut harness = Harness::new(config, 1);
    harness.logits.pop();
    assert_eq!(
        forward_once(&mut harness, &fixture, &[1]),
        Err(TransformerError::LogitsLengthMismatch)
    );
}

#[test]
fn running_past_the_context_is_refused_and_leaves_the_session_intact() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.maximum_sequence_length = 3;
    let fixture = Fixture::new(config, 0x900d_0015);
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
        .forward(&mut workspace, &mut session, &[1, 2], &mut logits)
        .unwrap();
    assert_eq!(session.position(), 2);
    assert_eq!(
        model.forward(&mut workspace, &mut session, &[3, 4], &mut logits),
        Err(TransformerError::ContextExhausted)
    );
    // The refused call did not move the clock, so the remaining slot is still
    // available and the session is still usable.
    assert_eq!(session.position(), 2);
    model
        .forward(&mut workspace, &mut session, &[3], &mut logits)
        .unwrap();
    assert_eq!(session.position(), 3);
}

#[test]
fn a_cache_cut_for_another_geometry_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let mut other = config;
    other.layer_count = 3;
    let fixture = Fixture::new(config, 0x900d_0016);
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&config, MAXIMUM_BATCH).unwrap()];
    let mut workspace = Workspace::new(&mut workspace_storage, &config, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&other, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&other).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    let mut logits = vec![0.0_f32; config.vocabulary_size];

    assert_eq!(
        model.forward(&mut workspace, &mut session, &[1], &mut logits),
        Err(TransformerError::CacheGeometryMismatch)
    );
}

// -------------------------------------------------------------- arena rules

#[test]
fn the_arena_issues_exactly_as_many_sessions_as_it_was_sized_for() {
    let config = fixture_config(RopePairing::Interleaved);
    let geometry = CacheGeometry::for_config(&config).unwrap();
    let mut storage = vec![0.0_f32; session_cache_floats(&config, 3).unwrap()];
    let mut arena = KeyValueArena::new(&mut storage, geometry).unwrap();

    assert_eq!(arena.sessions_remaining().unwrap(), 3);
    let _first = arena.issue_session().unwrap();
    assert_eq!(arena.sessions_remaining().unwrap(), 2);
    let _second = arena.issue_session().unwrap();
    let _third = arena.issue_session().unwrap();
    assert_eq!(arena.sessions_remaining().unwrap(), 0);
    assert_eq!(
        arena.issue_session().unwrap_err(),
        TransformerError::SessionArenaExhausted
    );
}

#[test]
fn an_arena_too_small_for_one_session_issues_none() {
    let config = fixture_config(RopePairing::Interleaved);
    let geometry = CacheGeometry::for_config(&config).unwrap();
    let mut storage = vec![0.0_f32; geometry.floats_per_session().unwrap() - 1];
    let mut arena = KeyValueArena::new(&mut storage, geometry).unwrap();
    assert_eq!(arena.sessions_remaining().unwrap(), 0);
    assert_eq!(
        arena.issue_session().unwrap_err(),
        TransformerError::SessionArenaExhausted
    );
}

#[test]
fn the_session_size_is_the_documented_product() {
    let config = fixture_config(RopePairing::Interleaved);
    let geometry = CacheGeometry::for_config(&config).unwrap();
    // n_layers × 2 planes × max_seq_len × (n_kv_heads × d_head)
    assert_eq!(geometry.floats_per_session().unwrap(), 2 * 2 * 16 * 16);
    assert_eq!(
        session_cache_floats(&config, 5).unwrap(),
        5 * 2 * 2 * 16 * 16
    );
}

// ----------------------------------------------------------- workspace rules

#[test]
fn a_short_workspace_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let required = workspace_floats(&config, MAXIMUM_BATCH).unwrap();
    let mut storage = vec![0.0_f32; required - 1];
    assert_eq!(
        Workspace::new(&mut storage, &config, MAXIMUM_BATCH).unwrap_err(),
        TransformerError::WorkspaceTooSmall
    );
}

#[test]
fn a_workspace_exactly_the_required_size_is_accepted() {
    let config = fixture_config(RopePairing::Interleaved);
    let required = workspace_floats(&config, MAXIMUM_BATCH).unwrap();
    let mut storage = vec![0.0_f32; required];
    assert!(Workspace::new(&mut storage, &config, MAXIMUM_BATCH).is_ok());
}

#[test]
fn a_zero_batch_ceiling_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let mut storage = vec![0.0_f32; 4096];
    assert_eq!(
        Workspace::new(&mut storage, &config, 0).unwrap_err(),
        TransformerError::ZeroDimension
    );
}

#[test]
fn the_workspace_size_is_the_documented_sum() {
    let config = fixture_config(RopePairing::Interleaved);
    // batch × (4·d_model + 3·q_width + 3·kv_width + 3·d_ffn) + 2·max_seq_len
    let expected = MAXIMUM_BATCH * (4 * 32 + 3 * 32 + 3 * 16 + 3 * 64) + 2 * 16;
    assert_eq!(workspace_floats(&config, MAXIMUM_BATCH).unwrap(), expected);
}

#[test]
fn a_workspace_built_for_another_model_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let mut other = config;
    other.rope_pairing = RopePairing::HalfSplit;
    let fixture = Fixture::new(config, 0x900d_0021);
    let layers = fixture.layer_views();
    let weights = fixture.weights(&layers);
    let model = Model::new(config, weights).unwrap();

    let mut workspace_storage = vec![0.0_f32; workspace_floats(&other, MAXIMUM_BATCH).unwrap()];
    let mut workspace = Workspace::new(&mut workspace_storage, &other, MAXIMUM_BATCH).unwrap();
    let mut cache_storage = vec![0.0_f32; session_cache_floats(&config, 1).unwrap()];
    let mut arena = KeyValueArena::new(
        &mut cache_storage,
        CacheGeometry::for_config(&config).unwrap(),
    )
    .unwrap();
    let mut session = arena.issue_session().unwrap();
    let mut logits = vec![0.0_f32; config.vocabulary_size];

    assert_eq!(
        model.forward(&mut workspace, &mut session, &[1], &mut logits),
        Err(TransformerError::WorkspaceGeometryMismatch)
    );
}

// ------------------------------------------- deny paths found by coverage
//
// Every config hyperparameter arrives from a BXW1 header, which is hostile
// input. These arms are what stop a malformed header from being turned into a
// buffer size, so an unexecuted one is an untested refusal.

#[test]
fn a_zero_key_value_head_count_is_refused_rather_than_dividing_by_zero() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.key_value_head_count = 0;

    assert_eq!(
        config.query_heads_per_group(),
        Err(TransformerError::InvalidKeyValueHeadCount),
        "grouped-query attention divides by this; zero must refuse, not trap"
    );
}

#[test]
fn a_valid_key_value_head_count_reports_the_group_size() {
    let config = fixture_config(RopePairing::Interleaved);
    assert_eq!(
        config.query_heads_per_group(),
        Ok(2),
        "4 query heads / 2 kv heads"
    );
}

#[test]
fn a_sequence_length_past_the_rope_bound_is_refused() {
    let mut config = fixture_config(RopePairing::Interleaved);
    config.maximum_sequence_length = usize::MAX;

    let error = config
        .validate()
        .expect_err("an unbounded sequence must deny");
    assert!(
        matches!(
            error,
            TransformerError::SequenceLengthExceedsRopeBound | TransformerError::DimensionOverflow
        ),
        "got {error:?}"
    );
}

#[test]
fn the_model_reports_back_the_config_and_geometry_it_was_built_with() {
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0031);
    let layers = fixture.layer_views();
    let model = Model::new(config, fixture.weights(&layers)).expect("the fixture is valid");

    // A caller sizes its own cache and workspace from these, so a model that
    // misreported them would have every downstream buffer sized wrongly.
    assert_eq!(model.config().layer_count, config.layer_count);
    assert_eq!(model.config().model_width, config.model_width);
    assert_eq!(
        model.cache_geometry(),
        CacheGeometry::for_config(&config).expect("the fixture is valid")
    );
}

#[test]
fn a_tensor_kernel_error_is_carried_through_rather_than_flattened() {
    // TransformerError::Kernel is how a tensor-layer refusal reaches the
    // caller. Flattening it would lose which kernel refused and why.
    let kernel = TransformerError::from(brainix_tensor::TensorError::ZeroDimension);
    assert_eq!(
        kernel,
        TransformerError::Kernel(brainix_tensor::TensorError::ZeroDimension)
    );
}

#[test]
fn a_sequence_length_that_fits_a_u32_but_passes_the_rope_bound_is_refused() {
    // Distinct from the usize::MAX case, which overflows earlier. This one is
    // representable and still past what the RoPE tables cover, so it must be
    // caught by the bound rather than silently producing garbage angles.
    let mut config = fixture_config(RopePairing::Interleaved);
    config.maximum_sequence_length = brainix_tensor::MAX_ROPE_POSITION as usize + 2;

    assert_eq!(
        config.validate(),
        Err(TransformerError::SequenceLengthExceedsRopeBound)
    );
}

#[test]
fn a_token_embedding_table_of_the_wrong_size_is_refused() {
    // The embedding table's length is vocabulary_size × model_width. A header
    // that disagrees with its own payload must deny rather than index into
    // whatever follows.
    let config = fixture_config(RopePairing::Interleaved);
    let fixture = Fixture::new(config, 0x900d_0041);
    let layers = fixture.layer_views();

    let mut shrunk = config;
    shrunk.vocabulary_size = config.vocabulary_size + 1;

    assert_eq!(
        Model::new(shrunk, fixture.weights(&layers)).unwrap_err(),
        TransformerError::WeightShapeMismatch,
        "a vocabulary the embedding table cannot cover must deny"
    );
}

#[test]
fn a_cache_arena_with_any_zero_dimension_is_refused() {
    let config = fixture_config(RopePairing::Interleaved);
    let sound = CacheGeometry::for_config(&config).expect("the fixture is valid");
    let mut storage = vec![0.0_f32; session_cache_floats(&config, MAXIMUM_BATCH).expect("sizes")];

    // Each dimension independently: a zero in any of the three makes every
    // derived offset degenerate, so the arena must refuse rather than hand back
    // slices that overlap.
    for zeroed in ["layer_count", "maximum_sequence_length", "key_value_width"] {
        let mut geometry = sound;
        match zeroed {
            "layer_count" => geometry.layer_count = 0,
            "maximum_sequence_length" => geometry.maximum_sequence_length = 0,
            _ => geometry.key_value_width = 0,
        }
        assert_eq!(
            KeyValueArena::new(&mut storage, geometry).err(),
            Some(TransformerError::ZeroDimension),
            "a zero {zeroed} was accepted"
        );
    }
}
