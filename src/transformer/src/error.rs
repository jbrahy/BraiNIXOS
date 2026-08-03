//! The single failure enum for the forward pass.
//!
//! One variant per failure mode, so a refused call can be audited for *why* it
//! was refused rather than merely *that* it was. Deliberately not
//! `#[non_exhaustive]`: callers inside BraiNIX are meant to match exhaustively
//! so that a newly added failure mode is a compile error, not a silent wildcard
//! arm. This mirrors [`brainix_tensor::TensorError`] and `brainix_adt::AdtError`.

use brainix_tensor::TensorError;

/// Every way the transformer can refuse a call.
///
/// A refusal made **before** the first arithmetic operation leaves every
/// caller-supplied buffer untouched. A refusal made after — which can only come
/// from a kernel, and only after the shape agreement of the whole call has
/// already been established — may have written scratch, and may have written
/// key/value rows for the current call into the session cache. It never
/// advances the session's committed position, so those rows are overwritten by
/// the next call and are never read: a refused call contributes nothing to any
/// later token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformerError {
    /// A declared extent is zero. Refused rather than treated as a no-op, for
    /// the reason BXW1 §7.4 rule D4 gives: a zero extent makes the element
    /// product zero, which passes a naive length check and then computes
    /// nothing while reporting success.
    ZeroDimension,

    /// A checked multiplication or addition over the declared shape would have
    /// overflowed `usize` or `u32`. Overflow refuses; it never wraps and never
    /// saturates.
    DimensionOverflow,

    /// `d_model != n_heads × d_head` (BXW1 §5.1).
    ModelWidthDisagreesWithHeads,

    /// `n_kv_heads` exceeds `n_heads`, or does not divide it (BXW1 §5.1).
    ///
    /// The group size `n_heads / n_kv_heads` is what maps a query head to its
    /// key/value head, and a non-integral group size is not an approximation of
    /// grouped-query attention — it is a different model.
    InvalidKeyValueHeadCount,

    /// `rope_dim` is zero, odd, or greater than `d_head` (BXW1 §7.2 rule H17).
    InvalidRopeDimensions,

    /// `arch_id` names an architecture family for which BXW1 §5.6 states no
    /// attention score scale.
    ///
    /// Refused at [`Model::new`](crate::Model::new), before a token is decoded.
    /// The scale is a property of the architecture, and guessing one for an
    /// unrecognized family is the failure class §5.5 and §5.6 exist to
    /// eliminate: it does not crash and does not deny, it changes the sharpness
    /// of every attention distribution, and the engine emits fluent, confident,
    /// wrong text. There is no fallback to `1/√d_head`, because assuming it
    /// silently is the bug.
    UnspecifiedAttentionScale,

    /// `norm_eps` is not a positive, finite, normal `f32`.
    ///
    /// Classified from its bit pattern, following BXW1 §4.7: comparing an
    /// unvalidated float is itself the bug, since `NaN < x` and `NaN > x` are
    /// both false and a float-comparison range check accepts NaN silently.
    InvalidNormalizationEpsilon,

    /// `rope_theta` is not a positive, finite, normal `f32` greater than one.
    InvalidRopeTheta,

    /// `max_seq_len` exceeds the largest position
    /// [`brainix_tensor::MAX_ROPE_POSITION`] admits, so some position the
    /// context permits could not be rotated.
    ///
    /// Refused at configuration time rather than at the token that first
    /// reaches it: a context length the engine cannot actually serve is a
    /// configuration error, not a runtime surprise.
    SequenceLengthExceedsRopeBound,

    /// The supplied layer-weight slice does not have exactly `n_layers`
    /// entries.
    LayerCountDisagreesWithConfig,

    /// A weight matrix's declared or implied shape is not the shape the
    /// hyperparameters require (BXW1 §5.3, §6.2).
    ///
    /// Refused in either direction. A short matrix would truncate; a long one
    /// means the caller and the configuration disagree, and BXW1 §7.5
    /// (`INV-PARSE-004`) is explicit that disagreeing sources fail closed with
    /// no precedence rule.
    WeightShapeMismatch,

    /// A session cache was built for a different model geometry than the one
    /// being run.
    ///
    /// This is the check that stops model A's cache from being handed to model
    /// B — a mismatch that is not a crash but a system that runs and emits
    /// plausible nonsense.
    CacheGeometryMismatch,

    /// The arena has no room left for another session partition.
    SessionArenaExhausted,

    /// The tokens in flight would carry the session past `max_seq_len`.
    ///
    /// The context window is a fixed, build-time-sized region (`INV-MEM`);
    /// there is no growth path and no eviction policy here, so running off the
    /// end is refused and the decision about what to do next belongs to the
    /// caller.
    ContextExhausted,

    /// The workspace slice is shorter than
    /// [`workspace_floats`](crate::workspace_floats) requires, or one of its
    /// views was addressed past its end.
    WorkspaceTooSmall,

    /// A workspace was cut for a different model than the one being run.
    ///
    /// The same class of check as
    /// [`TransformerError::CacheGeometryMismatch`]: a workspace sized for
    /// another model's widths would not crash, it would compute over the wrong
    /// number of elements and report success.
    WorkspaceGeometryMismatch,

    /// More tokens were submitted in one call than the workspace was built for.
    BatchExceedsWorkspace,

    /// A forward call was given no tokens. An empty batch has no next token to
    /// produce, so it is refused rather than reported as success.
    EmptyBatch,

    /// A token identifier is not less than `vocab_size`.
    TokenOutOfRange,

    /// The logits slice is not exactly `vocab_size` long.
    LogitsLengthMismatch,

    /// The sampler scratch slice is not exactly
    /// [`sampler_scratch_floats`](crate::sampler_scratch_floats) long.
    SamplerScratchLengthMismatch,

    /// The sampling temperature is not a positive, finite, normal `f32`.
    ///
    /// Zero is refused rather than silently redirected to greedy: a caller that
    /// wants argmax names [`Sampler::Greedy`](crate::Sampler::Greedy), and a
    /// zero arriving from a client is a request the engine cannot honour as
    /// written.
    InvalidTemperature,

    /// `top_k` is zero, exceeds the vocabulary, or exceeds
    /// [`MAXIMUM_TOP_K`](crate::MAXIMUM_TOP_K).
    InvalidTopK,

    /// The caller-supplied uniform deviate is not in `[0, 1)`.
    ///
    /// Classified with a finiteness test *first*, so no float comparison is
    /// ever performed against a possible NaN.
    InvalidUniformDeviate,

    /// A logit is NaN or ±Inf, so the argmax and the softmax that sampling
    /// rests on have no defined answer.
    ///
    /// This is a model or weight failure surfacing at the only place it can be
    /// caught cheaply, and it is refused rather than turned into an arbitrary
    /// token.
    NonFiniteLogits,

    /// A kernel refused the call. The inner value says which kernel invariant
    /// was violated.
    Kernel(TensorError),
}

impl From<TensorError> for TransformerError {
    fn from(error: TensorError) -> Self {
        Self::Kernel(error)
    }
}
