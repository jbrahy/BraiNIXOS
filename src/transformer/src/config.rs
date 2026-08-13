//! The model hyperparameters, and the derived extents everything else is sized
//! from.
//!
//! Every field here is a BXW1 header field (§5.1). **There is no `Default` and
//! no constant of any kind is compiled in** — not the RoPE base, not the
//! normalization epsilon, not the pairing convention, not the head count. BXW1
//! §5's opening sentence is that the transformer must run with no model
//! constant compiled into it, and a `Default` impl on this struct would be
//! exactly such a constant wearing a different name.
//!
//! # The mapping from a BXW1 header
//!
//! This crate does **not** depend on `brainix_bxw1`. The forward pass is
//! architecture-neutral and host-testable, and coupling it to the blob parser
//! would make it neither. The caller — `modeld`, at the point where a validated
//! blob becomes a servable model — performs the field-for-field copy, and the
//! two structures are deliberately shaped so that copy is mechanical:
//!
//! | BXW1 `Header` | [`ModelConfig`] |
//! |---|---|
//! | `arch_id` | `architecture_id` |
//! | `n_layers` | `layer_count` |
//! | `d_model` | `model_width` |
//! | `n_heads` | `query_head_count` |
//! | `n_kv_heads` | `key_value_head_count` |
//! | `d_head` | `head_width` |
//! | `d_ffn` | `feed_forward_width` |
//! | `vocab_size` | `vocabulary_size` |
//! | `max_seq_len` | `maximum_sequence_length` |
//! | `rope_theta` | `rope_theta` |
//! | `norm_eps` | `normalization_epsilon` |
//! | `rope_dim` | `rope_dimensions` |
//! | `rope_pairing` | `rope_pairing` |
//!
//! `rope_pairing` crosses that boundary as an already-decoded
//! [`RopePairing`] — `brainix_bxw1::RopePairing::to_bxw1` then
//! [`RopePairing::from_bxw1`] — so an unrecognized convention is refused at the
//! blob boundary and is unrepresentable here.

use brainix_tensor::{is_positive_normal, RopePairing, MAX_ROPE_POSITION};

use crate::error::TransformerError;

/// The hyperparameters of one decoder-only model — BXW1 `arch_id = 1`.
///
/// Names are the full-word spellings CODE_STANDARDS Rule 1 requires; the BXW1
/// short names appear in the doc comment of each field so the mapping is
/// unambiguous at a glance.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelConfig {
    /// BXW1 `arch_id`: the architecture family (BXW1 §5.2).
    ///
    /// Carried rather than assumed because it is what determines the attention
    /// score scale (BXW1 §5.6). An `arch_id` for which the format states no
    /// scale is refused by [`Model::new`](crate::Model::new) — see
    /// [`TransformerError::UnspecifiedAttentionScale`].
    pub architecture_id: u32,
    /// BXW1 `n_layers`: transformer blocks.
    pub layer_count: usize,
    /// BXW1 `d_model`: residual-stream width. Must equal
    /// `query_head_count × head_width`.
    pub model_width: usize,
    /// BXW1 `n_heads`: query heads.
    pub query_head_count: usize,
    /// BXW1 `n_kv_heads`: key/value heads.
    ///
    /// Equal to `query_head_count` this is ordinary multi-head attention; equal
    /// to `1` it is multi-query attention. There is one code path for all
    /// three, and no "absent means equal to `n_heads`" default to get wrong.
    pub key_value_head_count: usize,
    /// BXW1 `d_head`: per-head width.
    pub head_width: usize,
    /// BXW1 `d_ffn`: feed-forward inner width.
    pub feed_forward_width: usize,
    /// BXW1 `vocab_size`.
    pub vocabulary_size: usize,
    /// BXW1 `max_seq_len`: the context length the weights support, and the
    /// fixed capacity of every session's key/value cache.
    pub maximum_sequence_length: usize,
    /// BXW1 `rope_theta`: the **base** of `θ_i = rope_theta^(−2i / rope_dim)`.
    pub rope_theta: f32,
    /// BXW1 `norm_eps`: added to the mean square **inside** the root.
    pub normalization_epsilon: f32,
    /// BXW1 `rope_dim`: leading per-head dimensions RoPE rotates. The
    /// remainder passes through unrotated — not zeroed (BXW1 §5.1).
    pub rope_dimensions: usize,
    /// BXW1 `rope_pairing`: which two components form a rotated pair.
    ///
    /// **No default.** Threaded from the header to every [`brainix_tensor::rope`]
    /// call and never assumed, because the two conventions differ by a
    /// permutation of the Q and K projection rows and a runtime that guesses
    /// produces fluent, confident, wrong text on every model converted under
    /// the other one (BXW1 §5.5).
    pub rope_pairing: RopePairing,
}

impl ModelConfig {
    /// `n_heads × d_head` — the width of the concatenated query heads, and of
    /// the attention output before `wo`.
    ///
    /// Equal to `model_width` for every configuration [`Self::validate`]
    /// accepts. It is derived and named separately anyway, because the two are
    /// different *concepts* and the matmul shapes read wrong when one stands in
    /// for the other.
    ///
    /// # Errors
    ///
    /// [`TransformerError::DimensionOverflow`].
    pub const fn query_width(&self) -> Result<usize, TransformerError> {
        checked_product(self.query_head_count, self.head_width)
    }

    /// `n_kv_heads × d_head` — the width of one cached key or value row.
    ///
    /// # Errors
    ///
    /// [`TransformerError::DimensionOverflow`].
    pub const fn key_value_width(&self) -> Result<usize, TransformerError> {
        checked_product(self.key_value_head_count, self.head_width)
    }

    /// `n_heads / n_kv_heads` — how many query heads share one key/value head.
    ///
    /// Exact, because [`Self::validate`] has already refused a non-integral
    /// ratio.
    ///
    /// # Errors
    ///
    /// [`TransformerError::InvalidKeyValueHeadCount`] if the head count is
    /// zero.
    pub const fn query_heads_per_group(&self) -> Result<usize, TransformerError> {
        match self.query_head_count.checked_div(self.key_value_head_count) {
            Some(group) => Ok(group),
            None => Err(TransformerError::InvalidKeyValueHeadCount),
        }
    }

    /// Checks every hyperparameter against BXW1 §5.1 and §7.2.
    ///
    /// Called once, by [`Model::new`](crate::Model::new), before any buffer is
    /// sized and long before any token is decoded.
    ///
    /// # Errors
    ///
    /// One variant per rule; see [`TransformerError`].
    pub fn validate(&self) -> Result<(), TransformerError> {
        self.validate_extents()?;
        self.validate_head_geometry()?;
        self.validate_rope()?;
        self.validate_floats()
    }

    /// Rule D4: no extent may be zero.
    fn validate_extents(&self) -> Result<(), TransformerError> {
        let extents = [
            self.layer_count,
            self.model_width,
            self.query_head_count,
            self.key_value_head_count,
            self.head_width,
            self.feed_forward_width,
            self.vocabulary_size,
            self.maximum_sequence_length,
        ];
        if extents.contains(&0) {
            return Err(TransformerError::ZeroDimension);
        }
        Ok(())
    }

    /// `d_model == n_heads × d_head`, and `n_kv_heads` divides `n_heads`.
    fn validate_head_geometry(&self) -> Result<(), TransformerError> {
        if self.query_width()? != self.model_width {
            return Err(TransformerError::ModelWidthDisagreesWithHeads);
        }
        if self.key_value_head_count > self.query_head_count {
            return Err(TransformerError::InvalidKeyValueHeadCount);
        }
        if !self
            .query_head_count
            .is_multiple_of(self.key_value_head_count)
        {
            return Err(TransformerError::InvalidKeyValueHeadCount);
        }
        Ok(())
    }

    /// Rule H17, plus the accuracy bound the sine/cosine argument reduction
    /// imposes on the largest position the context can reach.
    fn validate_rope(&self) -> Result<(), TransformerError> {
        if self.rope_dimensions == 0
            || !self.rope_dimensions.is_multiple_of(2)
            || self.rope_dimensions > self.head_width
        {
            return Err(TransformerError::InvalidRopeDimensions);
        }
        let highest_position = maximum_position(self.maximum_sequence_length)?;
        if highest_position > MAX_ROPE_POSITION {
            return Err(TransformerError::SequenceLengthExceedsRopeBound);
        }
        Ok(())
    }

    /// ε and θ, by bit pattern before any float comparison (BXW1 §4.7).
    fn validate_floats(&self) -> Result<(), TransformerError> {
        if !is_positive_normal(self.normalization_epsilon) {
            return Err(TransformerError::InvalidNormalizationEpsilon);
        }
        if !is_positive_normal(self.rope_theta) || self.rope_theta <= 1.0 {
            return Err(TransformerError::InvalidRopeTheta);
        }
        Ok(())
    }
}

/// The largest absolute position a context of `length` tokens can reach.
fn maximum_position(length: usize) -> Result<u32, TransformerError> {
    let highest = length
        .checked_sub(1)
        .ok_or(TransformerError::ZeroDimension)?;
    u32::try_from(highest).map_err(|_| TransformerError::SequenceLengthExceedsRopeBound)
}

/// `left × right`, refusing rather than wrapping. `const` so buffer sizes are
/// computable at build time.
pub(crate) const fn checked_product(left: usize, right: usize) -> Result<usize, TransformerError> {
    match left.checked_mul(right) {
        Some(product) => Ok(product),
        // COVERAGE-EXEMPT: `checked_product`/`scale`/`extend` are const fns folded at COMPILE time to compute buffer sizes, so their refusal arms have no runtime execution for llvm-cov to observe. A shape that would overflow is rejected by ModelConfig::validate before any of these is reached at runtime.
        None => Err(TransformerError::DimensionOverflow),
    }
}

/// `accumulated × factor`, propagating an earlier refusal. The `const` fold
/// every build-time size in this crate is written with.
pub(crate) const fn scale(
    accumulated: Result<usize, TransformerError>,
    factor: usize,
) -> Result<usize, TransformerError> {
    match accumulated {
        Ok(value) => checked_product(value, factor),
        // COVERAGE-EXEMPT: `checked_product`/`scale`/`extend` are const fns folded at COMPILE time to compute buffer sizes, so their refusal arms have no runtime execution for llvm-cov to observe. A shape that would overflow is rejected by ModelConfig::validate before any of these is reached at runtime.
        Err(error) => Err(error),
    }
}

/// `accumulated + addend`, propagating an earlier refusal.
pub(crate) const fn extend(
    accumulated: Result<usize, TransformerError>,
    addend: Result<usize, TransformerError>,
) -> Result<usize, TransformerError> {
    match (accumulated, addend) {
        (Ok(value), Ok(other)) => match value.checked_add(other) {
            Some(total) => Ok(total),
            // COVERAGE-EXEMPT: `checked_product`/`scale`/`extend` are const fns folded at COMPILE time to compute buffer sizes, so their refusal arms have no runtime execution for llvm-cov to observe. A shape that would overflow is rejected by ModelConfig::validate before any of these is reached at runtime.
            None => Err(TransformerError::DimensionOverflow),
        },
        // COVERAGE-EXEMPT: `checked_product`/`scale`/`extend` are const fns folded at COMPILE time to compute buffer sizes, so their refusal arms have no runtime execution for llvm-cov to observe. A shape that would overflow is rejected by ModelConfig::validate before any of these is reached at runtime.
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}
