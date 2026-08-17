//! The forward pass: embedding, `n_layers` blocks, final norm, logits.
//!
//! ```text
//! h  = embedding[token]
//! for each layer:
//!     h += wo · attention( RoPE(wq · rmsnorm(h)), RoPE(wk · rmsnorm(h)), wv · rmsnorm(h) )
//!     h += w2 · ( SiLU(w1 · rmsnorm(h)) ⊙ (w3 · rmsnorm(h)) )
//! logits = W_out · rmsnorm(h)
//! ```
//!
//! Pre-normalization throughout: each block normalizes a *copy* of the residual
//! stream and adds its output back to the unnormalized stream. Post-norm — where
//! the normalization is applied to the sum — is the other convention, it also
//! runs, and it produces a different model. BXW1 §5.2 pins `arch_id = 1` as
//! pre-normalization.
//!
//! # One path for prefill and for decode
//!
//! [`Model::forward`] takes a slice of tokens. `n` of them is a prefill;
//! one of them is a decode step. There is no second implementation, so there is
//! no second implementation to disagree with the first — every projection is
//! one matmul with `n_tokens = n`, every RoPE application is per token, and
//! attention runs per (token, head) with the causal bound taken from the token's
//! absolute position. Feeding a prompt in one call and feeding it one token at a
//! time are therefore the same arithmetic in the same order, and
//! `tests/parity.rs` asserts they agree bit for bit.
//!
//! # Only the last position's logits are produced
//!
//! The final norm and the output projection run on **one** row: the last token's
//! hidden state. Autoregressive decode never needs the others, and materializing
//! `n_tokens × vocab_size` floats would make the largest buffer in the system
//! the one nothing reads.
//!
//! # A refused call cannot poison a session
//!
//! Key and value rows for the tokens in flight are written into the cache before
//! attention runs, but the session's committed position advances only after the
//! whole call has succeeded. A call that fails leaves rows at positions the
//! session does not consider written, and the next call overwrites them. No
//! later token can read them.

use brainix_tensor::{rmsnorm, rope, swiglu, MatMulShape, RopeParams};

use crate::attention::{attend, AttentionShape};
use crate::cache::{CacheGeometry, SessionCache};
use crate::config::{checked_product, ModelConfig};
use crate::error::TransformerError;
use crate::math::attention_scale;
use crate::sampling::SamplingRequest;
use crate::slices::{add_into, copy_into, prefix, prefix_mut, row, span};
use crate::weights::{LayerWeights, ModelWeights};
use crate::workspace::Workspace;

/// A validated model: hyperparameters, borrowed weights, and the one derived
/// constant the forward pass needs.
///
/// Construction is the validation. Holding one of these means every
/// hyperparameter passed BXW1 §5.1's bounds and every weight matrix has the
/// shape §5.3 requires, so nothing inside the forward pass has to re-establish
/// either.
#[derive(Debug, Clone, Copy)]
pub struct Model<'a> {
    config: ModelConfig,
    weights: ModelWeights<'a>,
    /// The attention score scale BXW1 §5.6 assigns to the configuration's
    /// `arch_id` — `1/√d_head` for `arch_id = 1` — derived once at construction
    /// rather than once per score.
    scale: f32,
    /// The cache shape this model requires, computed once so every call
    /// compares rather than derives.
    geometry: CacheGeometry,
}

impl<'a> Model<'a> {
    /// Validates a configuration and its weights, and binds them together.
    ///
    /// # Errors
    ///
    /// Whatever [`ModelConfig::validate`] or [`ModelWeights::validate`] refuse,
    /// plus [`TransformerError::UnspecifiedAttentionScale`] when BXW1 §5.6
    /// states no attention score scale for the configuration's `arch_id`.
    pub fn new(config: ModelConfig, weights: ModelWeights<'a>) -> Result<Self, TransformerError> {
        config.validate()?;
        weights.validate(&config)?;
        Ok(Self {
            config,
            weights,
            scale: attention_scale(config.architecture_id, config.head_width)?,
            geometry: CacheGeometry::for_config(&config)?,
        })
    }

    /// The validated hyperparameters.
    #[must_use]
    pub const fn config(&self) -> &ModelConfig {
        &self.config
    }

    /// The cache geometry a session for this model must have been cut for.
    #[must_use]
    pub const fn cache_geometry(&self) -> CacheGeometry {
        self.geometry
    }

    /// Runs `tokens` through the model, appending them to `cache`'s context and
    /// writing the **last** token's logits.
    ///
    /// `logits` must be exactly `vocab_size` long. The session's position
    /// advances by `tokens.len()` on success and not at all on failure.
    ///
    /// # Errors
    ///
    /// Every agreement is established before the first arithmetic operation:
    /// [`TransformerError::EmptyBatch`],
    /// [`TransformerError::BatchExceedsWorkspace`],
    /// [`TransformerError::CacheGeometryMismatch`],
    /// [`TransformerError::ContextExhausted`],
    /// [`TransformerError::TokenOutOfRange`],
    /// [`TransformerError::LogitsLengthMismatch`], or
    /// [`TransformerError::WorkspaceGeometryMismatch`]. Past that point only
    /// [`TransformerError::Kernel`] is reachable.
    pub fn forward(
        &self,
        workspace: &mut Workspace<'_>,
        cache: &mut SessionCache<'_>,
        tokens: &[u32],
        logits: &mut [f32],
    ) -> Result<(), TransformerError> {
        let start = self.admit(workspace, cache, tokens, logits)?;
        self.embed(workspace, tokens)?;
        for (index, layer) in self.weights.layers.iter().enumerate() {
            self.run_layer(workspace, cache, layer, index, start, tokens.len())?;
        }
        self.project_logits(workspace, tokens.len(), logits)?;
        cache.commit(tokens.len())
    }

    /// One step of the decode loop: run `tokens`, then choose the next token.
    ///
    /// This is [`Self::forward`] followed by [`SamplingRequest::choose`], and it
    /// exists so the
    /// loop a caller writes is a loop over one call rather than over two that
    /// must be kept in the right order:
    ///
    /// ```text
    /// let mut token = model.next_token(…, prompt, …)?;      // prefill
    /// while !finished {
    ///     token = model.next_token(…, &[token], …)?;        // one step
    /// }
    /// ```
    ///
    /// Both calls reuse the same session, so the second and later steps read
    /// the key/value rows the first wrote and recompute nothing.
    ///
    /// The deviate inside `request` is the caller's; this crate never reaches
    /// for entropy (see [`crate::sample`]).
    ///
    /// # Errors
    ///
    /// Whatever [`Self::forward`] or [`SamplingRequest::choose`] refuse.
    pub fn next_token(
        &self,
        workspace: &mut Workspace<'_>,
        cache: &mut SessionCache<'_>,
        tokens: &[u32],
        logits: &mut [f32],
        request: &mut SamplingRequest<'_>,
    ) -> Result<u32, TransformerError> {
        self.forward(workspace, cache, tokens, logits)?;
        request.choose(logits)
    }

    /// Establishes every shape and bound agreement, returning the absolute
    /// position of the batch's first token.
    fn admit(
        &self,
        workspace: &Workspace<'_>,
        cache: &SessionCache<'_>,
        tokens: &[u32],
        logits: &[f32],
    ) -> Result<usize, TransformerError> {
        self.admit_shapes(workspace, cache, logits)?;
        self.admit_batch(workspace, cache, tokens)?;
        Ok(cache.position())
    }

    fn admit_shapes(
        &self,
        workspace: &Workspace<'_>,
        cache: &SessionCache<'_>,
        logits: &[f32],
    ) -> Result<(), TransformerError> {
        if workspace.config != self.config {
            return Err(TransformerError::WorkspaceGeometryMismatch);
        }
        if cache.geometry() != self.geometry {
            return Err(TransformerError::CacheGeometryMismatch);
        }
        if logits.len() != self.config.vocabulary_size {
            return Err(TransformerError::LogitsLengthMismatch);
        }
        Ok(())
    }

    fn admit_batch(
        &self,
        workspace: &Workspace<'_>,
        cache: &SessionCache<'_>,
        tokens: &[u32],
    ) -> Result<(), TransformerError> {
        if tokens.is_empty() {
            return Err(TransformerError::EmptyBatch);
        }
        if tokens.len() > workspace.maximum_batch_tokens {
            return Err(TransformerError::BatchExceedsWorkspace);
        }
        cache.position_after(tokens.len())?;
        self.admit_token_range(tokens)
    }

    fn admit_token_range(&self, tokens: &[u32]) -> Result<(), TransformerError> {
        for token in tokens {
            let index = usize::try_from(*token).map_err(|_| TransformerError::TokenOutOfRange)?;
            if index >= self.config.vocabulary_size {
                return Err(TransformerError::TokenOutOfRange);
            }
        }
        Ok(())
    }

    /// Copies one embedding row per token into the residual stream.
    fn embed(&self, workspace: &mut Workspace<'_>, tokens: &[u32]) -> Result<(), TransformerError> {
        let width = self.config.model_width;
        for (token, destination) in tokens.iter().zip(workspace.hidden.chunks_exact_mut(width)) {
            let index = usize::try_from(*token).map_err(|_| TransformerError::TokenOutOfRange)?;
            let start = checked_product(index, width)?;
            let end = start
                .checked_add(width)
                .ok_or(TransformerError::DimensionOverflow)?;
            let row = self
                .weights
                .token_embeddings
                .get(start..end)
                .ok_or(TransformerError::TokenOutOfRange)?;
            copy_into(row, destination);
        }
        Ok(())
    }

    fn run_layer(
        &self,
        workspace: &mut Workspace<'_>,
        cache: &mut SessionCache<'_>,
        layer: &LayerWeights<'_>,
        index: usize,
        start: usize,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        self.attention_block(workspace, cache, layer, index, start, token_count)?;
        self.feed_forward_block(workspace, layer, token_count)
    }

    /// RMSNorm, QKV, RoPE, cache write, attention, `wo`, residual.
    fn attention_block(
        &self,
        workspace: &mut Workspace<'_>,
        cache: &mut SessionCache<'_>,
        layer: &LayerWeights<'_>,
        index: usize,
        start: usize,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let span = checked_product(token_count, self.config.model_width)?;
        rmsnorm(
            prefix(workspace.hidden, span)?,
            layer.attention_norm,
            self.config.normalization_epsilon,
            prefix_mut(workspace.normed, span)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        self.project_query_key_value(workspace, layer, token_count)?;
        self.rotate(workspace, start, token_count)?;
        self.store_batch(workspace, cache, index, start, token_count)?;
        attend(
            workspace,
            cache,
            index,
            start,
            token_count,
            self.attention_shape()?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        self.project_attention_output(workspace, layer, token_count)?;
        add_into(
            prefix(workspace.projected, span)?,
            prefix_mut(workspace.hidden, span)?,
        )
    }

    fn project_query_key_value(
        &self,
        workspace: &mut Workspace<'_>,
        layer: &LayerWeights<'_>,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let query_width = self.config.query_width()?;
        let key_value_width = self.config.key_value_width()?;
        let span = checked_product(token_count, self.config.model_width)?;
        let normed = prefix(workspace.normed, span)?;
        let shape = self.projection_shape(token_count, self.config.model_width, query_width);
        layer.query_projection.project(
            shape,
            normed,
            workspace.quant_scratch,
            prefix_mut(workspace.query, checked_product(token_count, query_width)?)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        let shape = self.projection_shape(token_count, self.config.model_width, key_value_width);
        let key_span = checked_product(token_count, key_value_width)?;
        layer
            .key_projection
            .project(
            shape, normed, workspace.quant_scratch, prefix_mut(workspace.key, key_span)?)?;
        layer
            .value_projection
            .project(
            shape, normed, workspace.quant_scratch, prefix_mut(workspace.value, key_span)?)
    }

    /// RoPE over the query and the key of every token in the batch.
    ///
    /// Values are not rotated: RoPE encodes *where* a token is for the purpose
    /// of matching, and the value is what is retrieved once the match is made.
    fn rotate(
        &self,
        workspace: &mut Workspace<'_>,
        start: usize,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let query_width = self.config.query_width()?;
        let key_value_width = self.config.key_value_width()?;
        for token in 0..token_count {
            let params = self.rope_params(start, token)?;
            rotate_row(
                workspace.query,
                workspace.query_rotated,
                token,
                query_width,
                &params,
                // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
            )?;
            rotate_row(
                workspace.key,
                workspace.key_rotated,
                token,
                key_value_width,
                &params,
                // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
            )?;
        }
        Ok(())
    }

    /// The rotation parameters for the batch's `token`-th entry.
    ///
    /// Every field comes from the model header. `pairing` in particular is
    /// threaded from BXW1's `rope_pairing` and never assumed — see
    /// [`ModelConfig::rope_pairing`].
    fn rope_params(&self, start: usize, token: usize) -> Result<RopeParams, TransformerError> {
        let absolute = start
            .checked_add(token)
            .ok_or(TransformerError::DimensionOverflow)?;
        let position = u32::try_from(absolute).map_err(|_| TransformerError::ContextExhausted)?;
        Ok(RopeParams {
            d_head: self.config.head_width,
            rope_dim: self.config.rope_dimensions,
            base: self.config.rope_theta,
            pairing: self.config.rope_pairing,
            position,
        })
    }

    /// Writes each token's rotated key and unrotated value into the cache.
    fn store_batch(
        &self,
        workspace: &Workspace<'_>,
        cache: &mut SessionCache<'_>,
        layer: usize,
        start: usize,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let width = self.config.key_value_width()?;
        for token in 0..token_count {
            let position = start
                .checked_add(token)
                .ok_or(TransformerError::DimensionOverflow)?;
            let key = row(workspace.key_rotated, token, width)?;
            let value = row(workspace.value, token, width)?;
            cache.store(layer, position, key, value)?;
        }
        Ok(())
    }

    fn project_attention_output(
        &self,
        workspace: &mut Workspace<'_>,
        layer: &LayerWeights<'_>,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let query_width = self.config.query_width()?;
        let shape = self.projection_shape(token_count, query_width, self.config.model_width);
        let attention = prefix(
            workspace.attention,
            checked_product(token_count, query_width)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        let span = checked_product(token_count, self.config.model_width)?;
        layer.attention_output_projection.project(
            shape,
            attention,
            workspace.quant_scratch,
            prefix_mut(workspace.projected, span)?,
        )
    }

    /// RMSNorm, gate and up projections, SwiGLU, down projection, residual.
    fn feed_forward_block(
        &self,
        workspace: &mut Workspace<'_>,
        layer: &LayerWeights<'_>,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let span = checked_product(token_count, self.config.model_width)?;
        rmsnorm(
            prefix(workspace.hidden, span)?,
            layer.feed_forward_norm,
            self.config.normalization_epsilon,
            prefix_mut(workspace.normed, span)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        self.project_branches(workspace, layer, token_count)?;
        self.project_down(workspace, layer, token_count)?;
        add_into(
            prefix(workspace.feed_forward, span)?,
            prefix_mut(workspace.hidden, span)?,
        )
    }

    /// `gate = w1 · normed`, `up = w3 · normed`, `activated = SiLU(gate) ⊙ up`.
    fn project_branches(
        &self,
        workspace: &mut Workspace<'_>,
        layer: &LayerWeights<'_>,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let inner = checked_product(token_count, self.config.feed_forward_width)?;
        let span = checked_product(token_count, self.config.model_width)?;
        let shape = self.projection_shape(
            token_count,
            self.config.model_width,
            self.config.feed_forward_width,
        );
        layer.gate_projection.project(
            shape,
            prefix(workspace.normed, span)?,
            workspace.quant_scratch,
            prefix_mut(workspace.gate, inner)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        layer.up_projection.project(
            shape,
            prefix(workspace.normed, span)?,
            workspace.quant_scratch,
            prefix_mut(workspace.up, inner)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        swiglu(
            prefix(workspace.gate, inner)?,
            prefix(workspace.up, inner)?,
            prefix_mut(workspace.activated, inner)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        Ok(())
    }

    fn project_down(
        &self,
        workspace: &mut Workspace<'_>,
        layer: &LayerWeights<'_>,
        token_count: usize,
    ) -> Result<(), TransformerError> {
        let inner = checked_product(token_count, self.config.feed_forward_width)?;
        let span = checked_product(token_count, self.config.model_width)?;
        let shape = self.projection_shape(
            token_count,
            self.config.feed_forward_width,
            self.config.model_width,
        );
        layer.down_projection.project(
            shape,
            prefix(workspace.activated, inner)?,
            workspace.quant_scratch,
            prefix_mut(workspace.feed_forward, span)?,
        )
    }

    /// Final norm on the last token's hidden state, then the output
    /// projection.
    fn project_logits(
        &self,
        workspace: &mut Workspace<'_>,
        token_count: usize,
        logits: &mut [f32],
    ) -> Result<(), TransformerError> {
        let last = token_count
            .checked_sub(1)
            .ok_or(TransformerError::EmptyBatch)?;
        let width = self.config.model_width;
        rmsnorm(
            row(workspace.hidden, last, width)?,
            self.weights.final_norm,
            self.config.normalization_epsilon,
            prefix_mut(workspace.normed, width)?,
            // COVERAGE-EXEMPT: the tensor kernels cannot refuse here: Model::new validated the config, and every slice handed to them is sized from that same validated geometry. The `?` is what keeps a kernel refusal from being ignored if a future shape reaches this path unvalidated.
        )?;
        let shape = self.projection_shape(1, width, self.config.vocabulary_size);
        self.weights
            .logit_matrix()
            .project(
            shape, prefix(workspace.normed, width)?, workspace.quant_scratch, logits)
    }

    const fn projection_shape(
        &self,
        token_count: usize,
        in_features: usize,
        out_features: usize,
    ) -> MatMulShape {
        MatMulShape {
            n_tokens: token_count,
            n_in: in_features,
            n_out: out_features,
        }
    }

    fn attention_shape(&self) -> Result<AttentionShape, TransformerError> {
        Ok(AttentionShape {
            head_width: self.config.head_width,
            query_width: self.config.query_width()?,
            key_value_width: self.config.key_value_width()?,
            query_head_count: self.config.query_head_count,
            query_heads_per_group: self.config.query_heads_per_group()?,
            scale: self.scale,
        })
    }
}

/// Rotates one token's row of `source` into the same row of `destination`.
fn rotate_row(
    source: &[f32],
    destination: &mut [f32],
    index: usize,
    width: usize,
    params: &RopeParams,
) -> Result<(), TransformerError> {
    let (start, end) = span(index, width)?;
    let input = source
        .get(start..end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    let output = destination
        .get_mut(start..end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    rope(input, params, output)?;
    Ok(())
}
