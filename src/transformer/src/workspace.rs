//! Activation scratch: one caller-supplied slice, cut once into named views.
//!
//! # `INV-MEM`
//!
//! The forward pass owns no buffer. Every intermediate it needs — the residual
//! stream, the normalized copy, the three attention projections, their rotated
//! forms, the attention output, the two feed-forward branches, the attention
//! score row and its softmax — is a sub-slice of the one `&mut [f32]` the
//! caller hands over. [`workspace_floats`] is a `const fn`, so that slice is
//! sized at build time from the hyperparameters and the largest batch the
//! deployment intends to admit.
//!
//! # Why the batch ceiling is a build-time parameter
//!
//! A prefill of `T` tokens runs every projection as one matmul with
//! `n_tokens = T`, which is the whole reason
//! [`brainix_tensor::matmul_f32`]'s loop order is weights-outer: the weight
//! bytes are streamed once for the whole batch instead of once per token. That
//! costs `T ×` the activation scratch. Since there is no allocator, `T` cannot
//! be discovered at runtime — it is stated up front, the workspace is sized for
//! it, and a larger batch is refused with
//! [`TransformerError::BatchExceedsWorkspace`] rather than silently split.
//!
//! Single-token decode is the same code with `T = 1`, not a second path.

use crate::config::{checked_product, extend, scale, ModelConfig};
use crate::error::TransformerError;

/// Per-token scratch width: the residual stream and its three same-width
/// companions, the query and its rotation, the key/value trio, and the three
/// feed-forward branches.
const fn floats_per_token(config: &ModelConfig) -> Result<usize, TransformerError> {
    // hidden, normed, projected, feed_forward
    let residual = checked_product(config.model_width, 4);
    // query, query_rotated, attention
    let query = scale(config.query_width(), 3);
    // key, key_rotated, value
    let key_value = scale(config.key_value_width(), 3);
    // gate, up, activated
    let feed_forward = checked_product(config.feed_forward_width, 3);
    extend(extend(residual, query), extend(key_value, feed_forward))
}

/// Scratch that does not scale with the batch: the attention score row and its
/// softmax, both `max_seq_len` wide because a query may attend to the whole
/// context.
const fn floats_per_call(config: &ModelConfig) -> Result<usize, TransformerError> {
    checked_product(config.maximum_sequence_length, 2)
}
/// Bytes of `Q8_0` activation scratch the `SDOT` path needs.
///
/// The widest reduction any projection performs is `max(d_model, d_ffn)`, so
/// one buffer of that width serves every call site. Supplying fewer bytes than
/// this is not an error -- it selects the `f32`-activation kernel -- which is
/// what makes enabling the faster, lossier path an explicit act.
pub const fn quantized_activation_bytes(
    config: &ModelConfig,
    maximum_batch_tokens: usize,
) -> Result<usize, TransformerError> {
    let widest = if config.feed_forward_width > config.model_width {
        config.feed_forward_width
    } else {
        config.model_width
    };
    // Mirrors BXW1 §4.3: a 128-aligned scale plane followed by the quant plane.
    let blocks = match widest.checked_div(32) {
        Some(value) => value,
        None => return Err(TransformerError::ZeroDimension),
    };
    let scales = match blocks.checked_mul(4) {
        Some(value) => value,
        None => return Err(TransformerError::DimensionOverflow),
    };
    let padded = scales.next_multiple_of(128);
    match padded.checked_add(widest) {
        Some(per_token) => scale(Ok(per_token), maximum_batch_tokens),
        None => Err(TransformerError::DimensionOverflow),
    }
}


/// Floats a caller must reserve for a workspace admitting up to
/// `maximum_batch_tokens` tokens per call.
///
/// A `const fn`, so a serving build states its own ceiling:
///
/// ```
/// # use brainix_transformer::{workspace_floats, ModelConfig};
/// # use brainix_tensor::RopePairing;
/// const CONFIG: ModelConfig = ModelConfig {
///     architecture_id: 1,
///     layer_count: 2, model_width: 32, query_head_count: 4,
///     key_value_head_count: 2, head_width: 8, feed_forward_width: 64,
///     vocabulary_size: 48, maximum_sequence_length: 16,
///     rope_theta: 1.0e4, normalization_epsilon: 1.0e-5,
///     rope_dimensions: 4, rope_pairing: RopePairing::Interleaved,
/// };
/// const FLOATS: usize = match workspace_floats(&CONFIG, 8) {
///     Ok(floats) => floats,
///     Err(_) => 0,
/// };
/// let mut scratch = [0.0_f32; FLOATS];
/// assert_eq!(FLOATS, 8 * (4 * 32 + 3 * 32 + 3 * 16 + 3 * 64) + 2 * 16);
/// ```
///
/// # Errors
///
/// [`TransformerError::DimensionOverflow`].
pub const fn workspace_floats(
    config: &ModelConfig,
    maximum_batch_tokens: usize,
) -> Result<usize, TransformerError> {
    let batched = scale(floats_per_token(config), maximum_batch_tokens);
    extend(batched, floats_per_call(config))
}

/// The named views the forward pass writes through.
///
/// Fields are crate-visible rather than accessor-wrapped so that the borrow
/// checker can see two of them being used at once — reading `normed` while
/// writing `query` is a disjoint two-field borrow, which no pair of `&self` /
/// `&mut self` accessors could express.
#[derive(Debug)]
pub struct Workspace<'a> {
    /// Scratch for `Q8_0`-quantized activations, in bytes.
    ///
    /// Separate storage from the `f32` cut below, because it is bytes and this
    /// crate will not reinterpret one as the other. Sized by
    /// [`quantized_activation_bytes`]; **empty is legal and selects the
    /// `f32`-activation kernel**, so a caller that has not opted into lossy
    /// activations keeps the higher-precision result.
    pub(crate) quant_scratch: &'a mut [u8],
    /// The residual stream, `[batch, d_model]`.
    pub(crate) hidden: &'a mut [f32],
    /// RMSNorm output, `[batch, d_model]`. Reused by both norms of a layer and
    /// by the final norm.
    pub(crate) normed: &'a mut [f32],
    /// `wq · normed`, `[batch, n_heads × d_head]`, before rotation.
    pub(crate) query: &'a mut [f32],
    /// RoPE applied to `query`, `[batch, n_heads × d_head]`.
    pub(crate) query_rotated: &'a mut [f32],
    /// `wk · normed`, `[batch, n_kv_heads × d_head]`, before rotation.
    pub(crate) key: &'a mut [f32],
    /// RoPE applied to `key`, `[batch, n_kv_heads × d_head]`. This is what is
    /// cached: keys are stored **rotated**, so a position's key is rotated
    /// exactly once no matter how many later tokens attend to it.
    pub(crate) key_rotated: &'a mut [f32],
    /// `wv · normed`, `[batch, n_kv_heads × d_head]`. Values are **not**
    /// rotated.
    pub(crate) value: &'a mut [f32],
    /// The attention output before `wo`, `[batch, n_heads × d_head]`.
    pub(crate) attention: &'a mut [f32],
    /// `wo · attention`, `[batch, d_model]`.
    pub(crate) projected: &'a mut [f32],
    /// `w1 · normed`, `[batch, d_ffn]` — the gate branch.
    pub(crate) gate: &'a mut [f32],
    /// `w3 · normed`, `[batch, d_ffn]` — the up branch.
    pub(crate) up: &'a mut [f32],
    /// `SiLU(gate) ⊙ up`, `[batch, d_ffn]`.
    pub(crate) activated: &'a mut [f32],
    /// `w2 · activated`, `[batch, d_model]`.
    pub(crate) feed_forward: &'a mut [f32],
    /// One query's attention scores over the context, `[max_seq_len]`.
    pub(crate) scores: &'a mut [f32],
    /// The softmax of `scores`, `[max_seq_len]`.
    pub(crate) probabilities: &'a mut [f32],
    /// The batch ceiling this workspace was cut for.
    pub(crate) maximum_batch_tokens: usize,
    /// The configuration this workspace was cut for, so a forward pass can
    /// refuse a workspace built for a different model.
    pub(crate) config: ModelConfig,
}

impl<'a> Workspace<'a> {
    /// Cuts `storage` into the views above.
    ///
    /// `storage` may be longer than [`workspace_floats`] requires — the tail is
    /// simply unused — but never shorter.
    ///
    /// # Errors
    ///
    /// [`TransformerError::WorkspaceTooSmall`],
    /// [`TransformerError::ZeroDimension`] if `maximum_batch_tokens` is zero,
    /// or [`TransformerError::DimensionOverflow`].
    pub fn new(
        storage: &'a mut [f32],
        quant_scratch: &'a mut [u8],
        config: &ModelConfig,
        maximum_batch_tokens: usize,
    ) -> Result<Self, TransformerError> {
        if maximum_batch_tokens == 0 {
            return Err(TransformerError::ZeroDimension);
        }
        config.validate()?;
        let mut remaining: &mut [f32] = storage;
        let cut = Cut {
            residual: checked_product(config.model_width, maximum_batch_tokens)?,
            query: checked_product(config.query_width()?, maximum_batch_tokens)?,
            key_value: checked_product(config.key_value_width()?, maximum_batch_tokens)?,
            feed_forward: checked_product(config.feed_forward_width, maximum_batch_tokens)?,
            context: config.maximum_sequence_length,
        };
        let mut workspace = cut.apply(&mut remaining, *config, maximum_batch_tokens)?;
        workspace.quant_scratch = quant_scratch;
        Ok(workspace)
    }
}

/// The five distinct extents a workspace is cut into, computed once so the cut
/// itself reads as a list of names rather than a list of products.
struct Cut {
    residual: usize,
    query: usize,
    key_value: usize,
    feed_forward: usize,
    context: usize,
}

impl Cut {
    fn apply<'a>(
        &self,
        remaining: &mut &'a mut [f32],
        config: ModelConfig,
        maximum_batch_tokens: usize,
    ) -> Result<Workspace<'a>, TransformerError> {
        Ok(Workspace {
            quant_scratch: &mut [],
            hidden: take(remaining, self.residual)?,
            normed: take(remaining, self.residual)?,
            query: take(remaining, self.query)?,
            query_rotated: take(remaining, self.query)?,
            key: take(remaining, self.key_value)?,
            key_rotated: take(remaining, self.key_value)?,
            value: take(remaining, self.key_value)?,
            attention: take(remaining, self.query)?,
            projected: take(remaining, self.residual)?,
            gate: take(remaining, self.feed_forward)?,
            up: take(remaining, self.feed_forward)?,
            activated: take(remaining, self.feed_forward)?,
            feed_forward: take(remaining, self.residual)?,
            scores: take(remaining, self.context)?,
            probabilities: take(remaining, self.context)?,
            maximum_batch_tokens,
            config,
        })
    }
}

/// Splits `count` floats off the front of `remaining`, advancing it.
///
/// `split_at_mut_checked` rather than `split_at_mut`: the latter panics, and a
/// workspace one float short is a caller sizing error, not a crash.
fn take<'a>(
    remaining: &mut &'a mut [f32],
    count: usize,
) -> Result<&'a mut [f32], TransformerError> {
    if remaining.len() < count {
        return Err(TransformerError::WorkspaceTooSmall);
    }
    let storage = core::mem::take(remaining);
    let (head, rest) = storage
        .split_at_mut_checked(count)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    *remaining = rest;
    Ok(head)
}
