//! Grouped-query attention over the session's key/value cache.
//!
//! ```text
//! scores[p]  = (q_h · k_p,g) / √d_head        for p in 0 ..= position
//! weights    = softmax(scores)
//! out_h      = Σ_p weights[p] · v_p,g
//! ```
//!
//! where `g = h / (n_heads / n_kv_heads)` is the key/value head that query head
//! `h` reads. `n_kv_heads == n_heads` makes that the identity and gives
//! ordinary multi-head attention; `n_kv_heads == 1` makes every query head read
//! head zero and gives multi-query attention. One code path, three behaviours,
//! no default (BXW1 §5.1).
//!
//! # Causal masking is the loop bound, not a mask
//!
//! A query at absolute position `p` attends to `0 ..= p` and nothing further.
//! That is expressed by ending the loop at `p`, not by writing `−∞` into the
//! scores of later positions and letting softmax turn them into zeros. The two
//! agree numerically — `exp(−∞ − max) = 0` — but the loop bound also does not
//! read cache slots that have never been written, which is the difference
//! between a causal model and a model that happens to average in whatever the
//! previous session left behind. There is no `−∞` anywhere in this crate.
//!
//! # SIMD seams
//!
//! 1. **[`dot_product`]** — two contiguous `d_head` slices, the shape a
//!    four-accumulator `vfmaq_f32` loop replaces cleanly. It is the hot loop of
//!    decode once the context is long, since it runs
//!    `n_heads × context` times per layer per token.
//! 2. **[`accumulate_weighted`]** — an `axpy` over `d_head`, one `vdupq_n_f32`
//!    of the softmax weight and one `vfmaq_f32` per four values.
//!
//! Neither is vectorized, and neither may be until P3-T0 lands: the context
//! switch does not preserve vector state, so a NEON kernel today would be a
//! correctness bug wearing a performance costume.

use brainix_tensor::softmax;

use crate::cache::SessionCache;
use crate::config::checked_product;
use crate::error::TransformerError;
use crate::slices::{prefix, prefix_mut};
use crate::workspace::Workspace;

/// The extents one attention call is shaped by, gathered so the per-head
/// helpers take a shape rather than five loose integers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AttentionShape {
    /// BXW1 `d_head`.
    pub(crate) head_width: usize,
    /// `n_heads × d_head` — the stride of one token's query row.
    pub(crate) query_width: usize,
    /// `n_kv_heads × d_head` — the stride of one cached position's row.
    pub(crate) key_value_width: usize,
    /// BXW1 `n_heads`.
    pub(crate) query_head_count: usize,
    /// `n_heads / n_kv_heads`.
    pub(crate) query_heads_per_group: usize,
    /// `1/√d_head`.
    pub(crate) scale: f32,
}

impl AttentionShape {
    /// The key/value head query head `query_head` reads.
    fn group_of(&self, query_head: usize) -> Result<usize, TransformerError> {
        query_head
            .checked_div(self.query_heads_per_group)
            .ok_or(TransformerError::InvalidKeyValueHeadCount)
    }

    /// The `[start, end)` element range of one head within a row of `width`
    /// heads.
    fn head_range(&self, base: usize, head: usize) -> Result<(usize, usize), TransformerError> {
        let offset = checked_product(head, self.head_width)?;
        let start = base
            .checked_add(offset)
            .ok_or(TransformerError::DimensionOverflow)?;
        let end = start
            .checked_add(self.head_width)
            .ok_or(TransformerError::DimensionOverflow)?;
        Ok((start, end))
    }
}

/// Runs attention for every token in the batch, writing
/// `workspace.attention`.
///
/// `start` is the absolute position of the batch's first token; the cache
/// already holds every key and value for positions `0 .. start + token_count`.
pub(crate) fn attend(
    workspace: &mut Workspace<'_>,
    cache: &SessionCache<'_>,
    layer: usize,
    start: usize,
    token_count: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let keys = cache.keys(layer)?;
    let values = cache.values(layer)?;
    for token in 0..token_count {
        let position = start
            .checked_add(token)
            .ok_or(TransformerError::DimensionOverflow)?;
        attend_one_token(workspace, keys, values, token, position, shape)?;
    }
    Ok(())
}

/// One token's attention, over every query head.
fn attend_one_token(
    workspace: &mut Workspace<'_>,
    keys: &[f32],
    values: &[f32],
    token: usize,
    position: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let row = checked_product(token, shape.query_width)?;
    let context = position
        .checked_add(1)
        .ok_or(TransformerError::DimensionOverflow)?;
    for head in 0..shape.query_head_count {
        attend_one_head(workspace, keys, values, row, head, context, shape)?;
    }
    Ok(())
}

/// One query head of one token: score, softmax, weighted sum of values.
fn attend_one_head(
    workspace: &mut Workspace<'_>,
    keys: &[f32],
    values: &[f32],
    row: usize,
    head: usize,
    context: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let group = shape.group_of(head)?;
    let (query_start, query_end) = shape.head_range(row, head)?;
    let query = workspace
        .query_rotated
        .get(query_start..query_end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    let scores = prefix_mut(workspace.scores, context)?;
    score_against_keys(query, keys, group, context, shape, scores)?;
    let probabilities = prefix_mut(workspace.probabilities, context)?;
    softmax(prefix(workspace.scores, context)?, probabilities)?;
    let (out_start, out_end) = shape.head_range(row, head)?;
    let destination = workspace
        .attention
        .get_mut(out_start..out_end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    blend_values(
        values,
        prefix(workspace.probabilities, context)?,
        group,
        shape,
        destination,
    )
}

/// `scores[p] = (query · key[p, group]) / √d_head` for `p in 0 .. context`.
fn score_against_keys(
    query: &[f32],
    keys: &[f32],
    group: usize,
    context: usize,
    shape: AttentionShape,
    scores: &mut [f32],
) -> Result<(), TransformerError> {
    for (position, slot) in scores.iter_mut().enumerate().take(context) {
        let base = checked_product(position, shape.key_value_width)?;
        let (start, end) = shape.head_range(base, group)?;
        let key = keys
            .get(start..end)
            .ok_or(TransformerError::CacheGeometryMismatch)?;
        *slot = dot_product(query, key) * shape.scale;
    }
    Ok(())
}

/// `destination = Σ_p probabilities[p] · value[p, group]`.
fn blend_values(
    values: &[f32],
    probabilities: &[f32],
    group: usize,
    shape: AttentionShape,
    destination: &mut [f32],
) -> Result<(), TransformerError> {
    for slot in destination.iter_mut() {
        *slot = 0.0;
    }
    for (position, weight) in probabilities.iter().enumerate() {
        let base = checked_product(position, shape.key_value_width)?;
        let (start, end) = shape.head_range(base, group)?;
        let value = values
            .get(start..end)
            .ok_or(TransformerError::CacheGeometryMismatch)?;
        accumulate_weighted(*weight, value, destination);
    }
    Ok(())
}

/// `destination += weight × value`, elementwise. **SIMD seam 2.**
fn accumulate_weighted(weight: f32, value: &[f32], destination: &mut [f32]) {
    for (source, slot) in value.iter().zip(destination.iter_mut()) {
        *slot += weight * source;
    }
}

/// `f32`-accumulated dot product over two equal-length slices. **SIMD seam 1.**
///
/// Accumulation is `f32`, matching what the matmul kernels do and what a NEON
/// pass will do, so the reference and its vectorized successor round identically
/// in the only respect under this crate's control — the order of the additions.
fn dot_product(left: &[f32], right: &[f32]) -> f32 {
    let mut accumulated = 0.0_f32;
    for (left_value, right_value) in left.iter().zip(right.iter()) {
        accumulated += left_value * right_value;
    }
    accumulated
}
