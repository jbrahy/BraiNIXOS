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

use brainix_tensor::{softmax, TensorError};

use crate::cache::SessionCache;
use crate::config::checked_product;
use crate::dispatch::Dispatch;
use crate::error::TransformerError;
use crate::slices::{prefix, prefix_mut};
use crate::workspace::Workspace;
use core::sync::atomic::{AtomicBool, Ordering};

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
    /// The score scale BXW1 §5.6 assigns to the model's `arch_id`; `1/√d_head`
    /// for `arch_id = 1`.
    pub(crate) scale: f32,
    /// `max_seq_len` — the stride between one head's score row and the next in
    /// `workspace.scores` and `workspace.probabilities`.
    pub(crate) score_stride: usize,
}

impl AttentionShape {
    /// The key/value head query head `query_head` reads.
    fn group_of(&self, query_head: usize) -> Result<usize, TransformerError> {
        query_head
            .checked_div(self.query_heads_per_group)
            .ok_or(TransformerError::InvalidKeyValueHeadCount)
    }

    /// The `[start, end)` range of head `head`'s live scores, within the
    /// `[n_heads, max_seq_len]` score board.
    fn score_range(&self, head: usize, context: usize) -> Result<(usize, usize), TransformerError> {
        let start = checked_product(head, self.score_stride)?;
        let end = start
            .checked_add(context)
            .ok_or(TransformerError::DimensionOverflow)?;
        Ok((start, end))
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
pub(crate) fn attend<D: Dispatch>(
    dispatch: &D,
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
        attend_one_token(dispatch, workspace, keys, values, token, position, shape)?;
    }
    Ok(())
}

/// One token's attention, in three phases so the middle one can be shared out.
///
/// # Why this is not a loop over heads any more
///
/// It was, until 2026-08-19, and each head ran score -> softmax -> blend before
/// the next one started. That is the natural shape and it has one problem:
/// `softmax` is the largest serial cost in a decode -- 9.44 ms/token at the
/// reference shape, 79% of all elementwise work -- and a loop like that cannot
/// hand any of it to another core, because every head writes the same score row.
///
/// Splitting one head's softmax is not the answer either. At `context` 2048 a
/// single softmax is about 9 us and a dispatch round trip is about 26 us, so
/// splitting one costs more than it saves. What pays is splitting *all* of
/// them: 32 heads is ~295 us of work behind one round trip. Measured on this
/// laptop, four workers turn 285 us into 95 us, **2.99x**, with bit-identical
/// output.
///
/// So the head loop is turned inside out. Every head scores into its own row,
/// one dispatch softmaxes the whole board, and then every head blends. The
/// price is the score board itself -- see `workspace::floats_per_call`.
///
/// # Measured 1.40x end to end, once the shape let it show
///
/// This spent a while unmerged because two attempts to price it end to end
/// could not resolve it: across binaries the single-core path -- identical
/// arithmetic in both -- reported up to 22% either way, and within one binary
/// two thresholds disagreed about the sign. Both were run on models where
/// `softmax` is a few percent of a decode, against a host whose noise band is
/// about 8%. The instrument was coarser than the effect.
///
/// The fix was the shape, not the method. On a model whose every matrix is
/// **under** the split threshold, changing the threshold varies only whether
/// `softmax` is shared out -- nothing else moves. 4 layers, `d_model` 256, 32
/// heads, 2000 tokens of context, best of five:
///
/// | threshold | what splits | tok/s | vs no split |
/// | --- | --- | --- | --- |
/// | `>= 0 KB` | everything, including 72 KB matmuls | 703.88 | 0.83x |
/// | `>= 512 KB` | **`softmax` only** | **1187.35** | **1.40x** |
/// | `>= 2 MB` | `softmax` only | 1086.04 | 1.28x |
/// | `split nothing` | neither | 850.42 | 1.00x |
///
/// One core is 840.59, within noise of the 850.42 that a pool splitting
/// nothing reaches, so the pool itself is free and the 1.40x is the split.
///
/// The 0.83x row is a second reading of the crossover rule in
/// `dispatch::minimum_split_bytes`, arrived at from the other direction:
/// splitting 72 KB matrices costs more than it saves, and a dispatcher with no
/// threshold gives back more than the softmax split wins.
///
/// **What this does not claim.** 1.40x is on a shape chosen so `softmax`
/// dominates. At the reference shape it is ~13% of a four-worker decode, so
/// the same 2.99x on the phase is worth single digits overall -- which is
/// exactly what the earlier attempts could not resolve, and why they were
/// right to stay unmerged rather than be reported as a win.
fn attend_one_token<D: Dispatch>(
    dispatch: &D,
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

    // Fused unless the softmax is actually going to be shared out.
    //
    // The three-phase shape is not free on one core: a head's score row is
    // written in phase one and not read until phase two, and at 32 heads and
    // `context` 1500 the board is 192 KB, past this machine's L1. Measured, the
    // unconditional three-phase version cost the single-core path **0.83x**
    // while buying the pool 1.07x. That is the wrong trade to make
    // unconditionally, because the serial path is what runs until there is a
    // scheduler.
    //
    // So the shape is chosen rather than fixed: fused keeps each row hot, and
    // the phases are only paid for when a dispatch will actually happen.
    if !worth_splitting(dispatch, context, shape) {
        for head in 0..shape.query_head_count {
            score_one_head(workspace, keys, row, head, context, shape)?;
            softmax_one_head(workspace, head, context, shape)?;
            blend_one_head(workspace, values, row, head, context, shape)?;
        }
        return Ok(());
    }

    for head in 0..shape.query_head_count {
        score_one_head(workspace, keys, row, head, context, shape)?;
    }
    softmax_every_head(dispatch, workspace, context, shape)?;
    for head in 0..shape.query_head_count {
        blend_one_head(workspace, values, row, head, context, shape)?;
    }
    Ok(())
}

/// One head's softmax, in this thread.
fn softmax_one_head(
    workspace: &mut Workspace<'_>,
    head: usize,
    context: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let (start, end) = shape.score_range(head, context)?;
    let source = workspace
        .scores
        .get(start..end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    let target = workspace
        .probabilities
        .get_mut(start..end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    softmax(source, target).map_err(TransformerError::from)
}

/// `scores[head] = query[head] · keys / √d_head`, over the live context.
fn score_one_head(
    workspace: &mut Workspace<'_>,
    keys: &[f32],
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
    let (score_start, score_end) = shape.score_range(head, context)?;
    let scores = workspace
        .scores
        .get_mut(score_start..score_end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    score_against_keys(query, keys, group, context, shape, scores)
}

/// `destination[head] = Σ_p probabilities[head][p] · value[p, group]`.
fn blend_one_head(
    workspace: &mut Workspace<'_>,
    values: &[f32],
    row: usize,
    head: usize,
    context: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let group = shape.group_of(head)?;
    let (score_start, score_end) = shape.score_range(head, context)?;
    let probabilities = workspace
        .probabilities
        .get(score_start..score_end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    let (out_start, out_end) = shape.head_range(row, head)?;
    let destination = workspace
        .attention
        .get_mut(out_start..out_end)
        .ok_or(TransformerError::WorkspaceTooSmall)?;
    blend_values(values, probabilities, group, shape, destination)
}

/// How many weight bytes one softmax element is worth, for the split decision.
///
/// [`Dispatch::minimum_split_bytes`] is denominated in weight bytes, because
/// every other caller is a matmul. Softmax moves almost no memory and is
/// entirely `exp`, so the comparison has to be made in a common currency: time.
///
/// `benches/matmul.rs` measures the `Q8_0` kernel at ~57 GB/s of weight bytes on
/// one core, and `softmax` at ~231 M elements/s. One softmax element therefore
/// occupies a core for as long as `57e9 / 231e6 ~= 246` weight bytes do. The
/// constant is rounded to 250 because it is a ratio of two measurements, not a
/// definition, and a third significant figure would be a lie.
///
/// # It was 200, from `47e9 / 236e6`
///
/// Both figures were re-measured on 2026-08-20, best of three. The softmax side
/// barely moved -- 236 to 231 M elements/s, which is load on the machine rather
/// than a change in the code. The whole error was the matmul side: 47 GB/s was
/// measured before the two-blocks-per-iteration unroll landed in
/// `matmul_q8_0_q8a` and was never revisited, so this ratio inherited a stale
/// numerator through `SINGLE_CORE_BYTES_PER_MICROSECOND`'s twin.
///
/// The direction matters here in a way it did not for that constant.
/// Under-valuing a softmax element under-values the whole board, so the split
/// was being declined on work that clears the threshold once the element is
/// priced correctly. The head-parallel path measured 1.40x end to end; a fifth
/// of the boards that should have taken it were staying serial.
const WEIGHT_BYTES_PER_SOFTMAX_ELEMENT: usize = 250;

/// Softmaxes every head's score row, splitting the board across workers when
/// there is enough of it to be worth a round trip.
fn worth_splitting<D: Dispatch>(dispatch: &D, context: usize, shape: AttentionShape) -> bool {
    let equivalent_bytes = shape
        .query_head_count
        .saturating_mul(context)
        .saturating_mul(WEIGHT_BYTES_PER_SOFTMAX_ELEMENT);
    dispatch.chunks() > 1 && equivalent_bytes >= dispatch.minimum_split_bytes()
}

fn softmax_every_head<D: Dispatch>(
    dispatch: &D,
    workspace: &mut Workspace<'_>,
    context: usize,
    shape: AttentionShape,
) -> Result<(), TransformerError> {
    let heads = shape.query_head_count;
    {
        let per_worker = heads.div_ceil(dispatch.chunks());
        let width = checked_product(per_worker, shape.score_stride)?;
        let board = checked_product(heads, shape.score_stride)?;
        let scores = prefix(workspace.scores, board)?;
        let destination = prefix_mut(workspace.probabilities, board)?;
        // Chunks run on other threads, so the closure is `Fn + Sync` and cannot
        // carry a `Result` out. Mirrors `weights.rs`: an atomic flag is the most
        // a shared closure can set without allocation or a lock, and every
        // argument below is derived from shapes already validated, so a refusal
        // is a bug in this arithmetic rather than a runtime condition.
        // Two flags, not one. They report DIFFERENT errors, and reporting one
        // for the other is a defect this code had until 2026-08-19: the serial
        // path propagates whatever `softmax` refused with, while this path
        // returned `WorkspaceTooSmall` for every failure -- so the same model,
        // decoded with and without a dispatcher, named different causes for the
        // same defect. Non-finite scores are reachable with extreme weights, so
        // that divergence was reachable too.
        let refused = AtomicBool::new(false);
        let mis_sliced = AtomicBool::new(false);
        dispatch.for_each_chunk(destination, width, |index, chunk| {
            let base = index.saturating_mul(per_worker);
            for (local, row) in chunk.chunks_mut(shape.score_stride).enumerate() {
                // No bound check on `head` here: `per_worker` is
                // `heads.div_ceil(chunks)`, so `chunks_mut` yields at most
                // `heads` rows in total and the last chunk is simply short. If
                // that arithmetic ever stops holding, the `get` below returns
                // `None` and the flag fires, which is the honest failure.
                let head = base.saturating_add(local);
                let start = head.saturating_mul(shape.score_stride);
                let end = start.saturating_add(context);
                match (scores.get(start..end), row.get_mut(..context)) {
                    (Some(source), Some(target)) => {
                        // Only non-finite input is reachable of the three
                        // things `softmax` refuses on, and the serial path
                        // names it -- so this path names the same thing.
                        if softmax(source, target).is_err() {
                            refused.store(true, Ordering::Relaxed);
                        }
                    }
                    // `context` is a parameter, so a caller can ask for more
                    // positions than a score row holds and land here. The flag
                    // rather than a panic: the board is left alone and the call
                    // refuses. Pinned by
                    // `a_context_wider_than_the_score_row_is_a_sizing_error_and_not_a_silent_pass`.
                    _ => mis_sliced.store(true, Ordering::Relaxed),
                }
            }
        });
        if refused.load(Ordering::Relaxed) {
            // The same error the serial path gives. A `Fn` closure cannot carry
            // a `Result` out, so the variant is reconstructed rather than
            // forwarded -- sound because only one of `softmax`'s refusals is
            // reachable from here, which is what the note at the call site
            // argues.
            return Err(TransformerError::Kernel(TensorError::NonFiniteInput));
        }
        if mis_sliced.load(Ordering::Relaxed) {
            return Err(TransformerError::WorkspaceTooSmall);
        }
        Ok(())
    }
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
///
/// # Two things measured here that are worth not re-deriving
///
/// **Deferring the softmax normalization into this loop's output is not worth
/// it.** Softmax scales all `context` probabilities by `1/sum`; that could be
/// skipped and the `d_head`-wide result scaled once instead, replacing 2048
/// multiplies with 128. Measured over three rounds it is 1.3% -- which matches
/// the theory, since this loop does `context x d_head` fused multiply-adds and
/// the normalization is under 1% of them. It also changes the result by 2.3e-6
/// relative. A numerics change for one percent is a bad trade.
///
/// **This loop is bandwidth-bound on the KV cache, not compute-bound.** At 2048
/// context and `d_head` 128 it reads 1 MB per head per layer and sustains about
/// 37 GB/s, close to what the matmul manages. That makes a quantized KV cache
/// the obvious lever -- but the arithmetic says wait: at 2048 context the cache
/// is 537 MB per token against 7.9 GB of Q8 weights, **6% of traffic**.
/// Quantizing it buys about 4%. It grows linearly with context while the
/// weights do not, so it becomes first-order somewhere past 16k, and that is
/// when to spend the format change rather than now.
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

/// Lanes the dot product splits into.
///
/// Four, matching `brainix_tensor`'s `block_dot` and the sweep recorded there.
/// The number is not arbitrary and not tuned again here: two accumulators do
/// not fill the pipeline and eight spill on this register file.
const DOT_LANES: usize = 4;

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
    // Four lanes, not one running total.
    //
    // A single accumulator makes every multiply wait for the previous add, so
    // the loop runs at the latency of `fadd` rather than its throughput and
    // nothing vectorizes. The whole transformer crate compiled to zero
    // `fmla.4s` and twenty-four scalar `fadd s0` before this.
    //
    // Measured, this shape against the serial one, 512 positions:
    //
    // | `d_head` | serial | four lanes | |
    // | --- | --- | --- | --- |
    // | 64 | 3.76 GMAC/s | 4.53 GMAC/s | 1.20x |
    // | 128 | 2.86 GMAC/s | 4.61 GMAC/s | 1.61x |
    //
    // The gain grows with head width because the dependency chain does.
    //
    // `block_dot` in `brainix_tensor` already carries this reasoning and the
    // sweep that chose four; this is the same fix at the seam that was labelled
    // for it and never cut. Indexed rather than zipped for the same reason it
    // gives: the fixed-width chunk is what lets the compiler see four
    // independent updates.
    let mut lanes = [0.0_f32; DOT_LANES];
    for (left_lane, right_lane) in left
        .chunks_exact(DOT_LANES)
        .zip(right.chunks_exact(DOT_LANES))
    {
        for lane in 0..DOT_LANES {
            let left_value = left_lane.get(lane).copied().unwrap_or(0.0);
            let right_value = right_lane.get(lane).copied().unwrap_or(0.0);
            let Some(slot) = lanes.get_mut(lane) else {
                // COVERAGE-EXEMPT: `lanes` is `[_; DOT_LANES]` and `lane` runs
                // `0..DOT_LANES`, so this cannot be reached. Indexing instead
                // would put a panic path in the attention inner loop.
                continue;
            };
            *slot += left_value * right_value;
        }
    }

    // The tail, for a `d_head` that is not a multiple of four. BXW1 permits
    // one; every model seen so far has a power-of-two head width, and a kernel
    // that is silently wrong on the first one that does not is worse than a
    // few lines.
    let handled = (left.len() / DOT_LANES).saturating_mul(DOT_LANES);
    let mut tail = 0.0_f32;
    for (left_value, right_value) in left.iter().zip(right.iter()).skip(handled) {
        tail += left_value * right_value;
    }

    // Pairwise, matching `block_dot`.
    ((lanes[0] + lanes[1]) + (lanes[2] + lanes[3])) + tail
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::{accumulate_weighted, dot_product, softmax_every_head, AttentionShape, DOT_LANES};
    use crate::config::ModelConfig;
    use crate::dispatch::Serial;
    use crate::error::TransformerError;
    use crate::workspace::{workspace_floats, Workspace};
    use brainix_tensor::{RopePairing, TensorError};

    /// The same small model the workspace documentation is written against.
    const CONFIG: ModelConfig = ModelConfig {
        architecture_id: 1,
        layer_count: 2,
        model_width: 32,
        query_head_count: 4,
        key_value_head_count: 2,
        head_width: 8,
        feed_forward_width: 64,
        vocabulary_size: 48,
        maximum_sequence_length: 16,
        rope_theta: 1.0e4,
        normalization_epsilon: 1.0e-5,
        rope_dimensions: 4,
        rope_pairing: RopePairing::Interleaved,
    };

    const FLOATS: usize = match workspace_floats(&CONFIG, 8) {
        Ok(floats) => floats,
        Err(_) => 0,
    };

    /// Non-finite scores must be named as such, on both dispatch paths.
    ///
    /// The comment at the call site says extreme weights make a dot product
    /// overflow to infinity, and that this was reachable -- the same model
    /// decoded with and without a dispatcher named different causes until that
    /// was fixed. Reaching it through weights would need a fixture built to
    /// overflow an f32; the score board is the same buffer those weights would
    /// have written, so writing infinity into it directly tests the refusal
    /// rather than the arithmetic that produces it.
    #[test]
    fn a_non_finite_score_is_refused_as_non_finite_and_not_as_a_sizing_error() {
        let mut storage = [0.0_f32; FLOATS];
        let mut quant: [u8; 0] = [];
        let mut workspace =
            Workspace::new(&mut storage, &mut quant, &CONFIG, 8).expect("workspace");

        let shape = AttentionShape {
            head_width: CONFIG.head_width,
            query_width: CONFIG.query_head_count * CONFIG.head_width,
            key_value_width: CONFIG.key_value_head_count * CONFIG.head_width,
            query_head_count: CONFIG.query_head_count,
            query_heads_per_group: CONFIG.query_head_count / CONFIG.key_value_head_count,
            scale: 1.0,
            score_stride: CONFIG.maximum_sequence_length,
        };

        // A finite board first: the same call must succeed, or the assertion
        // below would pass for the wrong reason.
        for slot in workspace.scores.iter_mut() {
            *slot = 0.0;
        }
        assert!(
            softmax_every_head(&Serial, &mut workspace, 4, shape).is_ok(),
            "a finite board must not be refused"
        );

        // One infinity anywhere in the first head's row is enough.
        if let Some(slot) = workspace.scores.first_mut() {
            *slot = f32::INFINITY;
        }
        assert_eq!(
            softmax_every_head(&Serial, &mut workspace, 4, shape),
            Err(TransformerError::Kernel(TensorError::NonFiniteInput)),
            "an infinite score is a non-finite input, not a workspace sizing error"
        );
    }

    /// The other flag, and the reason there are two of them.
    ///
    /// `context` is a parameter, so a caller can ask for more positions than a
    /// score row holds. Then `row.get_mut(..context)` is `None`, nothing is
    /// written, and the call must say so. Before today both flags reported
    /// `WorkspaceTooSmall`; the test above pins the other error, and this one
    /// pins that this case still gives the sizing error rather than inheriting
    /// the non-finite one now that they are told apart.
    #[test]
    fn a_context_wider_than_the_score_row_is_a_sizing_error_and_not_a_silent_pass() {
        let mut storage = [0.0_f32; FLOATS];
        let mut quant: [u8; 0] = [];
        let mut workspace =
            Workspace::new(&mut storage, &mut quant, &CONFIG, 8).expect("workspace");

        let shape = AttentionShape {
            head_width: CONFIG.head_width,
            query_width: CONFIG.query_head_count * CONFIG.head_width,
            key_value_width: CONFIG.key_value_head_count * CONFIG.head_width,
            query_head_count: CONFIG.query_head_count,
            query_heads_per_group: CONFIG.query_head_count / CONFIG.key_value_head_count,
            scale: 1.0,
            score_stride: CONFIG.maximum_sequence_length,
        };

        for slot in workspace.scores.iter_mut() {
            *slot = 0.0;
        }
        let too_wide = CONFIG.maximum_sequence_length + 1;
        assert_eq!(
            softmax_every_head(&Serial, &mut workspace, too_wide, shape),
            Err(TransformerError::WorkspaceTooSmall),
            "a context past the score stride must refuse, not write a partial board"
        );
    }

    /// A reference that is deliberately the shape the four-lane kernel replaced.
    fn serial(left: &[f32], right: &[f32]) -> f32 {
        let mut acc = 0.0_f32;
        for (l, r) in left.iter().zip(right.iter()) {
            acc += l * r;
        }
        acc
    }

    #[test]
    fn four_lanes_agree_with_a_serial_dot_on_aligned_widths() {
        // Fixed storage: this crate is `no_std` and has no allocator, which is
        // the same constraint the kernels themselves are written under.
        let mut left = [0.0_f32; 128];
        let mut right = [0.0_f32; 128];
        for (index, slot) in left.iter_mut().enumerate() {
            *slot = (index % 7) as f32 * 0.25 - 0.75;
        }
        for (index, slot) in right.iter_mut().enumerate() {
            *slot = (index % 5) as f32 * 0.5 - 1.0;
        }

        for width in [4_usize, 8, 64, 128] {
            let produced = dot_product(&left[..width], &right[..width]);
            let expected = serial(&left[..width], &right[..width]);
            // Not bit-identical, and it cannot be: four partial sums accumulate
            // in a different order than one running total. The bound is what
            // the format leaves free, and it is tight enough that a transposed
            // index or a dropped lane fails it.
            assert!(
                (produced - expected).abs() <= expected.abs().max(1.0) * 1e-5,
                "width {width}: {produced} vs {expected}"
            );
        }
    }

    /// The tail exists for a `d_head` that is not a multiple of four.
    ///
    /// Every model seen so far has a power-of-two head width, so this path is
    /// reached by no real config -- which is exactly why it needs a test. A
    /// kernel that is silently wrong on the first model that does not is worse
    /// than the six lines that handle it.
    #[test]
    fn a_width_that_is_not_a_multiple_of_four_still_sums_every_element() {
        let mut left = [0.0_f32; 64];
        for (index, slot) in left.iter_mut().enumerate() {
            *slot = (index as f32) + 1.0;
        }
        let right = [1.0_f32; 64];

        for width in [1_usize, 2, 3, 5, 7, 9, 63] {
            // With a right side of all ones the answer is the sum 1..=width,
            // known in closed form, so a dropped tail element is visible rather
            // than merely different.
            let expected = (width * (width + 1) / 2) as f32;
            let produced = dot_product(&left[..width], &right[..width]);
            assert!(
                (produced - expected).abs() <= expected.abs().max(1.0) * 1e-5,
                "width {width}: {produced} should be {expected}; an element \
                 past the last full group of {DOT_LANES} was dropped"
            );
        }
    }

    #[test]
    fn an_empty_dot_is_zero_rather_than_a_panic() {
        assert_eq!(dot_product(&[], &[]), 0.0);
    }

    #[test]
    fn accumulate_weighted_adds_rather_than_overwrites() {
        // The name says `+=` and the attention loop depends on it: every
        // position folds into the same destination, so an assignment here
        // would silently keep only the last one.
        let value = [1.0_f32, 2.0, 3.0];
        let mut destination = [10.0_f32, 20.0, 30.0];
        accumulate_weighted(2.0, &value, &mut destination);
        assert_eq!(destination, [12.0, 24.0, 36.0]);
        accumulate_weighted(0.5, &value, &mut destination);
        assert_eq!(destination, [12.5, 25.0, 37.5]);
    }
}
