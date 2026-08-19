//! Borrowed model weights, and the shape agreement they are checked against
//! before a single token is decoded.
//!
//! Nothing here owns a byte. Every field is a slice borrowed from the reserved
//! weights region, exactly as `brainix_bxw1::Tensor::data` hands it over
//! (`INV-MEM`).
//!
//! # Why `F32` weights arrive as `&[f32]` and not as `&[u8]`
//!
//! BXW1 hands a tensor payload over as `&[u8]`, and this crate wants `&[f32]`,
//! because [`brainix_tensor::matmul_f32`] wants `&[f32]`. Bridging the two is
//! exactly three things and no others: a reinterpreting cast (`unsafe`, which
//! this crate forbids), a copy into an `f32` buffer (an allocation or a
//! second full-size buffer, which `INV-MEM` forbids), or a byte-backed `f32`
//! matmul kernel (a change to `brainix_tensor`, which is not P3-T6's to make).
//!
//! So the cast stays where it belongs: **one audited seam in `modeld`**, at the
//! point where a validated blob becomes a servable model, where the region base
//! is known to be page-aligned and every tensor is known to be 128-byte aligned
//! within it (BXW1 §4.4) and the target is known to be little-endian (§2). Every
//! consumer downstream of that seam — this crate included — sees typed slices
//! and never re-derives the argument.
//!
//! # Q8_0 token embeddings: the kernel gap is closed, this crate's is not
//!
//! BXW1 §6.2 permits `tok_embeddings.weight` to be `Q8_0`, and the embedding
//! lookup needs **one row** of it. Materializing the whole `vocab × d_model`
//! matrix to reach that row would need a buffer 3.56× the tensor's stored size,
//! which is precisely what `Q8_0` exists to avoid and what `INV-MEM` forbids.
//! `brainix_tensor::Q8Weights::dequantize_row_into` now dequantizes a single row
//! into a caller-supplied slice, so the kernel-side gap no longer exists.
//!
//! **This crate has not taken it up.** [`ModelWeights::token_embeddings`] is
//! still `&[f32]` and [`Model::embed`](crate::Model) still copies a row, so a
//! `Q8_0` embedding table is still not servable *here*; what changed is that
//! closing it is now a change to this crate alone. Doing so is not free — a
//! dequantized row is `d_model` floats that must land somewhere, which means a
//! workspace view and a sizing change — so it is named rather than assumed.
//!
//! Every *projection*, including a tied logit projection through the embedding
//! table, already takes either dtype: a projection is a matmul, not a lookup.

use crate::dispatch::{chunk_len, Dispatch};
use brainix_tensor::{
    matmul_f32, matmul_q4_0_q8a, matmul_q8_0, matmul_q8_0_q8a, matmul_q8_0_q8a_rows,
    quantize_activations, MatMulShape, Q4Weights, Q8Weights,
};
use core::sync::atomic::{AtomicBool, Ordering};

use crate::config::{checked_product, ModelConfig};
use crate::error::TransformerError;

/// One weight matrix, stored `[out_features, in_features]` row-major
/// (BXW1 §6.1), in either dtype the format permits.
///
/// The `F32` variant carries no shape of its own, so its shape agreement is a
/// length check against the hyperparameters; the `Q8_0` variant carries its own
/// extents, and both are checked against the configuration with no precedence
/// rule (BXW1 §7.5).
#[derive(Debug, Clone, Copy)]
pub enum WeightMatrix<'a> {
    /// BXW1 `F32`: exactly `out_features × in_features` values, row-major.
    Float32(&'a [f32]),
    /// BXW1 `Q8_0`: the split-plane view over the borrowed payload.
    Quantized8(Q8Weights<'a>),
    /// BXW1 `Q4_0`: the split-plane view, two weights per byte.
    ///
    /// **0.625 bytes per weight against `Q8_0`'s 1.125.** Two things about this
    /// path differ from `Q8_0` and both are visible from here:
    ///
    /// - **There is no `f32`-activation kernel.** `Q8_0` keeps one so a caller
    ///   who supplies no quantization scratch gets the higher-precision result;
    ///   `Q4_0` has only the `SDOT` form, so it refuses rather than silently
    ///   computing something else.
    /// - **There is no row-split kernel**, so a `Q4_0` projection runs on the
    ///   calling core even when the dispatcher has workers idle. Since four
    ///   workers on `Q8_0` are worth 1.37x end to end, `Q4_0` has to beat that
    ///   on bytes alone before it is a win at all.
    Quantized4(Q4Weights<'a>),
}

impl WeightMatrix<'_> {
    /// Refuses unless the matrix is exactly `[out_features, in_features]`.
    ///
    /// Runs at [`Model::new`](crate::Model::new) time, over every matrix, so a
    /// shape disagreement is a construction error and never a mid-token one.
    ///
    /// # Errors
    ///
    /// [`TransformerError::WeightShapeMismatch`] in either direction — short
    /// would truncate, long means the caller and the configuration disagree.
    pub fn expect_shape(
        &self,
        out_features: usize,
        in_features: usize,
    ) -> Result<(), TransformerError> {
        let agrees = match self {
            Self::Float32(values) => values.len() == checked_product(out_features, in_features)?,
            Self::Quantized8(weights) => {
                weights.n_out() == out_features && weights.n_in() == in_features
            }
            Self::Quantized4(weights) => {
                weights.n_out() == out_features && weights.n_in() == in_features
            }
        };
        if agrees {
            Ok(())
        } else {
            Err(TransformerError::WeightShapeMismatch)
        }
    }

    /// `y = W xᵀ` for `shape.n_tokens` tokens at once.
    ///
    /// The dispatch is the only place dtype is branched on, and it is branched
    /// on once per projection per layer — never inside a loop over elements.
    ///
    /// # Errors
    ///
    /// [`TransformerError::Kernel`] carrying whichever shape rule the kernel
    /// refused.
    pub(crate) fn project<D: Dispatch>(
        &self,
        shape: MatMulShape,
        activations: &[f32],
        quant_scratch: &mut [u8],
        dispatch: &D,
        destination: &mut [f32],
    ) -> Result<(), TransformerError> {
        match self {
            Self::Float32(values) => matmul_f32(shape, values, activations, destination)?,
            Self::Quantized8(weights) => {
                // Quantize the activations and take the `SDOT` path when the
                // caller supplied room for it; fall back to the `f32`-activation
                // kernel otherwise.
                //
                // The fallback is not a nicety. The two kernels do not compute
                // the same thing -- quantizing activations is lossy -- so a
                // caller that has not opted in by supplying the buffer keeps the
                // higher-precision result, and the choice is visible at the call
                // site rather than buried here.
                let needed = Q8Weights::derived_payload_len(shape.n_tokens, shape.n_in)?;
                match quant_scratch.get_mut(..needed) {
                    Some(scratch) => {
                        quantize_activations(shape.n_tokens, shape.n_in, activations, scratch)?;
                        let view = Q8Weights::new(scratch, shape.n_tokens, shape.n_in)?;
                        // Row-splitting is only sound for a single token: for
                        // `n_tokens > 1` the output is `[n_tokens, n_out]`
                        // row-major, so a contiguous range of *output rows* is
                        // not a contiguous range of `destination`. Prefill
                        // therefore stays serial here and parallelizes over
                        // tokens elsewhere.
                        // Weight bytes this projection moves: `Q8_0` costs 1.125 per
                        // element. Compared against the dispatcher's threshold
                        // so that work smaller than a synchronization stays on
                        // the calling core.
                        let weight_bytes =
                            shape.n_out.saturating_mul(shape.n_in).saturating_mul(9) / 8;
                        let worth_splitting = weight_bytes >= dispatch.minimum_split_bytes();
                        if shape.n_tokens == 1 && dispatch.chunks() > 1 && worth_splitting {
                            let width = chunk_len(shape.n_out, dispatch.chunks())?;
                            // Chunks run on other threads, so the closure is
                            // `Fn + Sync` and cannot carry a `Result` out. An
                            // atomic flag is the most a shared closure can set
                            // without allocation or a lock.
                            //
                            // **The specific kernel error is lost, and that is a
                            // deliberate narrowing rather than an oversight.**
                            // Every argument here is derived from shapes this
                            // function has already validated against the weight
                            // view, so a refusal is a bug in the split
                            // arithmetic and not a runtime condition. The flag
                            // exists so that such a bug is loud instead of
                            // producing a silently half-written output.
                            let failed = AtomicBool::new(false);
                            dispatch.for_each_chunk(destination, width, |index, chunk| {
                                let start = index.saturating_mul(width);
                                if matmul_q8_0_q8a_rows(
                                    shape,
                                    weights,
                                    &view,
                                    start,
                                    chunk.len(),
                                    chunk,
                                )
                                .is_err()
                                // Unreachable. Every shape here came from a
                                // validated ModelConfig and a chunk_len width,
                                // so the kernel cannot refuse. The split path
                                // itself IS tested, in split_dispatch.rs; only
                                // this refusal cannot be provoked, and the flag
                                // exists to catch a refactor that breaks the
                                // agreement between those two.
                                // COVERAGE-EXEMPT: see the note above.
                                {
                                    // COVERAGE-EXEMPT: see the note above.
                                    failed.store(true, Ordering::Relaxed);
                                }
                            });
                            if failed.load(Ordering::Relaxed) {
                                // COVERAGE-EXEMPT: as above. The specific
                                // kernel error is lost because a `Fn` closure
                                // shared across threads cannot carry a `Result`
                                // out without allocating; the flag is the most
                                // it can set.
                                return Err(TransformerError::WeightShapeMismatch);
                            }
                        } else {
                            matmul_q8_0_q8a(shape, weights, &view, destination)?;
                        }
                    }
                    None => matmul_q8_0(shape, weights, activations, destination)?,
                }
            }
            Self::Quantized4(weights) => {
                // No fallback here, unlike `Quantized8`. There is no
                // `f32`-activation `Q4_0` kernel, so an empty scratch is a
                // caller error rather than a quieter path: computing the
                // projection some other way would silently change what the
                // model is.
                let needed = Q8Weights::derived_payload_len(shape.n_tokens, shape.n_in)?;
                let Some(scratch) = quant_scratch.get_mut(..needed) else {
                    return Err(TransformerError::WorkspaceTooSmall);
                };
                quantize_activations(shape.n_tokens, shape.n_in, activations, scratch)?;
                let view = Q8Weights::new(scratch, shape.n_tokens, shape.n_in)?;
                // Serial: there is no row-split `Q4_0` kernel yet, so the
                // dispatcher is unused on this path and every projection runs
                // on the calling core.
                matmul_q4_0_q8a(shape, weights, &view, destination)?;
            }
        }
        Ok(())
    }
}

/// The nine tensors of one transformer block, in BXW1 §6.2's naming.
///
/// The SwiGLU composition is `w2( SiLU(w1 x) ⊙ (w3 x) )`: `w1` gates, `w3` lifts,
/// `w2` projects back down. The field names say which is which, because the
/// two-of-three that are interchangeable by shape are not interchangeable by
/// meaning and swapping them produces a model that runs.
#[derive(Debug, Clone, Copy)]
pub struct LayerWeights<'a> {
    /// `layers.{l}.attention_norm.weight`, `[d_model]`, `F32` only.
    pub attention_norm: &'a [f32],
    /// `layers.{l}.attention.wq.weight`, `[n_heads × d_head, d_model]`.
    pub query_projection: WeightMatrix<'a>,
    /// `layers.{l}.attention.wk.weight`, `[n_kv_heads × d_head, d_model]`.
    pub key_projection: WeightMatrix<'a>,
    /// `layers.{l}.attention.wv.weight`, `[n_kv_heads × d_head, d_model]`.
    pub value_projection: WeightMatrix<'a>,
    /// `layers.{l}.attention.wo.weight`, `[d_model, n_heads × d_head]`.
    pub attention_output_projection: WeightMatrix<'a>,
    /// `layers.{l}.ffn_norm.weight`, `[d_model]`, `F32` only.
    pub feed_forward_norm: &'a [f32],
    /// `layers.{l}.feed_forward.w1.weight`, `[d_ffn, d_model]` — the **gate**.
    pub gate_projection: WeightMatrix<'a>,
    /// `layers.{l}.feed_forward.w3.weight`, `[d_ffn, d_model]` — the **up**
    /// projection.
    pub up_projection: WeightMatrix<'a>,
    /// `layers.{l}.feed_forward.w2.weight`, `[d_model, d_ffn]` — the **down**
    /// projection.
    pub down_projection: WeightMatrix<'a>,
}

impl LayerWeights<'_> {
    /// Refuses unless every tensor in the block has the shape BXW1 §5.3
    /// requires.
    ///
    /// # Errors
    ///
    /// [`TransformerError::WeightShapeMismatch`], or
    /// [`TransformerError::DimensionOverflow`].
    fn validate(&self, config: &ModelConfig) -> Result<(), TransformerError> {
        expect_vector(self.attention_norm, config.model_width)?;
        expect_vector(self.feed_forward_norm, config.model_width)?;
        self.validate_attention(config)?;
        self.validate_feed_forward(config)
    }

    fn validate_attention(&self, config: &ModelConfig) -> Result<(), TransformerError> {
        let query_width = config.query_width()?;
        let key_value_width = config.key_value_width()?;
        self.query_projection
            .expect_shape(query_width, config.model_width)?;
        self.key_projection
            .expect_shape(key_value_width, config.model_width)?;
        self.value_projection
            .expect_shape(key_value_width, config.model_width)?;
        self.attention_output_projection
            .expect_shape(config.model_width, query_width)
    }

    fn validate_feed_forward(&self, config: &ModelConfig) -> Result<(), TransformerError> {
        self.gate_projection
            .expect_shape(config.feed_forward_width, config.model_width)?;
        self.up_projection
            .expect_shape(config.feed_forward_width, config.model_width)?;
        self.down_projection
            .expect_shape(config.model_width, config.feed_forward_width)
    }
}

/// How logits are produced from the final hidden state.
///
/// BXW1 expresses weight tying with a flag rather than with two records
/// pointing at one extent (§6.3), and this enum is that flag after decoding:
/// `Tied` names no matrix at all, so there is no way to hand over a "tied"
/// model that also carries a separate output matrix.
#[derive(Debug, Clone, Copy)]
pub enum LogitProjection<'a> {
    /// `BXW1_FLAG_TIED_OUTPUT` was set: the output projection reuses
    /// `tok_embeddings.weight` and `output.weight` is absent.
    Tied,
    /// `output.weight`, `[vocab_size, d_model]`.
    Separate(WeightMatrix<'a>),
}

/// A whole model's borrowed weights.
#[derive(Debug, Clone, Copy)]
pub struct ModelWeights<'a> {
    /// `tok_embeddings.weight`, `[vocab_size, d_model]`, row-major.
    ///
    /// `F32` only — see the module documentation for why a `Q8_0` embedding
    /// table is not servable through this crate and what taking it up costs.
    pub token_embeddings: &'a [f32],
    /// Exactly `n_layers` blocks, in order.
    pub layers: &'a [LayerWeights<'a>],
    /// `norm.weight`, `[d_model]`, `F32` only.
    pub final_norm: &'a [f32],
    /// `output.weight`, or the tied marker.
    pub logit_projection: LogitProjection<'a>,
}

impl<'a> ModelWeights<'a> {
    /// Refuses unless every tensor agrees with `config` (BXW1 §5.3).
    ///
    /// # Errors
    ///
    /// [`TransformerError::LayerCountDisagreesWithConfig`],
    /// [`TransformerError::WeightShapeMismatch`], or
    /// [`TransformerError::DimensionOverflow`].
    pub fn validate(&self, config: &ModelConfig) -> Result<(), TransformerError> {
        if self.layers.len() != config.layer_count {
            return Err(TransformerError::LayerCountDisagreesWithConfig);
        }
        self.validate_global(config)?;
        for layer in self.layers {
            layer.validate(config)?;
        }
        Ok(())
    }

    fn validate_global(&self, config: &ModelConfig) -> Result<(), TransformerError> {
        expect_vector(self.final_norm, config.model_width)?;
        let embedding_elements = checked_product(config.vocabulary_size, config.model_width)?;
        if self.token_embeddings.len() != embedding_elements {
            return Err(TransformerError::WeightShapeMismatch);
        }
        self.logit_matrix()
            .expect_shape(config.vocabulary_size, config.model_width)
    }

    /// The matrix the logit projection actually multiplies by.
    ///
    /// Tying resolves here, once, rather than at every token: a tied model
    /// projects through the embedding table itself, which is the same bytes and
    /// therefore the same `[vocab_size, d_model]` shape.
    pub(crate) fn logit_matrix(&self) -> WeightMatrix<'a> {
        match self.logit_projection {
            LogitProjection::Tied => WeightMatrix::Float32(self.token_embeddings),
            LogitProjection::Separate(matrix) => matrix,
        }
    }
}

/// Refuses unless a rank-1 norm weight is exactly `width` long.
fn expect_vector(values: &[f32], width: usize) -> Result<(), TransformerError> {
    if values.len() == width {
        Ok(())
    } else {
        Err(TransformerError::WeightShapeMismatch)
    }
}
