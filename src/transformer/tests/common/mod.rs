//! The tiny model fixture and the reference forward pass.
//!
//! Everything in here is written for **clarity, not speed**. `std` is
//! available, `f64` is used freely, allocation is fine, and every routine is
//! the most obvious transcription of the formula it implements. That is the
//! whole point: the forward pass under test caches, batches and runs in `f32`,
//! and is therefore not obviously correct by inspection, so the thing it is
//! compared against has to be.
//!
//! **Nothing here calls into `brainix_transformer` or `brainix_tensor` for its
//! arithmetic.** The reference recomputes attention over the whole prompt from
//! scratch with no cache at all, so comparing the two is a real check rather
//! than a tautology. The only crate types it touches are
//! [`brainix_tensor::RopePairing`] (an enum, not an implementation) and the
//! configuration struct.
//!
//! # The fixture's dimensions, and why each one is what it is
//!
//! | Parameter | Value | Why |
//! |---|--:|---|
//! | `layer_count` | 2 | one layer cannot catch a per-layer cache stride bug |
//! | `query_head_count` | 4 | more than one head, and more than one group |
//! | `key_value_head_count` | 2 | group size 2 — grouped-query attention genuinely engages, and is neither MHA nor MQA |
//! | `head_width` | 8 | wide enough for a rotated part and an unrotated tail |
//! | `rope_dimensions` | 4 | `< head_width`, so the unrotated tail is exercised; `≥ 4`, so the two pairings differ (they coincide at 2) |
//! | `model_width` | 32 | `= 4 × 8`, and a multiple of 32 so `Q8_0` weights are legal |
//! | `feed_forward_width` | 64 | a multiple of 32 so `w2`'s reduction dimension is `Q8_0`-legal |
//! | `vocabulary_size` | 48 | not a multiple of 32 and not a power of two, so nothing lines up by accident |
//! | `maximum_sequence_length` | 16 | long enough for a prompt, a continuation, and an exhaustion test |
//!
//! Two matrices per layer are stored `Q8_0` and the rest `F32`, so both matmul
//! kernels and both dtype branches are on the tested path.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity,
    clippy::needless_range_loop,
    clippy::too_many_lines
)]

use brainix_tensor::{Q8Weights, RopePairing};
use brainix_transformer::{LayerWeights, LogitProjection, ModelConfig, ModelWeights, WeightMatrix};

/// Elements per `Q8_0` block (BXW1 §4.2).
const Q8_0_BLOCK: usize = 32;

/// Tensor-data alignment in bytes (BXW1 §4.4).
const BXW1_ALIGN: usize = 128;

/// The fixture's hyperparameters under a chosen RoPE pairing.
#[must_use]
pub fn fixture_config(rope_pairing: RopePairing) -> ModelConfig {
    ModelConfig {
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
        rope_pairing,
    }
}

/// Deterministic xorshift64\* generator.
///
/// The tests must be reproducible on every host and must not depend on a system
/// RNG, so the generator is in the tree and seeded explicitly.
pub struct Generator(u64);

impl Generator {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        self.0 = state;
        state.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform `f32` in `[-magnitude, magnitude)`.
    pub fn symmetric(&mut self, magnitude: f64) -> f32 {
        let unit = (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
        (-magnitude + unit * 2.0 * magnitude) as f32
    }

    /// `count` values uniform in `[-magnitude, magnitude)`.
    pub fn vector(&mut self, count: usize, magnitude: f64) -> Vec<f32> {
        (0..count).map(|_| self.symmetric(magnitude)).collect()
    }

    /// `count` values uniform in `[low, high)` — used for norm weights, which
    /// are near one in a real model.
    pub fn positive_vector(&mut self, count: usize, low: f64, high: f64) -> Vec<f32> {
        (0..count)
            .map(|_| {
                let unit = (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
                (low + unit * (high - low)) as f32
            })
            .collect()
    }
}

/// A weight matrix held as both a servable form and its exact dense values.
///
/// The dense copy is what the reference multiplies by. For a `Q8_0` matrix it
/// is the dequantized values, not the pre-quantization ones, so quantization
/// error is **not** a source of divergence between the two implementations —
/// the parity assertion measures the composition, which is what is under test.
pub struct Matrix {
    /// `Q8_0` split-plane payload, when the matrix is quantized.
    pub payload: Option<Vec<u8>>,
    /// `[out_features, in_features]` row-major `f32`.
    pub dense: Vec<f32>,
    pub out_features: usize,
    pub in_features: usize,
}

impl Matrix {
    /// An `F32` matrix.
    pub fn float(generator: &mut Generator, out_features: usize, in_features: usize) -> Self {
        Self {
            payload: None,
            dense: generator.vector(out_features * in_features, 0.5),
            out_features,
            in_features,
        }
    }

    /// A `Q8_0` matrix, together with its exact dequantized values.
    pub fn quantized(generator: &mut Generator, out_features: usize, in_features: usize) -> Self {
        let values = generator.vector(out_features * in_features, 0.5);
        let payload = quantize_q8_0(&values, out_features, in_features);
        let dense = dequantize_q8_0(&payload, out_features, in_features);
        Self {
            payload: Some(payload),
            dense,
            out_features,
            in_features,
        }
    }

    /// The borrowed view the forward pass consumes.
    #[must_use]
    pub fn view(&self) -> WeightMatrix<'_> {
        match &self.payload {
            Some(payload) => WeightMatrix::Quantized8(
                Q8Weights::new(payload, self.out_features, self.in_features).unwrap(),
            ),
            None => WeightMatrix::Float32(&self.dense),
        }
    }
}

/// One layer's storage.
pub struct LayerStorage {
    pub attention_norm: Vec<f32>,
    pub query: Matrix,
    pub key: Matrix,
    pub value: Matrix,
    pub attention_output: Matrix,
    pub feed_forward_norm: Vec<f32>,
    pub gate: Matrix,
    pub up: Matrix,
    pub down: Matrix,
}

/// The whole fixture: hyperparameters plus owned, deterministic weights.
pub struct Fixture {
    pub config: ModelConfig,
    pub token_embeddings: Vec<f32>,
    pub final_norm: Vec<f32>,
    pub output: Matrix,
    pub layers: Vec<LayerStorage>,
    /// Whether the output projection is tied to the embedding table.
    pub tied: bool,
}

impl Fixture {
    /// Builds a fixture with untied output weights.
    #[must_use]
    pub fn new(config: ModelConfig, seed: u64) -> Self {
        Self::build(config, seed, false)
    }

    /// Builds a fixture whose output projection reuses the embedding table.
    #[must_use]
    pub fn tied(config: ModelConfig, seed: u64) -> Self {
        Self::build(config, seed, true)
    }

    fn build(config: ModelConfig, seed: u64, tied: bool) -> Self {
        let mut generator = Generator::new(seed);
        let query_width = config.query_head_count * config.head_width;
        let key_value_width = config.key_value_head_count * config.head_width;
        let layers = (0..config.layer_count)
            .map(|_| LayerStorage {
                attention_norm: generator.positive_vector(config.model_width, 0.5, 1.5),
                // wq and w1 are Q8_0; the rest are F32, so both matmul kernels
                // and both dtype branches are on the tested path.
                query: Matrix::quantized(&mut generator, query_width, config.model_width),
                key: Matrix::float(&mut generator, key_value_width, config.model_width),
                value: Matrix::float(&mut generator, key_value_width, config.model_width),
                attention_output: Matrix::float(&mut generator, config.model_width, query_width),
                feed_forward_norm: generator.positive_vector(config.model_width, 0.5, 1.5),
                gate: Matrix::quantized(
                    &mut generator,
                    config.feed_forward_width,
                    config.model_width,
                ),
                up: Matrix::float(
                    &mut generator,
                    config.feed_forward_width,
                    config.model_width,
                ),
                down: Matrix::float(
                    &mut generator,
                    config.model_width,
                    config.feed_forward_width,
                ),
            })
            .collect();
        let token_embeddings = generator.vector(config.vocabulary_size * config.model_width, 0.5);
        let output = Matrix::float(&mut generator, config.vocabulary_size, config.model_width);
        Self {
            config,
            token_embeddings,
            final_norm: generator.positive_vector(config.model_width, 0.5, 1.5),
            output,
            layers,
            tied,
        }
    }

    /// The borrowed per-layer views. Kept as a local in each test so that
    /// [`Self::weights`] can borrow it alongside the fixture.
    #[must_use]
    pub fn layer_views(&self) -> Vec<LayerWeights<'_>> {
        self.layers
            .iter()
            .map(|layer| LayerWeights {
                attention_norm: &layer.attention_norm,
                query_projection: layer.query.view(),
                key_projection: layer.key.view(),
                value_projection: layer.value.view(),
                attention_output_projection: layer.attention_output.view(),
                feed_forward_norm: &layer.feed_forward_norm,
                gate_projection: layer.gate.view(),
                up_projection: layer.up.view(),
                down_projection: layer.down.view(),
            })
            .collect()
    }

    /// The borrowed model weights.
    #[must_use]
    pub fn weights<'a>(&'a self, layers: &'a [LayerWeights<'a>]) -> ModelWeights<'a> {
        ModelWeights {
            token_embeddings: &self.token_embeddings,
            layers,
            final_norm: &self.final_norm,
            logit_projection: if self.tied {
                LogitProjection::Tied
            } else {
                LogitProjection::Separate(self.output.view())
            },
        }
    }

    /// The dense matrix the reference projects logits through.
    fn logit_dense(&self) -> &[f32] {
        if self.tied {
            &self.token_embeddings
        } else {
            &self.output.dense
        }
    }
}

// ------------------------------------------------------------ Q8_0 producer

fn pad_to_align(length: usize) -> usize {
    length.div_ceil(BXW1_ALIGN) * BXW1_ALIGN
}

/// BXW1 §4.2's producer formula, verbatim. Nothing in BraiNIX quantizes at
/// runtime; the off-box converter does, and this stands in for it.
pub fn quantize_q8_0(values: &[f32], out_features: usize, in_features: usize) -> Vec<u8> {
    assert_eq!(values.len(), out_features * in_features);
    assert_eq!(in_features % Q8_0_BLOCK, 0, "BXW1 rule D8");
    let blocks = values.len() / Q8_0_BLOCK;
    let quant_offset = pad_to_align(blocks * 4);
    let mut payload = vec![0_u8; quant_offset + blocks * Q8_0_BLOCK];
    for block in 0..blocks {
        let window = &values[block * Q8_0_BLOCK..(block + 1) * Q8_0_BLOCK];
        let peak = window.iter().fold(0.0_f32, |best, v| best.max(v.abs()));
        let scale: f32 = if peak == 0.0 { 0.0 } else { peak / 127.0 };
        payload[block * 4..block * 4 + 4].copy_from_slice(&scale.to_le_bytes());
        for (offset, value) in window.iter().enumerate() {
            let quant: i8 = if scale == 0.0 {
                0
            } else {
                (value / scale).round_ties_even().clamp(-127.0, 127.0) as i8
            };
            payload[quant_offset + block * Q8_0_BLOCK + offset] = quant as u8;
        }
    }
    payload
}

/// The exact values a `Q8_0` payload denotes: `x = scale[b] × q`.
pub fn dequantize_q8_0(payload: &[u8], out_features: usize, in_features: usize) -> Vec<f32> {
    let blocks = out_features * in_features / Q8_0_BLOCK;
    let quant_offset = pad_to_align(blocks * 4);
    let mut values = Vec::with_capacity(out_features * in_features);
    for block in 0..blocks {
        let scale = f32::from_le_bytes([
            payload[block * 4],
            payload[block * 4 + 1],
            payload[block * 4 + 2],
            payload[block * 4 + 3],
        ]);
        for offset in 0..Q8_0_BLOCK {
            let quant = payload[quant_offset + block * Q8_0_BLOCK + offset] as i8;
            values.push(scale * f32::from(quant));
        }
    }
    values
}

// -------------------------------------------------------- reference kernels

/// `y = W x`, `W` stored `[out_features, in_features]` row-major.
fn matrix_vector(weights: &[f32], x: &[f64], out_features: usize, in_features: usize) -> Vec<f64> {
    assert_eq!(weights.len(), out_features * in_features);
    assert_eq!(x.len(), in_features);
    (0..out_features)
        .map(|out| {
            (0..in_features)
                .map(|inner| f64::from(weights[out * in_features + inner]) * x[inner])
                .sum()
        })
        .collect()
}

/// `out[i] = x[i] · rsqrt(mean(x²) + ε) · w[i]`, ε inside the root.
fn rms_norm(x: &[f64], weight: &[f32], epsilon: f32) -> Vec<f64> {
    let mean_square = x.iter().map(|v| v * v).sum::<f64>() / (x.len() as f64);
    let scale = 1.0 / (mean_square + f64::from(epsilon)).sqrt();
    x.iter()
        .zip(weight.iter())
        .map(|(v, w)| v * scale * f64::from(*w))
        .collect()
}

/// Rotary position embedding over `[heads, head_width]`, both conventions.
fn rotary(
    x: &[f64],
    head_width: usize,
    rope_dimensions: usize,
    base: f32,
    pairing: RopePairing,
    position: usize,
) -> Vec<f64> {
    let mut out = x.to_vec();
    let pairs = rope_dimensions / 2;
    for head in 0..(x.len() / head_width) {
        for pair in 0..pairs {
            let (low, high) = match pairing {
                RopePairing::Interleaved => (2 * pair, 2 * pair + 1),
                RopePairing::HalfSplit => (pair, pair + pairs),
            };
            let frequency = f64::from(base).powf(-2.0 * (pair as f64) / (rope_dimensions as f64));
            let angle = (position as f64) * frequency;
            let (sine, cosine) = (angle.sin(), angle.cos());
            let first = x[head * head_width + low];
            let second = x[head * head_width + high];
            out[head * head_width + low] = first * cosine - second * sine;
            out[head * head_width + high] = first * sine + second * cosine;
        }
    }
    out
}

/// Numerically stable softmax over one row.
fn soft_max(scores: &[f64]) -> Vec<f64> {
    let peak = scores.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let terms: Vec<f64> = scores.iter().map(|s| (s - peak).exp()).collect();
    let total: f64 = terms.iter().sum();
    terms.iter().map(|t| t / total).collect()
}

fn silu(value: f64) -> f64 {
    value / (1.0 + (-value).exp())
}

// -------------------------------------------------------- reference forward

/// The reference forward pass: no cache, no batching, everything recomputed.
///
/// Returns the logits of the **last** token of `tokens`, which is what
/// [`brainix_transformer::Model::forward`] produces.
#[must_use]
pub fn reference_logits(fixture: &Fixture, tokens: &[u32]) -> Vec<f64> {
    let config = &fixture.config;
    let head_width = config.head_width;
    let query_width = config.query_head_count * head_width;
    let key_value_width = config.key_value_head_count * head_width;
    let group_size = config.query_head_count / config.key_value_head_count;
    let scale = 1.0 / (head_width as f64).sqrt();

    // The residual stream, one row per token.
    let mut hidden: Vec<Vec<f64>> = tokens
        .iter()
        .map(|token| {
            let start = (*token as usize) * config.model_width;
            fixture.token_embeddings[start..start + config.model_width]
                .iter()
                .map(|v| f64::from(*v))
                .collect()
        })
        .collect();

    for layer in &fixture.layers {
        // Attention.
        let mut rotated_queries = Vec::new();
        let mut rotated_keys = Vec::new();
        let mut values = Vec::new();
        for (position, row) in hidden.iter().enumerate() {
            let normed = rms_norm(row, &layer.attention_norm, config.normalization_epsilon);
            let query = matrix_vector(&layer.query.dense, &normed, query_width, config.model_width);
            let key = matrix_vector(
                &layer.key.dense,
                &normed,
                key_value_width,
                config.model_width,
            );
            let value = matrix_vector(
                &layer.value.dense,
                &normed,
                key_value_width,
                config.model_width,
            );
            rotated_queries.push(rotary(
                &query,
                head_width,
                config.rope_dimensions,
                config.rope_theta,
                config.rope_pairing,
                position,
            ));
            rotated_keys.push(rotary(
                &key,
                head_width,
                config.rope_dimensions,
                config.rope_theta,
                config.rope_pairing,
                position,
            ));
            values.push(value);
        }

        let mut attention_rows = Vec::new();
        for position in 0..hidden.len() {
            let mut row = vec![0.0_f64; query_width];
            for head in 0..config.query_head_count {
                let group = head / group_size;
                let query = &rotated_queries[position][head * head_width..(head + 1) * head_width];
                let scores: Vec<f64> = (0..=position)
                    .map(|other| {
                        let key =
                            &rotated_keys[other][group * head_width..(group + 1) * head_width];
                        query
                            .iter()
                            .zip(key.iter())
                            .map(|(a, b)| a * b)
                            .sum::<f64>()
                            * scale
                    })
                    .collect();
                let weights = soft_max(&scores);
                for (other, weight) in weights.iter().enumerate() {
                    let value = &values[other][group * head_width..(group + 1) * head_width];
                    for (offset, component) in value.iter().enumerate() {
                        row[head * head_width + offset] += weight * component;
                    }
                }
            }
            attention_rows.push(row);
        }

        for (row, attention) in hidden.iter_mut().zip(attention_rows.iter()) {
            let projected = matrix_vector(
                &layer.attention_output.dense,
                attention,
                config.model_width,
                query_width,
            );
            for (slot, value) in row.iter_mut().zip(projected.iter()) {
                *slot += value;
            }
        }

        // Feed-forward.
        for row in hidden.iter_mut() {
            let normed = rms_norm(row, &layer.feed_forward_norm, config.normalization_epsilon);
            let gate = matrix_vector(
                &layer.gate.dense,
                &normed,
                config.feed_forward_width,
                config.model_width,
            );
            let up = matrix_vector(
                &layer.up.dense,
                &normed,
                config.feed_forward_width,
                config.model_width,
            );
            let activated: Vec<f64> = gate
                .iter()
                .zip(up.iter())
                .map(|(g, u)| silu(*g) * u)
                .collect();
            let down = matrix_vector(
                &layer.down.dense,
                &activated,
                config.model_width,
                config.feed_forward_width,
            );
            for (slot, value) in row.iter_mut().zip(down.iter()) {
                *slot += value;
            }
        }
    }

    let last = hidden.last().expect("a prompt has at least one token");
    let normed = rms_norm(last, &fixture.final_norm, config.normalization_epsilon);
    matrix_vector(
        fixture.logit_dense(),
        &normed,
        config.vocabulary_size,
        config.model_width,
    )
}

/// The largest absolute difference between an `f32` result and an `f64`
/// reference.
#[must_use]
pub fn largest_difference(actual: &[f32], reference: &[f64]) -> f64 {
    assert_eq!(actual.len(), reference.len());
    actual
        .iter()
        .zip(reference.iter())
        .map(|(a, r)| (f64::from(*a) - r).abs())
        .fold(0.0_f64, f64::max)
}

/// The index of the largest value, ties broken low.
#[must_use]
pub fn argmax(values: &[f64]) -> usize {
    let mut best = 0;
    for (index, value) in values.iter().enumerate() {
        if *value > values[best] {
            best = index;
        }
    }
    best
}
