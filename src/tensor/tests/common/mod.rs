//! Reference implementations and fixtures shared by the kernel tests.
//!
//! Everything in here is written for **clarity, not speed**. `std` is
//! available, `f64` is used freely, allocation is fine, and every routine is
//! the most obvious transcription of the formula it implements. That is the
//! whole point: the kernels under test are written for a bandwidth-bound
//! machine and are therefore not obviously correct by inspection, so the thing
//! they are compared against has to be.
//!
//! The `Q8_0` quantizer here is the **producer** side of BXW1 §4.2, which is
//! informative in the spec and does not exist in the crate — nothing in BraiNIX
//! quantizes at runtime; the off-box converter does. It lives in the tests
//! because the round-trip assertion needs it and nothing else does.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

use brainix_tensor::{BXW1_ALIGN, Q8_0_BLOCK};

/// Unit roundoff for binary32: `2⁻²⁴`. Half of `f32::EPSILON`.
pub const F32_UNIT_ROUNDOFF: f64 = 5.960_464_477_539_063e-8;

/// Deterministic xorshift64\* generator.
///
/// The tests must be reproducible on every host and must not depend on a
/// system RNG, so the generator is in the tree and seeded explicitly per test.
pub struct Rng(u64);

impl Rng {
    /// Seeds the generator. Any non-zero seed is fine.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform `f64` in `[low, high)`.
    pub fn range(&mut self, low: f64, high: f64) -> f64 {
        let unit = (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0);
        low + unit * (high - low)
    }

    /// Uniform `f32` in `[-magnitude, magnitude)`.
    pub fn symmetric_f32(&mut self, magnitude: f64) -> f32 {
        self.range(-magnitude, magnitude) as f32
    }

    /// `count` values uniform in `[-magnitude, magnitude)`.
    pub fn vector(&mut self, count: usize, magnitude: f64) -> Vec<f32> {
        (0..count).map(|_| self.symmetric_f32(magnitude)).collect()
    }
}

/// The value of a dot product together with the sum of the magnitudes of its
/// terms.
///
/// Both are needed: the value is what the kernel is compared against, and
/// `abs_sum` is what the error bound is proportional to. The classical forward
/// error bound for a length-`n` floating-point dot product is
/// `|fl(dot) − dot| ≤ γ_n · Σ|a_i·b_i|` with `γ_n = n·u/(1 − n·u)` — a bound on
/// the *absolute* error that says nothing useful about relative error when the
/// terms cancel, which is exactly what happens with random signed inputs.
pub struct DotRef {
    /// The dot product, accumulated in `f64`.
    pub value: f64,
    /// `Σ|a_i · b_i|`, the magnitude the error bound scales with.
    pub abs_sum: f64,
}

/// Reference dot product: one term at a time, `f64` accumulator.
pub fn ref_dot(a: &[f32], b: &[f32]) -> DotRef {
    assert_eq!(a.len(), b.len());
    let mut value = 0.0_f64;
    let mut abs_sum = 0.0_f64;
    for i in 0..a.len() {
        let term = f64::from(a[i]) * f64::from(b[i]);
        value += term;
        abs_sum += term.abs();
    }
    DotRef { value, abs_sum }
}

/// The tolerance a length-`n` `f32` dot product is allowed against a `f64`
/// reference of the same terms.
///
/// Twice the classical bound, so the assertion is a real check rather than a
/// tripwire that fires on ordinary rounding. The additive floor keeps the
/// bound meaningful when every term is zero.
pub fn dot_tolerance(n: usize, abs_sum: f64) -> f64 {
    2.0 * (n as f64) * F32_UNIT_ROUNDOFF * abs_sum + 1e-30
}

/// Reference `f32` matmul: `weights` is `[n_out, n_in]`, `x` is
/// `[n_tokens, n_in]`, result is `[n_tokens, n_out]`.
///
/// Returns one [`DotRef`] per output element, in the output's own order, so a
/// caller has both the expected value and its tolerance.
pub fn ref_matmul(
    weights: &[f32],
    x: &[f32],
    n_tokens: usize,
    n_in: usize,
    n_out: usize,
) -> Vec<DotRef> {
    assert_eq!(weights.len(), n_out * n_in);
    assert_eq!(x.len(), n_tokens * n_in);
    let mut out = Vec::with_capacity(n_tokens * n_out);
    for t in 0..n_tokens {
        for o in 0..n_out {
            out.push(ref_dot(
                &weights[o * n_in..(o + 1) * n_in],
                &x[t * n_in..(t + 1) * n_in],
            ));
        }
    }
    out
}

/// Rounds `scale_len` up to a multiple of [`BXW1_ALIGN`].
fn pad_to_align(scale_len: usize) -> usize {
    scale_len.div_ceil(BXW1_ALIGN) * BXW1_ALIGN
}

/// Quantizes a row-major `f32` tensor into a BXW1 `Q8_0` split-plane payload.
///
/// This is the §4.2 producer formula, verbatim:
///
/// ```text
/// scale = max(|x_j|) / 127.0
/// q_j   = clamp(round_ties_even(x_j / scale), -127, 127)
/// ```
///
/// Using 127 rather than 128 keeps the quantized range symmetric, so this
/// producer never emits `-128`. An all-zero block gets `scale = +0.0` and 32
/// zero quants, which §4.7 explicitly admits (`s == 0x0000_0000`).
///
/// The layout is scale plane, zero pad to [`BXW1_ALIGN`], quant plane.
pub fn quantize_q8_0(values: &[f32], n_out: usize, n_in: usize) -> Vec<u8> {
    assert_eq!(values.len(), n_out * n_in);
    assert_eq!(n_in % Q8_0_BLOCK, 0, "BXW1 rule D8");

    let n_blocks = values.len() / Q8_0_BLOCK;
    let scale_len = n_blocks * 4;
    let quant_off = pad_to_align(scale_len);

    let mut payload = vec![0_u8; quant_off + n_blocks * Q8_0_BLOCK];

    for b in 0..n_blocks {
        let block = &values[b * Q8_0_BLOCK..(b + 1) * Q8_0_BLOCK];
        let max_abs = block.iter().fold(0.0_f32, |m, v| m.max(v.abs()));
        let scale: f32 = if max_abs == 0.0 { 0.0 } else { max_abs / 127.0 };

        payload[b * 4..b * 4 + 4].copy_from_slice(&scale.to_le_bytes());

        for (j, value) in block.iter().enumerate() {
            let q: i8 = if scale == 0.0 {
                0
            } else {
                (value / scale).round_ties_even().clamp(-127.0, 127.0) as i8
            };
            payload[quant_off + b * Q8_0_BLOCK + j] = q as u8;
        }
    }
    payload
}

/// Reference dequantizer: walks a `Q8_0` payload's two planes from first
/// principles and applies §4.2's normative formula
/// `x[b*32 + j] = scale[b] × (f32) q[b*32 + j]`.
///
/// Written independently of the crate's `Q8Weights::dequantize_into` so that
/// comparing the two is a real check rather than a tautology.
pub fn ref_dequantize_q8_0(payload: &[u8], n_out: usize, n_in: usize) -> Vec<f32> {
    assert_eq!(n_in % Q8_0_BLOCK, 0);
    let n_blocks = n_out * n_in / Q8_0_BLOCK;
    let quant_off = pad_to_align(n_blocks * 4);
    assert_eq!(payload.len(), quant_off + n_blocks * Q8_0_BLOCK);

    let mut out = Vec::with_capacity(n_out * n_in);
    for b in 0..n_blocks {
        let scale = f32::from_le_bytes([
            payload[b * 4],
            payload[b * 4 + 1],
            payload[b * 4 + 2],
            payload[b * 4 + 3],
        ]);
        for j in 0..Q8_0_BLOCK {
            let q = payload[quant_off + b * Q8_0_BLOCK + j] as i8;
            out.push(scale * f32::from(q));
        }
    }
    out
}

/// Reference RMSNorm, one row: `x·rsqrt(mean(x²) + ε)·w`, ε inside the root.
pub fn ref_rmsnorm(x: &[f32], weight: &[f32], eps: f32) -> Vec<f32> {
    assert_eq!(x.len(), weight.len());
    let mean_square =
        x.iter().map(|v| f64::from(*v) * f64::from(*v)).sum::<f64>() / (x.len() as f64);
    let scale = 1.0 / (mean_square + f64::from(eps)).sqrt();
    x.iter()
        .zip(weight.iter())
        .map(|(v, w)| ((f64::from(*v) * scale) as f32) * w)
        .collect()
}

/// Reference softmax in `f64`, with the row maximum subtracted.
pub fn ref_softmax(x: &[f32]) -> Vec<f64> {
    let max = x
        .iter()
        .fold(f64::NEG_INFINITY, |m, v| m.max(f64::from(*v)));
    let terms: Vec<f64> = x.iter().map(|v| (f64::from(*v) - max).exp()).collect();
    let sum: f64 = terms.iter().sum();
    terms.iter().map(|t| t / sum).collect()
}

/// Reference RoPE for one head, interleaved pairing, `f64` trigonometry.
pub fn ref_rope(head: &[f32], rope_dim: usize, base: f32, position: u32) -> Vec<f32> {
    let mut out = head.to_vec();
    for i in 0..rope_dim / 2 {
        let theta = f64::from(base).powf(-2.0 * (i as f64) / (rope_dim as f64));
        let angle = f64::from(position) * theta;
        let (sin, cos) = (angle.sin() as f32, angle.cos() as f32);
        let a = head[2 * i];
        let b = head[2 * i + 1];
        out[2 * i] = a * cos - b * sin;
        out[2 * i + 1] = a * sin + b * cos;
    }
    out
}

/// Reference SiLU in `f64`.
pub fn ref_silu(x: &[f32]) -> Vec<f32> {
    x.iter()
        .map(|v| {
            let d = f64::from(*v);
            (d / (1.0 + (-d).exp())) as f32
        })
        .collect()
}

/// Asserts `actual` is within `tolerance` of `expected`, reporting both.
pub fn assert_close(actual: f64, expected: f64, tolerance: f64, what: &str) {
    let error = (actual - expected).abs();
    assert!(
        error <= tolerance,
        "{what}: got {actual}, want {expected}, error {error} > tolerance {tolerance}"
    );
}
