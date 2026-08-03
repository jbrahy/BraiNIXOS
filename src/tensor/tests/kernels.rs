//! Randomized agreement tests: every kernel against an obvious reference.
//!
//! Each test states the tolerance it uses and where the tolerance comes from.
//! Where a bound is available from numerical analysis — the dot product's
//! `γ_n·Σ|a_i b_i|`, `Q8_0`'s `scale/2` per element — the bound is used
//! directly rather than a round number that happens to pass.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

mod common;

use brainix_tensor::{
    matmul_f32, matmul_q8_0, rmsnorm, rope, silu, softmax, swiglu, MatMulShape, Q8Weights,
    RopePairing, RopeParams, Q8_0_BLOCK,
};
use common::{
    assert_close, dot_tolerance, quantize_q8_0, ref_dequantize_q8_0, ref_dot, ref_matmul,
    ref_rmsnorm, ref_rope, ref_silu, ref_softmax, Rng, F32_UNIT_ROUNDOFF,
};

// ---------------------------------------------------------------- f32 matmul

#[test]
fn matmul_f32_matches_the_reference_on_random_shapes() {
    let mut rng = Rng::new(0x5eed_0001);
    // Shapes chosen to include a non-power-of-two n_in and n_out, several
    // tokens, and the degenerate 1x1x1 case.
    let shapes = [(1, 1, 1), (1, 1, 7), (1, 7, 1), (1, 37, 53), (5, 64, 3)];

    for (n_tokens, n_in, n_out) in shapes {
        let weights = rng.vector(n_out * n_in, 1.0);
        let x = rng.vector(n_tokens * n_in, 1.0);
        let mut y = vec![f32::NAN; n_tokens * n_out];

        let shape = MatMulShape {
            n_tokens,
            n_in,
            n_out,
        };
        matmul_f32(shape, &weights, &x, &mut y).unwrap();

        let reference = ref_matmul(&weights, &x, n_tokens, n_in, n_out);
        for (index, expected) in reference.iter().enumerate() {
            assert_close(
                f64::from(y[index]),
                expected.value,
                dot_tolerance(n_in, expected.abs_sum),
                &format!("matmul_f32 {n_tokens}x{n_in}x{n_out} element {index}"),
            );
        }
    }
}

#[test]
fn matmul_f32_is_independent_of_the_token_count() {
    // The kernel runs weights-outer, tokens-inner. Batching must not change any
    // individual token's result, which is the property that ordering choice is
    // allowed to preserve and a blocking bug would break.
    let mut rng = Rng::new(0x5eed_0002);
    let (n_in, n_out) = (96, 11);
    let weights = rng.vector(n_out * n_in, 1.0);
    let x = rng.vector(4 * n_in, 1.0);

    let mut batched = vec![0.0_f32; 4 * n_out];
    matmul_f32(
        MatMulShape {
            n_tokens: 4,
            n_in,
            n_out,
        },
        &weights,
        &x,
        &mut batched,
    )
    .unwrap();

    for token in 0..4 {
        let mut single = vec![0.0_f32; n_out];
        matmul_f32(
            MatMulShape {
                n_tokens: 1,
                n_in,
                n_out,
            },
            &weights,
            &x[token * n_in..(token + 1) * n_in],
            &mut single,
        )
        .unwrap();
        assert_eq!(&batched[token * n_out..(token + 1) * n_out], &single[..]);
    }
}

// ------------------------------------------------------------- Q8_0 round trip

#[test]
fn q8_0_round_trip_respects_the_block_error_bound() {
    // BXW1 §4.2's producer uses scale = max(|x|)/127 and a round-to-nearest
    // quantizer, so the dequantized value differs from the original by at most
    // half a quantization step: |x − x'| <= scale/2 = max(|x|)/254.
    //
    // The 1.0001 factor covers the two roundings the bound above ignores: the
    // f32 rounding of the scale itself (relative 6e-8) and of the product
    // scale×q (relative 6e-8). Both are ~1.5e-5 of the main term, so the factor
    // is four orders of magnitude of margin over what is needed and still four
    // orders tighter than the bound it is checking.
    let mut rng = Rng::new(0x5eed_0003);
    let (n_out, n_in) = (9, 160);

    for magnitude in [1e-3, 1.0, 1e3] {
        let values = rng.vector(n_out * n_in, magnitude);
        let payload = quantize_q8_0(&values, n_out, n_in);
        let restored = ref_dequantize_q8_0(&payload, n_out, n_in);

        assert_eq!(values.len(), restored.len());
        for b in 0..values.len() / Q8_0_BLOCK {
            let block = &values[b * Q8_0_BLOCK..(b + 1) * Q8_0_BLOCK];
            let max_abs = block.iter().fold(0.0_f32, |m, v| m.max(v.abs()));
            let bound = f64::from(max_abs) / 254.0 * 1.0001;
            for j in 0..Q8_0_BLOCK {
                let index = b * Q8_0_BLOCK + j;
                assert_close(
                    f64::from(restored[index]),
                    f64::from(values[index]),
                    bound,
                    &format!("q8 round trip magnitude {magnitude} element {index}"),
                );
            }
        }
    }
}

#[test]
fn q8_0_round_trip_is_exact_for_an_all_zero_block() {
    // scale = +0.0 and every quant zero. BXW1 §4.7 admits exactly +0.0, so this
    // is a legal tensor and not an edge case the format excludes.
    let values = vec![0.0_f32; Q8_0_BLOCK * 3];
    let payload = quantize_q8_0(&values, 3, Q8_0_BLOCK);
    let restored = ref_dequantize_q8_0(&payload, 3, Q8_0_BLOCK);
    assert!(restored.iter().all(|v| *v == 0.0));
}

#[test]
fn crate_dequantizer_agrees_with_the_reference_bit_for_bit() {
    // Q8Weights::dequantize_into and the reference walk the same planes with
    // the same formula, so they must agree exactly — not approximately. Any
    // difference is a plane-offset or endianness bug, not rounding.
    let mut rng = Rng::new(0x5eed_0004);
    for (n_out, n_in) in [(1, 32), (3, 64), (33, 32), (7, 96)] {
        let values = rng.vector(n_out * n_in, 2.0);
        let payload = quantize_q8_0(&values, n_out, n_in);

        let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();
        let mut crate_side = vec![f32::NAN; n_out * n_in];
        weights.dequantize_into(&mut crate_side).unwrap();

        assert_eq!(crate_side, ref_dequantize_q8_0(&payload, n_out, n_in));
    }
}

// -------------------------------------------------------------- Q8_0 matmul

#[test]
fn matmul_q8_0_agrees_with_dequantize_then_f32_matmul() {
    // The kernel computes  Σ_b scale[b]·(Σ_j q·x)  and the reference computes
    // Σ_i (scale·q)_i·x_i. Algebraically identical, differently rounded, so the
    // gap is bounded by the same dot-product bound both are subject to.
    let mut rng = Rng::new(0x5eed_0005);
    let shapes = [
        (1, 32, 1),
        (1, 32, 5),
        (1, 128, 17),
        (3, 96, 4),
        (1, 160, 33),
    ];

    for (n_tokens, n_in, n_out) in shapes {
        let raw = rng.vector(n_out * n_in, 1.0);
        let payload = quantize_q8_0(&raw, n_out, n_in);
        let dequantized = ref_dequantize_q8_0(&payload, n_out, n_in);
        let x = rng.vector(n_tokens * n_in, 1.0);

        let shape = MatMulShape {
            n_tokens,
            n_in,
            n_out,
        };
        let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();
        let mut quantized_path = vec![f32::NAN; n_tokens * n_out];
        matmul_q8_0(shape, &weights, &x, &mut quantized_path).unwrap();

        let mut f32_path = vec![f32::NAN; n_tokens * n_out];
        matmul_f32(shape, &dequantized, &x, &mut f32_path).unwrap();

        let reference = ref_matmul(&dequantized, &x, n_tokens, n_in, n_out);
        for (index, expected) in reference.iter().enumerate() {
            let tolerance = dot_tolerance(n_in, expected.abs_sum);
            assert_close(
                f64::from(quantized_path[index]),
                expected.value,
                tolerance,
                &format!("q8 matmul {n_tokens}x{n_in}x{n_out} element {index}"),
            );
            assert_close(
                f64::from(quantized_path[index]),
                f64::from(f32_path[index]),
                2.0 * tolerance,
                &format!("q8 vs dequantized f32 path element {index}"),
            );
        }
    }
}

#[test]
fn matmul_q8_0_stays_within_the_quantization_error_bound_of_the_exact_product() {
    // The end-to-end claim the format rests on: quantizing the weights perturbs
    // the projection by no more than the per-element quantization error can
    // account for. For each output, the bound is Σ_i |Δw_i · x_i| where
    // |Δw_i| <= scale(block of i)/2, plus the f32 dot product's own bound.
    let mut rng = Rng::new(0x5eed_0006);
    let (n_in, n_out) = (256, 12);
    let raw = rng.vector(n_out * n_in, 1.0);
    let payload = quantize_q8_0(&raw, n_out, n_in);
    let dequantized = ref_dequantize_q8_0(&payload, n_out, n_in);
    let x = rng.vector(n_in, 1.0);

    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();
    let mut actual = vec![f32::NAN; n_out];
    matmul_q8_0(
        MatMulShape {
            n_tokens: 1,
            n_in,
            n_out,
        },
        &weights,
        &x,
        &mut actual,
    )
    .unwrap();

    for o in 0..n_out {
        let row = &raw[o * n_in..(o + 1) * n_in];
        let restored_row = &dequantized[o * n_in..(o + 1) * n_in];
        let exact = ref_dot(row, &x);

        let quantization_error: f64 = (0..n_in)
            .map(|i| (f64::from(row[i]) - f64::from(restored_row[i])) * f64::from(x[i]))
            .map(f64::abs)
            .sum();

        assert_close(
            f64::from(actual[o]),
            exact.value,
            quantization_error + dot_tolerance(n_in, exact.abs_sum),
            &format!("q8 matmul vs exact f32, output {o}"),
        );
    }
}

// ----------------------------------------------------------------- RMSNorm

#[test]
fn rmsnorm_matches_the_reference() {
    // Both accumulate the sum of squares in f64 and both apply the same two f32
    // multiplies, so the only difference is rsqrt versus 1/sqrt. The kernel's
    // Newton iteration converges to well below f64 precision, so the gap is a
    // couple of f32 ulps of the output magnitude: 8 ulps is generous margin.
    let mut rng = Rng::new(0x5eed_0007);
    for width in [1_usize, 7, 64, 4096] {
        let x = rng.vector(width * 3, 2.0);
        let weight = rng.vector(width, 1.0);
        let eps = 1e-5_f32;

        let mut out = vec![f32::NAN; x.len()];
        rmsnorm(&x, &weight, eps, &mut out).unwrap();

        for row in 0..3 {
            let expected = ref_rmsnorm(&x[row * width..(row + 1) * width], &weight, eps);
            for i in 0..width {
                let magnitude = f64::from(expected[i]).abs();
                assert_close(
                    f64::from(out[row * width + i]),
                    f64::from(expected[i]),
                    8.0 * F32_UNIT_ROUNDOFF * magnitude + 1e-30,
                    &format!("rmsnorm width {width} row {row} element {i}"),
                );
            }
        }
    }
}

// ----------------------------------------------------------------- softmax

#[test]
fn softmax_matches_the_reference_and_sums_to_one() {
    // Every output is in [0, 1] and the reference is computed in f64, so the
    // error is dominated by the single f32 rounding of each stored term plus
    // the f32 rounding of the reciprocal: 4 ulps of 1.0 is ample and is an
    // absolute bound because the outputs are bounded.
    let mut rng = Rng::new(0x5eed_0008);
    for length in [1_usize, 2, 31, 1024] {
        for magnitude in [1e-3, 1.0, 20.0] {
            let x = rng.vector(length, magnitude);
            let mut out = vec![f32::NAN; length];
            softmax(&x, &mut out).unwrap();

            let expected = ref_softmax(&x);
            for i in 0..length {
                assert_close(
                    f64::from(out[i]),
                    expected[i],
                    4.0 * F32_UNIT_ROUNDOFF,
                    &format!("softmax length {length} magnitude {magnitude} element {i}"),
                );
            }
            let sum: f64 = out.iter().map(|v| f64::from(*v)).sum();
            assert_close(sum, 1.0, (length as f64) * F32_UNIT_ROUNDOFF, "softmax sum");
        }
    }
}

// -------------------------------------------------------------------- RoPE

#[test]
fn rope_matches_the_reference_under_both_pairings() {
    // The kernel evaluates sine and cosine in f64 and rounds to f32 before the
    // four multiplies, exactly as the reference does, so the tolerance is a few
    // ulps of the input magnitude rather than of the output — the rotation can
    // cancel, and a relative bound on a cancelled output is meaningless.
    //
    // Both conventions are exercised over the same shapes and positions: each
    // is a supported path, not a fallback, so neither gets weaker coverage.
    let mut rng = Rng::new(0x5eed_0009);
    let params_under_test = [(8_usize, 8_usize), (64, 64), (128, 64), (2, 2)];

    for pairing in [RopePairing::Interleaved, RopePairing::HalfSplit] {
        for (d_head, rope_dim) in params_under_test {
            for position in [0_u32, 1, 7, 4095, 131_072] {
                let n_heads = 3;
                let x = rng.vector(n_heads * d_head, 1.0);
                let mut out = vec![f32::NAN; x.len()];
                let params = RopeParams {
                    d_head,
                    rope_dim,
                    base: 1.0e4,
                    pairing,
                    position,
                };
                rope(&x, &params, &mut out).unwrap();

                for head in 0..n_heads {
                    let slice = &x[head * d_head..(head + 1) * d_head];
                    let expected = ref_rope(slice, rope_dim, 1.0e4, position, pairing);
                    for i in 0..d_head {
                        assert_close(
                            f64::from(out[head * d_head + i]),
                            f64::from(expected[i]),
                            1e-5,
                            &format!(
                                "rope {pairing:?} d_head {d_head} pos {position} \
                                 head {head} element {i}"
                            ),
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn the_two_pairings_produce_different_results_on_the_same_input() {
    // The assertion that proves `pairing` is load bearing rather than accepted
    // and ignored. If this ever passes trivially — because one path silently
    // dispatches to the other — the whole point of the BXW1 §5.5 field is gone
    // and every model converted under the other convention becomes fluent
    // nonsense with no test to catch it.
    //
    // rope_dim >= 4 is required: with a single pair the two conventions
    // genuinely coincide (interleaved (x[0], x[1]) is half-split
    // (x[0], x[0+1])), which is a property of the definitions, not a bug.
    let mut rng = Rng::new(0x5eed_000d);

    for (d_head, rope_dim) in [(4_usize, 4_usize), (8, 8), (64, 64), (128, 96)] {
        let x = rng.vector(d_head * 2, 1.0);
        let mut interleaved = vec![f32::NAN; x.len()];
        let mut half_split = vec![f32::NAN; x.len()];

        let base_params = RopeParams {
            d_head,
            rope_dim,
            base: 1.0e4,
            pairing: RopePairing::Interleaved,
            position: 13,
        };
        rope(&x, &base_params, &mut interleaved).unwrap();
        rope(
            &x,
            &RopeParams {
                pairing: RopePairing::HalfSplit,
                ..base_params
            },
            &mut half_split,
        )
        .unwrap();

        assert_ne!(
            interleaved, half_split,
            "d_head {d_head} rope_dim {rope_dim}: the pairing parameter is being ignored"
        );

        // Stronger than "not equal": a majority of rotated components must
        // actually differ, so the test cannot pass on a single stray element.
        let differing = interleaved
            .iter()
            .zip(half_split.iter())
            .take(rope_dim)
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differing * 2 > rope_dim,
            "d_head {d_head}: only {differing} of {rope_dim} rotated components differ"
        );
    }
}

#[test]
fn the_two_pairings_coincide_at_a_single_pair() {
    // Documented above and asserted here so the exception is pinned rather than
    // rediscovered as a suspicious test failure later.
    let mut rng = Rng::new(0x5eed_000e);
    let x = rng.vector(2, 1.0);
    let mut interleaved = [f32::NAN; 2];
    let mut half_split = [f32::NAN; 2];

    let params = RopeParams {
        d_head: 2,
        rope_dim: 2,
        base: 1.0e4,
        pairing: RopePairing::Interleaved,
        position: 99,
    };
    rope(&x, &params, &mut interleaved).unwrap();
    rope(
        &x,
        &RopeParams {
            pairing: RopePairing::HalfSplit,
            ..params
        },
        &mut half_split,
    )
    .unwrap();
    assert_eq!(interleaved, half_split);
}

#[test]
fn rope_takes_its_base_from_the_parameters() {
    // Two different bases must give different rotations, or the base is being
    // ignored and a hardcoded 10000 is hiding somewhere.
    let mut rng = Rng::new(0x5eed_000a);
    let x = rng.vector(64, 1.0);
    let mut a = vec![0.0_f32; 64];
    let mut b = vec![0.0_f32; 64];

    rope(
        &x,
        &RopeParams {
            d_head: 64,
            rope_dim: 64,
            base: 1.0e4,
            pairing: RopePairing::Interleaved,
            position: 17,
        },
        &mut a,
    )
    .unwrap();
    rope(
        &x,
        &RopeParams {
            d_head: 64,
            rope_dim: 64,
            base: 1.0e6,
            pairing: RopePairing::Interleaved,
            position: 17,
        },
        &mut b,
    )
    .unwrap();

    assert_ne!(a, b, "changing rope_theta must change the rotation");
}

// ------------------------------------------------------------ SiLU / SwiGLU

#[test]
fn silu_matches_the_reference() {
    let mut rng = Rng::new(0x5eed_000b);
    for magnitude in [1e-3, 1.0, 30.0] {
        let x = rng.vector(512, magnitude);
        let mut out = vec![f32::NAN; x.len()];
        silu(&x, &mut out).unwrap();

        let expected = ref_silu(&x);
        for i in 0..x.len() {
            // Absolute bound scaled by the input magnitude: silu(v) is at most
            // |v|, so 8 ulps of |v| covers the sigmoid's rounding and the
            // product's.
            let bound = 8.0 * F32_UNIT_ROUNDOFF * f64::from(x[i]).abs() + 1e-30;
            assert_close(
                f64::from(out[i]),
                f64::from(expected[i]),
                bound,
                &format!("silu magnitude {magnitude} element {i}"),
            );
        }
    }
}

#[test]
fn swiglu_is_silu_of_the_gate_times_the_up_projection() {
    let mut rng = Rng::new(0x5eed_000c);
    let gate = rng.vector(300, 3.0);
    let up = rng.vector(300, 3.0);

    let mut gated = vec![f32::NAN; gate.len()];
    silu(&gate, &mut gated).unwrap();

    let mut fused = vec![f32::NAN; gate.len()];
    swiglu(&gate, &up, &mut fused).unwrap();

    for i in 0..gate.len() {
        // The fused kernel does exactly one f32 multiply more than `silu`, on
        // the same f32 value, so the two must agree bit for bit.
        assert_eq!(fused[i], gated[i] * up[i], "swiglu element {i}");
    }
}
