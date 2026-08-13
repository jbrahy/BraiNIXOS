//! Edge shapes, numerical stability, structural properties, and every
//! rejection path.
//!
//! These are the tests that catch the failures a randomized agreement test
//! never will: a block-quantized matmul that breaks on a dimension that is not
//! a multiple of the block size, a softmax that is fine on `N(0,1)` and
//! produces `NaN` on a real attention row, a RoPE that is off by a pairing
//! convention at every position except zero.

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
    RopePairing, RopeParams, TensorError, MAX_ROPE_POSITION, Q8_0_BLOCK,
};
use common::{quantize_q8_0, Rng};

// ------------------------------------------------------------- edge shapes

#[test]
fn f32_matmul_handles_single_element_row_and_column() {
    // 1x1x1: the whole computation is one multiply.
    let mut y = [0.0_f32];
    matmul_f32(
        MatMulShape {
            n_tokens: 1,
            n_in: 1,
            n_out: 1,
        },
        &[3.0],
        &[5.0],
        &mut y,
    )
    .unwrap();
    assert_eq!(y, [15.0]);

    // Single row of weights: n_out == 1, an inner product.
    let mut y = [0.0_f32];
    matmul_f32(
        MatMulShape {
            n_tokens: 1,
            n_in: 4,
            n_out: 1,
        },
        &[1.0, 2.0, 3.0, 4.0],
        &[1.0, 1.0, 1.0, 1.0],
        &mut y,
    )
    .unwrap();
    assert_eq!(y, [10.0]);

    // Single column: n_in == 1, an outer product against a scalar activation.
    let mut y = [0.0_f32; 3];
    matmul_f32(
        MatMulShape {
            n_tokens: 1,
            n_in: 1,
            n_out: 3,
        },
        &[1.0, 2.0, 3.0],
        &[7.0],
        &mut y,
    )
    .unwrap();
    assert_eq!(y, [7.0, 14.0, 21.0]);
}

#[test]
fn q8_matmul_handles_the_smallest_legal_shape() {
    // One block. n_in cannot be smaller than 32 for a Q8_0 tensor, so this is
    // the single-element case the format admits.
    let values: Vec<f32> = (0..Q8_0_BLOCK).map(|i| (i as f32) - 16.0).collect();
    let payload = quantize_q8_0(&values, 1, Q8_0_BLOCK);
    let weights = Q8Weights::new(&payload, 1, Q8_0_BLOCK).unwrap();

    let x = vec![1.0_f32; Q8_0_BLOCK];
    let mut y = [0.0_f32];
    matmul_q8_0(
        MatMulShape {
            n_tokens: 1,
            n_in: Q8_0_BLOCK,
            n_out: 1,
        },
        &weights,
        &x,
        &mut y,
    )
    .unwrap();

    // Σ (i − 16) for i in 0..32 = −16, reproduced through the quantizer to
    // within one quantization step per element.
    let expected: f32 = values.iter().sum();
    assert!((y[0] - expected).abs() < 1.0, "got {}", y[0]);
}

#[test]
fn q8_payload_length_derivation_covers_a_scale_plane_smaller_than_the_alignment() {
    // The classic break: a tensor with so few blocks that the scale plane is
    // shorter than BXW1_ALIGN, so the pad is most of the plane. Getting the
    // round-up wrong here places the quant plane at the wrong offset and every
    // weight is silently garbage.
    for (n_out, n_in, blocks) in [(1_usize, 32_usize, 1_usize), (3, 64, 6), (1, 1024, 32)] {
        assert_eq!(n_out * n_in / Q8_0_BLOCK, blocks);
        let scale_len = blocks * 4;
        let quant_off = scale_len.div_ceil(128) * 128;
        assert_eq!(
            Q8Weights::derived_payload_len(n_out, n_in).unwrap(),
            quant_off + blocks * Q8_0_BLOCK
        );
    }
}

#[test]
fn q8_refuses_an_inner_dimension_that_is_not_a_multiple_of_the_block() {
    // BXW1 rule D8. This is where block-quantized matmuls usually break, and
    // the format's answer is to refuse the tensor rather than to grow a
    // partial-block branch in the inner loop.
    for n_in in [1_usize, 31, 33, 48, 96 + 1] {
        assert_eq!(
            Q8Weights::new(&[], 4, n_in).unwrap_err(),
            TensorError::NotBlockAligned,
            "n_in = {n_in}"
        );
    }
    // 96 is a multiple of 32 and must be accepted where 97 was not.
    let payload = vec![0_u8; Q8Weights::derived_payload_len(4, 96).unwrap()];
    assert!(Q8Weights::new(&payload, 4, 96).is_ok());
}

#[test]
fn q8_out_dimension_need_not_be_a_multiple_of_the_block() {
    // Only the *last* axis carries the block constraint: blocks run along
    // in_features, so an odd row count is ordinary and must work.
    let mut rng = Rng::new(0x1eaf_0001);
    let (n_out, n_in) = (7, 32);
    let values = rng.vector(n_out * n_in, 1.0);
    let payload = quantize_q8_0(&values, n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();
    assert_eq!(weights.blocks_per_row(), 1);

    let mut out = vec![f32::NAN; n_out * n_in];
    weights.dequantize_into(&mut out).unwrap();
    assert!(out.iter().all(|v| v.is_finite()));
}

// ------------------------------------------------------- softmax stability

#[test]
fn softmax_is_stable_for_large_positive_magnitudes() {
    // A naive exp(x)/Σexp(x) overflows to Inf/Inf = NaN here.
    let x = [1000.0_f32, 999.0, 998.0];
    let mut out = [0.0_f32; 3];
    softmax(&x, &mut out).unwrap();

    assert!(out.iter().all(|v| v.is_finite()), "{out:?}");
    let sum: f64 = out.iter().map(|v| f64::from(*v)).sum();
    assert!((sum - 1.0).abs() < 1e-6, "sum {sum}");
    // exp(0) : exp(-1) : exp(-2), normalized.
    assert!((f64::from(out[0]) - 0.665_240_9).abs() < 1e-5, "{out:?}");
}

#[test]
fn softmax_is_stable_for_large_negative_magnitudes() {
    // A naive implementation underflows every term to zero and divides by a
    // zero denominator.
    let x = [-1000.0_f32, -1001.0, -1002.0];
    let mut out = [0.0_f32; 3];
    softmax(&x, &mut out).unwrap();

    assert!(out.iter().all(|v| v.is_finite()), "{out:?}");
    let sum: f64 = out.iter().map(|v| f64::from(*v)).sum();
    assert!((sum - 1.0).abs() < 1e-6, "sum {sum}");
    assert!((f64::from(out[0]) - 0.665_240_9).abs() < 1e-5, "{out:?}");
}

#[test]
fn softmax_handles_the_full_f32_exponent_range_in_one_row() {
    // x[i] − max overflows f32 for this row, which is why the subtraction is
    // widened to f64 before the exponential.
    let x = [f32::MAX, -f32::MAX];
    let mut out = [0.0_f32; 2];
    softmax(&x, &mut out).unwrap();
    assert_eq!(out, [1.0, 0.0]);
}

#[test]
fn softmax_of_a_constant_row_is_uniform() {
    for value in [0.0_f32, 1e30, -1e30] {
        let x = [value; 4];
        let mut out = [0.0_f32; 4];
        softmax(&x, &mut out).unwrap();
        assert_eq!(out, [0.25; 4], "value {value}");
    }
}

#[test]
fn softmax_of_a_single_element_is_one() {
    let mut out = [0.0_f32];
    softmax(&[-1e30], &mut out).unwrap();
    assert_eq!(out, [1.0]);
}

#[test]
fn softmax_refuses_non_finite_input() {
    for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
        let x = [1.0_f32, bad, 2.0];
        let mut out = [7.0_f32; 3];
        assert_eq!(softmax(&x, &mut out), Err(TensorError::NonFiniteInput));
        assert_eq!(out, [7.0; 3], "output must be untouched on refusal");
    }
}

// ---------------------------------------------------------- RoPE properties

#[test]
fn rope_at_position_zero_is_the_identity_under_both_pairings() {
    // cos(0) = 1 and sin(0) = 0 exactly, so this must be bit-for-bit equality,
    // not approximate. Anything less means the sine/cosine kernel is not exact
    // at zero and every position is slightly wrong.
    //
    // It holds under both conventions — which is precisely why position 0
    // cannot be used to tell them apart, and therefore why the pairing has to
    // be a declared field rather than something an engine could detect.
    let mut rng = Rng::new(0x1eaf_0002);
    for pairing in [RopePairing::Interleaved, RopePairing::HalfSplit] {
        for (d_head, rope_dim) in [(2_usize, 2_usize), (8, 4), (64, 64), (128, 96)] {
            let x = rng.vector(d_head * 3, 5.0);
            let mut out = vec![f32::NAN; x.len()];
            rope(
                &x,
                &RopeParams {
                    d_head,
                    rope_dim,
                    base: 1.0e4,
                    pairing,
                    position: 0,
                },
                &mut out,
            )
            .unwrap();
            assert_eq!(out, x, "{pairing:?} d_head {d_head} rope_dim {rope_dim}");
        }
    }
}

#[test]
fn rope_pairing_decodes_only_the_two_bxw1_values() {
    assert_eq!(RopePairing::from_bxw1(1).unwrap(), RopePairing::Interleaved);
    assert_eq!(RopePairing::from_bxw1(2).unwrap(), RopePairing::HalfSplit);
    assert_eq!(RopePairing::Interleaved.to_bxw1(), 1);
    assert_eq!(RopePairing::HalfSplit.to_bxw1(), 2);
}

#[test]
fn rope_pairing_refuses_every_unrecognized_value_including_zero() {
    // BXW1 §5.5 / rule H17a. Zero is the value a converter that predates the
    // field writes, so admitting it as a default would mean the one case the
    // field exists to catch is exactly the case it does not catch. It is
    // refused on the same footing as any other unknown value — no fallback to
    // either path.
    for value in [0_u32, 3, 4, 255, 0x8000_0000, u32::MAX] {
        assert_eq!(
            RopePairing::from_bxw1(value).unwrap_err(),
            TensorError::InvalidRopePairing,
            "rope_pairing = {value}"
        );
    }
}

#[test]
fn rope_preserves_the_norm_of_every_rotated_pair_under_both_pairings() {
    // A rotation is orthogonal, so each pair's magnitude is invariant. This is
    // the property that fails first if the two components of a pair are picked
    // from the wrong places or the sign of one term is wrong — and it holds for
    // both conventions, which is the second reason no unit test can tell them
    // apart.
    let mut rng = Rng::new(0x1eaf_0003);
    let (d_head, rope_dim) = (128_usize, 96_usize);
    let x = rng.vector(d_head * 2, 3.0);
    let half = rope_dim / 2;

    for pairing in [RopePairing::Interleaved, RopePairing::HalfSplit] {
        for position in [1_u32, 3, 512, 65_537, MAX_ROPE_POSITION] {
            let mut out = vec![f32::NAN; x.len()];
            rope(
                &x,
                &RopeParams {
                    d_head,
                    rope_dim,
                    base: 1.0e4,
                    pairing,
                    position,
                },
                &mut out,
            )
            .unwrap();

            for head in 0..2 {
                for pair in 0..half {
                    let (lo, hi) = match pairing {
                        RopePairing::Interleaved => (2 * pair, 2 * pair + 1),
                        RopePairing::HalfSplit => (pair, pair + half),
                    };
                    let (lo, hi) = (head * d_head + lo, head * d_head + hi);
                    let before = f64::from(x[lo]).hypot(f64::from(x[hi]));
                    let after = f64::from(out[lo]).hypot(f64::from(out[hi]));
                    assert!(
                        (after - before).abs() <= 1e-6 * before.max(1.0),
                        "{pairing:?} position {position} pair {pair}: {before} -> {after}"
                    );
                }
                // The unrotated tail passes through untouched — BXW1 §5.1 pins
                // "passed through", not zeroed. Both pairings cover exactly
                // 0..rope_dim, so the tail is the same set for both.
                for i in rope_dim..d_head {
                    assert_eq!(
                        out[head * d_head + i],
                        x[head * d_head + i],
                        "{pairing:?} tail element {i} must pass through unrotated"
                    );
                }
                assert!(
                    (rope_dim..d_head).any(|i| x[head * d_head + i] != 0.0),
                    "the tail fixture must be non-zero or the assertion above is vacuous"
                );
            }
        }
    }
}

#[test]
fn rope_refuses_an_invalid_dimension_or_base() {
    let x = [1.0_f32; 8];
    let mut out = [0.0_f32; 8];
    let valid = RopeParams {
        d_head: 8,
        rope_dim: 8,
        base: 1.0e4,
        pairing: RopePairing::Interleaved,
        position: 0,
    };

    for (params, expected) in [
        (
            RopeParams {
                rope_dim: 7,
                ..valid
            },
            TensorError::InvalidRopeDim,
        ),
        (
            RopeParams {
                rope_dim: 0,
                ..valid
            },
            TensorError::InvalidRopeDim,
        ),
        (
            RopeParams {
                rope_dim: 10,
                ..valid
            },
            TensorError::InvalidRopeDim,
        ),
        (
            RopeParams { d_head: 0, ..valid },
            TensorError::ZeroDimension,
        ),
        (
            RopeParams {
                base: f32::NAN,
                ..valid
            },
            TensorError::InvalidTheta,
        ),
        (
            RopeParams {
                base: f32::INFINITY,
                ..valid
            },
            TensorError::InvalidTheta,
        ),
        (RopeParams { base: 0.0, ..valid }, TensorError::InvalidTheta),
        (
            RopeParams {
                base: -1.0e4,
                ..valid
            },
            TensorError::InvalidTheta,
        ),
        (RopeParams { base: 1.0, ..valid }, TensorError::InvalidTheta),
        (
            RopeParams {
                position: MAX_ROPE_POSITION + 1,
                ..valid
            },
            TensorError::PositionTooLarge,
        ),
    ] {
        assert_eq!(rope(&x, &params, &mut out), Err(expected), "{params:?}");
        assert_eq!(out, [0.0; 8], "output must be untouched on refusal");
    }
}

// ------------------------------------------------------------ shape refusal

#[test]
fn every_kernel_refuses_a_shape_mismatch_without_writing() {
    let sentinel = 7.0_f32;

    // f32 matmul: y one element short.
    let mut y = [sentinel; 2];
    assert_eq!(
        matmul_f32(
            MatMulShape {
                n_tokens: 1,
                n_in: 2,
                n_out: 3
            },
            &[1.0; 6],
            &[1.0; 2],
            &mut y
        ),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(y, [sentinel; 2]);

    // f32 matmul: y one element long — refused in the other direction too.
    let mut y = [sentinel; 4];
    assert_eq!(
        matmul_f32(
            MatMulShape {
                n_tokens: 1,
                n_in: 2,
                n_out: 3
            },
            &[1.0; 6],
            &[1.0; 2],
            &mut y
        ),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(y, [sentinel; 4]);

    // f32 matmul: the weight slice disagrees with the shape.
    let mut y = [sentinel; 3];
    assert_eq!(
        matmul_f32(
            MatMulShape {
                n_tokens: 1,
                n_in: 2,
                n_out: 3
            },
            &[1.0; 5],
            &[1.0; 2],
            &mut y
        ),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(y, [sentinel; 3]);

    // Q8 matmul: the shape disagrees with the view's own extents.
    let payload = vec![0_u8; Q8Weights::derived_payload_len(2, 32).unwrap()];
    let weights = Q8Weights::new(&payload, 2, 32).unwrap();
    let mut y = [sentinel; 3];
    assert_eq!(
        matmul_q8_0(
            MatMulShape {
                n_tokens: 1,
                n_in: 32,
                n_out: 3
            },
            &weights,
            &[1.0; 32],
            &mut y
        ),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(y, [sentinel; 3]);

    // RMSNorm: x is not a whole multiple of the weight width.
    let mut out = [sentinel; 5];
    assert_eq!(
        rmsnorm(&[1.0; 5], &[1.0; 2], 1e-5, &mut out),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(out, [sentinel; 5]);

    // Softmax, SiLU, SwiGLU: output length disagreement.
    let mut out = [sentinel; 2];
    assert_eq!(
        softmax(&[1.0; 3], &mut out),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(silu(&[1.0; 3], &mut out), Err(TensorError::ShapeMismatch));
    assert_eq!(
        swiglu(&[1.0; 3], &[1.0; 3], &mut out),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(
        swiglu(&[1.0; 2], &[1.0; 3], &mut out),
        Err(TensorError::ShapeMismatch)
    );
    assert_eq!(out, [sentinel; 2]);
}

#[test]
fn every_kernel_refuses_a_zero_dimension() {
    let mut empty: [f32; 0] = [];
    assert_eq!(
        matmul_f32(
            MatMulShape {
                n_tokens: 0,
                n_in: 1,
                n_out: 1
            },
            &[1.0],
            &[],
            &mut empty
        ),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(
        matmul_f32(
            MatMulShape {
                n_tokens: 1,
                n_in: 0,
                n_out: 1
            },
            &[],
            &[],
            &mut empty
        ),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(
        rmsnorm(&[], &[1.0], 1e-5, &mut empty),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(
        rmsnorm(&[1.0], &[], 1e-5, &mut empty),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(softmax(&[], &mut empty), Err(TensorError::ZeroDimension));
    assert_eq!(silu(&[], &mut empty), Err(TensorError::ZeroDimension));
    assert_eq!(
        swiglu(&[], &[], &mut empty),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(
        Q8Weights::new(&[], 0, 32).unwrap_err(),
        TensorError::ZeroDimension
    );
    assert_eq!(
        Q8Weights::new(&[], 4, 0).unwrap_err(),
        TensorError::ZeroDimension
    );
}

#[test]
fn q8_refuses_a_payload_of_the_wrong_length_in_either_direction() {
    let exact = Q8Weights::derived_payload_len(3, 64).unwrap();
    for length in [0, exact - 1, exact + 1, exact * 2] {
        assert_eq!(
            Q8Weights::new(&vec![0_u8; length], 3, 64).unwrap_err(),
            TensorError::PayloadLengthMismatch,
            "length {length} against exact {exact}"
        );
    }
    assert!(Q8Weights::new(&vec![0_u8; exact], 3, 64).is_ok());
}

// ------------------------------------------------------- Q8_0 per-row access

#[test]
fn q8_row_dequantization_agrees_with_the_whole_matrix() {
    // The property that makes the row accessor safe to use for a token
    // embedding: it must be the same arithmetic over the same bytes as the
    // whole-matrix path, not merely close to it. Asserted with `assert_eq!` on
    // the floats — a one-ulp difference would mean the two derivations of the
    // plane offsets had drifted, which is exactly the bug worth catching.
    let mut rng = Rng::new(0x0110_0001);
    for (n_out, n_in) in [(1_usize, 32_usize), (7, 32), (3, 64), (48, 32), (2, 1024)] {
        let values = rng.vector(n_out * n_in, 1.5);
        let payload = quantize_q8_0(&values, n_out, n_in);
        let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();

        let mut whole = vec![f32::NAN; n_out * n_in];
        weights.dequantize_into(&mut whole).unwrap();

        for row in 0..n_out {
            let mut one = vec![f32::NAN; n_in];
            weights.dequantize_row_into(row, &mut one).unwrap();
            assert_eq!(
                one,
                whole[row * n_in..(row + 1) * n_in],
                "row {row} of {n_out}x{n_in}"
            );
        }
    }
}

#[test]
fn q8_row_dequantization_refuses_a_row_past_the_last() {
    // A token identifier is a caller-supplied index, so this is the one place
    // in the crate where an out-of-range index is reachable at all. Refused,
    // never wrapped and never clamped: a clamped identifier would return some
    // other token's embedding and decode fluently from it.
    let mut rng = Rng::new(0x0110_0002);
    let (n_out, n_in) = (5, 64);
    let payload = quantize_q8_0(&rng.vector(n_out * n_in, 1.0), n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();

    let mut out = vec![0.0_f32; n_in];
    for row in [n_out, n_out + 1, usize::MAX] {
        assert_eq!(
            weights.dequantize_row_into(row, &mut out).unwrap_err(),
            TensorError::RowOutOfRange,
            "row {row} was accepted"
        );
    }
    // The last valid row must still be reachable — an off-by-one in the refusal
    // would hide behind the assertions above.
    assert!(weights.dequantize_row_into(n_out - 1, &mut out).is_ok());
}

#[test]
fn q8_row_dequantization_refuses_an_output_slice_of_the_wrong_length() {
    // In either direction, per BXW1 §7.5: a short slice would truncate the row
    // and a long one means the caller and the shape disagree.
    let mut rng = Rng::new(0x0110_0003);
    let (n_out, n_in) = (4, 96);
    let payload = quantize_q8_0(&rng.vector(n_out * n_in, 1.0), n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();

    for length in [0, n_in - 1, n_in - 32, n_in + 1, n_in * 2] {
        let mut out = vec![0.0_f32; length];
        assert_eq!(
            weights.dequantize_row_into(0, &mut out).unwrap_err(),
            TensorError::ShapeMismatch,
            "length {length} against n_in {n_in}"
        );
    }
}

#[test]
fn q8_row_dequantization_writes_nothing_when_it_refuses() {
    // Every check completes before the first output element, so a refused call
    // leaves the caller's buffer exactly as it found it.
    let mut rng = Rng::new(0x0110_0004);
    let (n_out, n_in) = (3, 32);
    let payload = quantize_q8_0(&rng.vector(n_out * n_in, 1.0), n_out, n_in);
    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();

    let mut out = vec![7.0_f32; n_in];
    assert!(weights.dequantize_row_into(n_out, &mut out).is_err());
    assert!(out.iter().all(|value| *value == 7.0), "{out:?}");
}

// --------------------------------------------------------- RMSNorm refusal

#[test]
fn rmsnorm_refuses_an_epsilon_that_is_not_a_positive_normal() {
    let mut out = [7.0_f32; 4];
    for bad in [
        f32::NAN,
        f32::INFINITY,
        f32::NEG_INFINITY,
        0.0,
        -0.0,
        -1e-5,
        f32::from_bits(1), // smallest positive subnormal
    ] {
        assert_eq!(
            rmsnorm(&[1.0; 4], &[1.0; 4], bad, &mut out),
            Err(TensorError::InvalidEpsilon),
            "eps bits {:#010x}",
            bad.to_bits()
        );
        assert_eq!(out, [7.0; 4]);
    }
    assert!(rmsnorm(&[1.0; 4], &[1.0; 4], f32::MIN_POSITIVE, &mut out).is_ok());
}

#[test]
fn rmsnorm_refuses_a_non_finite_row_without_writing_earlier_rows() {
    // The bad value is in the *second* row. A kernel that validated per row as
    // it wrote would leave the first row modified and report failure.
    let x = [1.0_f32, 2.0, f32::NAN, 4.0];
    let mut out = [7.0_f32; 4];
    assert_eq!(
        rmsnorm(&x, &[1.0; 2], 1e-5, &mut out),
        Err(TensorError::NonFiniteInput)
    );
    assert_eq!(out, [7.0; 4]);
}

#[test]
fn rmsnorm_of_an_all_zero_row_is_zero_rather_than_undefined() {
    // mean(x²) = 0, so the reciprocal square root sees exactly ε. Without ε
    // inside the root this divides by zero.
    let mut out = [7.0_f32; 4];
    rmsnorm(&[0.0; 4], &[1.0; 4], 1e-5, &mut out).unwrap();
    assert_eq!(out, [0.0; 4]);
}

// -------------------------------------------------------- activation edges

#[test]
fn silu_is_zero_at_zero_and_saturates_gracefully() {
    let x = [0.0_f32, -1000.0, 1000.0, -100.0];
    let mut out = [f32::NAN; 4];
    silu(&x, &mut out).unwrap();
    assert_eq!(out[0], 0.0);
    // silu(v) -> 0 as v -> -inf and -> v as v -> +inf.
    assert!(out[1].abs() < 1e-30, "{}", out[1]);
    assert_eq!(out[2], 1000.0);
    assert!(out[3].abs() < 1e-30, "{}", out[3]);
    assert!(out.iter().all(|v| v.is_finite()));
}

// ---------------------------------------------- deny paths found by coverage
//
// Every test below closes a region that line coverage showed unexecuted. They
// are all rejection paths, which is the point: a parser's error arms are the
// half an agreement test never reaches, and an unexecuted `return Err(..)` is
// an untested claim about what the code refuses.

#[test]
fn rope_rejects_an_empty_input() {
    let mut out: Vec<f32> = Vec::new();
    let error = rope(
        &[],
        &RopeParams {
            d_head: 4,
            rope_dim: 4,
            base: 1.0e4,
            pairing: RopePairing::Interleaved,
            position: 0,
        },
        &mut out,
    )
    .expect_err("an empty input has no heads to rotate");
    assert_eq!(error, TensorError::ZeroDimension);
}

#[test]
fn rope_rejects_an_output_of_a_different_length() {
    let x = vec![0.0_f32; 8];
    let mut out = vec![f32::NAN; 7];
    let error = rope(
        &x,
        &RopeParams {
            d_head: 4,
            rope_dim: 4,
            base: 1.0e4,
            pairing: RopePairing::Interleaved,
            position: 0,
        },
        &mut out,
    )
    .expect_err("a short output buffer must deny, never truncate");
    assert_eq!(error, TensorError::ShapeMismatch);
}

#[test]
fn rope_rejects_an_input_that_is_not_a_whole_number_of_heads() {
    let x = vec![0.0_f32; 9];
    let mut out = vec![f32::NAN; 9];
    let error = rope(
        &x,
        &RopeParams {
            d_head: 4,
            rope_dim: 4,
            base: 1.0e4,
            pairing: RopePairing::Interleaved,
            position: 0,
        },
        &mut out,
    )
    .expect_err("9 is not a multiple of d_head 4");
    assert_eq!(error, TensorError::ShapeMismatch);
}

#[test]
fn derived_payload_len_rejects_a_zero_dimension() {
    assert_eq!(
        Q8Weights::derived_payload_len(0, Q8_0_BLOCK),
        Err(TensorError::ZeroDimension)
    );
    assert_eq!(
        Q8Weights::derived_payload_len(4, 0),
        Err(TensorError::ZeroDimension)
    );
}

#[test]
fn derived_payload_len_rejects_a_width_that_is_not_block_aligned() {
    assert_eq!(
        Q8Weights::derived_payload_len(4, Q8_0_BLOCK + 1),
        Err(TensorError::NotBlockAligned),
        "Q8_0 stores whole blocks; a partial trailing block has no representation"
    );
}

#[test]
fn dequantize_into_rejects_a_destination_of_the_wrong_size() {
    let n_out = 2;
    let n_in = Q8_0_BLOCK;
    let payload_len = Q8Weights::derived_payload_len(n_out, n_in).unwrap();
    let payload = vec![0u8; payload_len];
    let weights = Q8Weights::new(&payload, n_out, n_in).unwrap();

    let mut too_small = vec![0.0_f32; n_out * n_in - 1];
    assert_eq!(
        weights.dequantize_into(&mut too_small),
        Err(TensorError::ShapeMismatch)
    );

    let mut too_large = vec![0.0_f32; n_out * n_in + 1];
    assert_eq!(
        weights.dequantize_into(&mut too_large),
        Err(TensorError::ShapeMismatch),
        "an oversized destination is as wrong as a short one: the caller has \
         the shape wrong either way, and silently filling a prefix would hide it"
    );
}
