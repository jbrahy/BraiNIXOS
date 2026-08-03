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
    RopeParams, TensorError, MAX_ROPE_POSITION, Q8_0_BLOCK,
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
fn rope_at_position_zero_is_the_identity() {
    // cos(0) = 1 and sin(0) = 0 exactly, so this must be bit-for-bit equality,
    // not approximate. Anything less means the sine/cosine kernel is not exact
    // at zero and every position is slightly wrong.
    let mut rng = Rng::new(0x1eaf_0002);
    for (d_head, rope_dim) in [(2_usize, 2_usize), (8, 4), (64, 64), (128, 96)] {
        let x = rng.vector(d_head * 3, 5.0);
        let mut out = vec![f32::NAN; x.len()];
        rope(
            &x,
            &RopeParams {
                d_head,
                rope_dim,
                base: 1.0e4,
                position: 0,
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(out, x, "d_head {d_head} rope_dim {rope_dim}");
    }
}

#[test]
fn rope_preserves_the_norm_of_every_rotated_pair() {
    // A rotation is orthogonal, so each pair's magnitude is invariant. This is
    // the property that fails first if the two components of a pair are picked
    // from the wrong places or the sign of one term is wrong.
    let mut rng = Rng::new(0x1eaf_0003);
    let (d_head, rope_dim) = (128_usize, 96_usize);
    let x = rng.vector(d_head * 2, 3.0);

    for position in [1_u32, 3, 512, 65_537, MAX_ROPE_POSITION] {
        let mut out = vec![f32::NAN; x.len()];
        rope(
            &x,
            &RopeParams {
                d_head,
                rope_dim,
                base: 1.0e4,
                position,
            },
            &mut out,
        )
        .unwrap();

        for head in 0..2 {
            for pair in 0..rope_dim / 2 {
                let base = head * d_head + 2 * pair;
                let before = f64::from(x[base]).hypot(f64::from(x[base + 1]));
                let after = f64::from(out[base]).hypot(f64::from(out[base + 1]));
                assert!(
                    (after - before).abs() <= 1e-6 * before.max(1.0),
                    "position {position} pair {pair}: {before} -> {after}"
                );
            }
            // The unrotated tail passes through untouched.
            for i in rope_dim..d_head {
                assert_eq!(out[head * d_head + i], x[head * d_head + i]);
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
