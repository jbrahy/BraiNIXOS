//! `Q8_0` activations against the `f32`-activation reference.
//!
//! The point of the `SDOT` path is speed; the point of these tests is that it
//! computes the same thing. "Same" cannot mean bit-identical -- quantizing the
//! activations is a lossy step by construction -- so the bound is stated and
//! checked rather than hoped for.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cognitive_complexity
)]

use brainix_tensor::{
    matmul_q4_0_q8a, matmul_q4_0_q8a_rows, matmul_q4_0_q8a_tokens, matmul_q8_0, matmul_q8_0_q8a,
    matmul_q8_0_q8a_rows, matmul_q8_0_q8a_tokens, quantize_activations, quantize_q4_0, MatMulShape,
    Q4Weights, Q8Weights,
};

/// Deterministic pseudo-random floats in a range typical of activations.
fn values(count: usize, seed: u32) -> Vec<f32> {
    let mut state = seed | 1;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((state >> 8) as f32 / 8_388_608.0) - 1.0
        })
        .collect()
}

fn q8_payload(n_out: usize, n_in: usize, seed: u32) -> Vec<u8> {
    let payload_len = Q8Weights::derived_payload_len(n_out, n_in).expect("shape");
    let mut payload = vec![0u8; payload_len];
    let blocks = n_out * (n_in / 32);
    let quant_start = payload_len - blocks * 32;
    for (index, chunk) in payload[..quant_start].chunks_exact_mut(4).enumerate() {
        let scale = 0.005_f32 + (index % 13) as f32 * 0.0007;
        chunk.copy_from_slice(&scale.to_le_bytes());
    }
    let mut state = seed | 1;
    for byte in payload[quant_start..].iter_mut() {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        *byte = ((state >> 16) as i32 % 254 - 127) as i8 as u8;
    }
    payload
}

#[test]
fn quantized_activations_track_the_f32_reference() {
    const N_OUT: usize = 128;
    const N_IN: usize = 256;
    for tokens in [1usize, 3] {
        let payload = q8_payload(N_OUT, N_IN, 7);
        let weights = Q8Weights::new(&payload, N_OUT, N_IN).expect("weights");
        let x = values(tokens * N_IN, 99);
        let shape = MatMulShape {
            n_tokens: tokens,
            n_in: N_IN,
            n_out: N_OUT,
        };

        let mut reference = vec![0.0f32; tokens * N_OUT];
        matmul_q8_0(shape, &weights, &x, &mut reference).expect("reference");

        let mut scratch = vec![0u8; Q8Weights::derived_payload_len(tokens, N_IN).expect("len")];
        quantize_activations(tokens, N_IN, &x, &mut scratch).expect("quantize");
        let quantized = Q8Weights::new(&scratch, tokens, N_IN).expect("view");
        let mut fast = vec![0.0f32; tokens * N_OUT];
        matmul_q8_0_q8a(shape, &weights, &quantized, &mut fast).expect("fast");

        // Relative error against the magnitude of the reference row. 8-bit
        // activations carry ~0.4% quantization error per element; errors across
        // a 256-element reduction partially cancel, so a 2% bound is loose
        // enough not to be flaky and tight enough to catch a wrong kernel --
        // a transposed index or a dropped scale misses by orders of magnitude,
        // not by percent.
        let scale = reference
            .iter()
            .fold(0.0f32, |peak, value| peak.max(value.abs()));
        for (index, (want, got)) in reference.iter().zip(fast.iter()).enumerate() {
            let error = (want - got).abs() / scale.max(f32::MIN_POSITIVE);
            assert!(
                error < 0.02,
                "tokens {tokens}, index {index}: reference {want}, sdot {got}, \
                 relative error {error}"
            );
        }
    }
}

#[test]
fn quantization_error_never_exceeds_half_a_step() {
    // The guarantee `Q8_0` actually makes. An earlier version of this test
    // asserted that "exactly representable" inputs round-trip bit-for-bit and
    // then supplied inputs that were not exactly representable -- the values
    // were multiples of one constant while the derived scale was `absmax / 127`
    // of another. The bound below is the real property and does not depend on
    // constructing a special input.
    for seed in [3u32, 17, 4242] {
        let x = values(64, seed);
        let peak = x.iter().fold(0.0f32, |acc, value| acc.max(value.abs()));
        let step = peak / 127.0;

        let mut scratch = vec![0u8; Q8Weights::derived_payload_len(2, 32).expect("len")];
        quantize_activations(2, 32, &x, &mut scratch).expect("quantize");
        let view = Q8Weights::new(&scratch, 2, 32).expect("view");

        let mut recovered = vec![0.0f32; 32];
        for row in 0..2usize {
            view.dequantize_row_into(row, &mut recovered)
                .expect("dequantize");
            for (index, got) in recovered.iter().enumerate() {
                let want = x[row * 32 + index];
                let error = (got - want).abs();
                // Half a step of the *block's own* peak, which may be below the
                // whole-slice peak; a slack factor covers that plus f32 rounding.
                assert!(
                    error <= step * 0.51 + 1e-7,
                    "seed {seed} row {row} index {index}: {got} vs {want}, \
                     error {error} exceeds half-step {}",
                    step * 0.5
                );
            }
        }
    }
}

#[test]
fn an_all_zero_block_emits_a_zero_scale() {
    let x = vec![0.0f32; 32];
    let mut scratch = vec![0xAAu8; Q8Weights::derived_payload_len(1, 32).expect("len")];
    quantize_activations(1, 32, &x, &mut scratch).expect("quantize");
    let view = Q8Weights::new(&scratch, 1, 32).expect("view");
    let mut recovered = vec![1.0f32; 32];
    view.dequantize_row_into(0, &mut recovered)
        .expect("dequantize");
    assert!(
        recovered.iter().all(|value| *value == 0.0),
        "an all-zero block must dequantize to zeros, got {recovered:?}"
    );
}

#[test]
fn a_shape_disagreement_denies() {
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, 32).expect("len")];
    assert!(quantize_activations(1, 32, &[0.0; 31], &mut scratch).is_err());
    assert!(quantize_activations(1, 32, &[0.0; 32], &mut scratch[..4]).is_err());
}

#[test]
fn splitting_the_output_rows_reproduces_the_whole() {
    // The property a parallel decomposition rests on: N workers each computing
    // a slice of the output rows produce exactly what one call produces. Not
    // "within a tolerance" -- bit-for-bit, because each output element is
    // computed by the identical sequence of operations either way. Splitting
    // changes who does the work, not the arithmetic.
    const N_OUT: usize = 96;
    const N_IN: usize = 128;
    let payload = q8_payload(N_OUT, N_IN, 11);
    let weights = Q8Weights::new(&payload, N_OUT, N_IN).expect("weights");
    let x = values(N_IN, 5);
    let shape = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };

    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, N_IN).expect("len")];
    quantize_activations(1, N_IN, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, 1, N_IN).expect("view");

    let mut whole = vec![0.0f32; N_OUT];
    matmul_q8_0_q8a(shape, &weights, &quantized, &mut whole).expect("whole");

    for workers in [1usize, 2, 3, 4, 6] {
        let per = N_OUT / workers;
        let mut split = vec![0.0f32; N_OUT];
        for (index, chunk) in split.chunks_mut(per).enumerate() {
            matmul_q8_0_q8a_rows(shape, &weights, &quantized, index * per, chunk.len(), chunk)
                .expect("range");
        }
        assert_eq!(split, whole, "{workers} workers disagreed with one call");
    }
}

#[test]
fn a_row_range_past_the_end_denies() {
    let payload = q8_payload(64, 64, 2);
    let weights = Q8Weights::new(&payload, 64, 64).expect("weights");
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, 64).expect("len")];
    quantize_activations(1, 64, &values(64, 1), &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, 1, 64).expect("view");
    let shape = MatMulShape {
        n_tokens: 1,
        n_in: 64,
        n_out: 64,
    };
    let mut y = vec![0.0f32; 8];
    // Starts inside, ends outside.
    assert!(matmul_q8_0_q8a_rows(shape, &weights, &quantized, 60, 8, &mut y).is_err());
}

#[test]
fn splitting_the_q4_output_rows_reproduces_the_whole() {
    // The same property as `splitting_the_output_rows_reproduces_the_whole`,
    // for `Q4_0`. It matters more here, not less: the row-split kernel is the
    // only reason `Q4_0` can reach the bandwidth-bound regime where its fewer
    // bytes are worth anything, so it is the kernel a decode will actually run
    // once the dispatcher has workers.
    //
    // Bit-for-bit again, and for the same reason: splitting changes who does
    // the work, not the arithmetic. A tolerance here would hide precisely the
    // bug this is for -- an off-by-one in the row offset, which perturbs a few
    // outputs by a little and passes any bound loose enough to allow rounding.
    const N_OUT: usize = 96;
    const N_IN: usize = 128;

    // Build the weights by quantizing known values, so the payload is a real
    // Q4_0 encoding rather than bytes that merely parse.
    let dense = values(N_OUT * N_IN, 23);
    let mut payload = vec![0u8; Q4Weights::derived_payload_len(N_OUT, N_IN).expect("shape")];
    quantize_q4_0(N_OUT, N_IN, &dense, &mut payload).expect("quantize weights");
    let weights = Q4Weights::new(&payload, N_OUT, N_IN).expect("weights");

    let x = values(N_IN, 7);
    let shape = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, N_IN).expect("len")];
    quantize_activations(1, N_IN, &x, &mut scratch).expect("quantize activations");
    let quantized = Q8Weights::new(&scratch, 1, N_IN).expect("view");

    let mut whole = vec![0.0f32; N_OUT];
    matmul_q4_0_q8a(shape, &weights, &quantized, &mut whole).expect("whole");

    for workers in [1usize, 2, 3, 4, 6] {
        let per = N_OUT / workers;
        let mut split = vec![0.0f32; N_OUT];
        for (index, chunk) in split.chunks_mut(per).enumerate() {
            matmul_q4_0_q8a_rows(shape, &weights, &quantized, index * per, chunk.len(), chunk)
                .expect("range");
        }
        assert_eq!(split, whole, "{workers} workers disagreed with one call");
    }
}

#[test]
fn a_q4_row_range_past_the_end_denies() {
    const N_OUT: usize = 64;
    const N_IN: usize = 64;
    let dense = values(N_OUT * N_IN, 31);
    let mut payload = vec![0u8; Q4Weights::derived_payload_len(N_OUT, N_IN).expect("shape")];
    quantize_q4_0(N_OUT, N_IN, &dense, &mut payload).expect("quantize");
    let weights = Q4Weights::new(&payload, N_OUT, N_IN).expect("weights");

    let x = values(N_IN, 3);
    let shape = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, N_IN).expect("len")];
    quantize_activations(1, N_IN, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, 1, N_IN).expect("view");

    // One row past the end, and a count that wraps the addition. Both must be
    // refused rather than read past the payload: this kernel is handed offsets
    // computed by a dispatcher, which is exactly the code most likely to be
    // wrong about them.
    let mut out = vec![0.0f32; N_OUT];
    assert!(matmul_q4_0_q8a_rows(shape, &weights, &quantized, N_OUT, 1, &mut out[..1]).is_err());
    assert!(matmul_q4_0_q8a_rows(shape, &weights, &quantized, 1, N_OUT, &mut out).is_err());
    assert!(
        matmul_q4_0_q8a_rows(shape, &weights, &quantized, usize::MAX, 2, &mut out[..2]).is_err()
    );
    // A zero count is a caller error rather than a no-op, matching Q8_0.
    assert!(matmul_q4_0_q8a_rows(shape, &weights, &quantized, 0, 0, &mut []).is_err());

    // Each of the three shape agreements the kernel checks, disagreed one at a
    // time. A dispatcher passes this function a shape and a view that were
    // derived separately, so "they describe the same matrix" is an assumption
    // worth refusing on rather than indexing on.
    let wrong_n_out = MatMulShape {
        n_out: N_OUT + 32,
        ..shape
    };
    assert!(
        matmul_q4_0_q8a_rows(wrong_n_out, &weights, &quantized, 0, 1, &mut out[..1]).is_err(),
        "a shape claiming more output rows than the weights have must be refused"
    );

    let wrong_n_in = MatMulShape {
        n_in: N_IN + 32,
        ..shape
    };
    assert!(
        matmul_q4_0_q8a_rows(wrong_n_in, &weights, &quantized, 0, 1, &mut out[..1]).is_err(),
        "a reduction width the weights do not have must be refused"
    );

    let wrong_tokens = MatMulShape {
        n_tokens: 2,
        ..shape
    };
    assert!(
        matmul_q4_0_q8a_rows(wrong_tokens, &weights, &quantized, 0, 1, &mut out[..2]).is_err(),
        "more tokens than the activation view holds must be refused"
    );

    // And the destination length, which is the one a chunking bug gets wrong:
    // n_tokens x row_count, not n_tokens x n_out.
    assert!(
        matmul_q4_0_q8a_rows(shape, &weights, &quantized, 0, 4, &mut out[..3]).is_err(),
        "y must be exactly n_tokens x row_count"
    );
}

#[test]
fn splitting_the_tokens_reproduces_the_whole() {
    // The prefill counterpart of `splitting_the_output_rows_reproduces_the_whole`,
    // and the property token-parallel prefill would rest on: N workers each
    // taking a range of TOKENS produce exactly what one call produces.
    //
    // Bit-for-bit, again, and this direction is the one worth checking. A token
    // range writes `y[t * n_out ..]` for each of its tokens, so an off-by-one in
    // the destination index moves whole rows rather than perturbing a sum, and
    // an approximate comparison would not notice.
    const N_OUT: usize = 96;
    const N_IN: usize = 128;
    const N_TOKENS: usize = 12;

    let payload = q8_payload(N_OUT, N_IN, 23);
    let weights = Q8Weights::new(&payload, N_OUT, N_IN).expect("weights");
    let x = values(N_TOKENS * N_IN, 7);
    let shape = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N_IN,
        n_out: N_OUT,
    };

    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(N_TOKENS, N_IN).expect("len")];
    quantize_activations(N_TOKENS, N_IN, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, N_TOKENS, N_IN).expect("view");

    let mut whole = vec![0.0f32; N_TOKENS * N_OUT];
    matmul_q8_0_q8a(shape, &weights, &quantized, &mut whole).expect("whole");

    // Every divisor of 12, so the last chunk is full, plus 5, where it is not.
    for workers in [1usize, 2, 3, 4, 6, 12, 5] {
        let per_worker = N_TOKENS.div_ceil(workers);
        let mut split = vec![0.0f32; N_TOKENS * N_OUT];
        for (index, chunk) in split.chunks_mut(per_worker * N_OUT).enumerate() {
            let start = index * per_worker;
            let count = chunk.len() / N_OUT;
            matmul_q8_0_q8a_tokens(shape, &weights, &quantized, start, count, chunk)
                .expect("token range");
        }
        assert_eq!(
            split, whole,
            "{workers} workers disagreed with one call over {N_TOKENS} tokens"
        );
    }
}

#[test]
fn a_token_range_past_the_end_denies() {
    const N: usize = 64;
    const N_TOKENS: usize = 4;
    let payload = q8_payload(N, N, 3);
    let weights = Q8Weights::new(&payload, N, N).expect("weights");
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(N_TOKENS, N).expect("len")];
    quantize_activations(N_TOKENS, N, &values(N_TOKENS * N, 4), &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, N_TOKENS, N).expect("view");
    let shape = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N,
        n_out: N,
    };

    // Starts inside, ends outside.
    let mut y = vec![0.0f32; 2 * N];
    assert!(matmul_q8_0_q8a_tokens(shape, &weights, &quantized, 3, 2, &mut y).is_err());
    // Starts outside.
    assert!(matmul_q8_0_q8a_tokens(shape, &weights, &quantized, N_TOKENS, 1, &mut y[..N]).is_err());
    // Empty range.
    assert!(matmul_q8_0_q8a_tokens(shape, &weights, &quantized, 0, 0, &mut y[..0]).is_err());
    // Right range, wrong destination length.
    assert!(matmul_q8_0_q8a_tokens(shape, &weights, &quantized, 0, 2, &mut y[..N]).is_err());

    // A shape whose n_out disagrees with the weight view.
    let wrong_out = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N,
        n_out: N / 2,
    };
    assert!(
        matmul_q8_0_q8a_tokens(wrong_out, &weights, &quantized, 0, 1, &mut y[..N / 2]).is_err()
    );

    // A shape whose n_in disagrees with the activation view. The weight view
    // has to agree with it, or the earlier guard fires first and this one is
    // never reached -- which is the whole reason they are separate guards.
    let narrow = q8_payload(N, N / 2, 9);
    let narrow_weights = Q8Weights::new(&narrow, N, N / 2).expect("narrow weights");
    let wrong_in = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N / 2,
        n_out: N,
    };
    assert!(
        matmul_q8_0_q8a_tokens(wrong_in, &narrow_weights, &quantized, 0, 1, &mut y[..N]).is_err()
    );
}

#[test]
fn splitting_the_q4_tokens_reproduces_the_whole() {
    // The `Q4_0` twin of `splitting_the_tokens_reproduces_the_whole`. Worth its
    // own test rather than trusting the shape: this kernel un-nibbles each
    // block into a scratch buffer that is reused across every token of every
    // output row, so a split that got the iteration order wrong could corrupt
    // the scratch rather than merely misplace a result.
    const N_OUT: usize = 96;
    const N_IN: usize = 128;
    const N_TOKENS: usize = 12;

    let mut weight_payload =
        vec![0_u8; Q4Weights::derived_payload_len(N_OUT, N_IN).expect("weight len")];
    quantize_q4_0(N_OUT, N_IN, &values(N_OUT * N_IN, 31), &mut weight_payload).expect("quantize");
    let weights = Q4Weights::new(&weight_payload, N_OUT, N_IN).expect("weights");

    let x = values(N_TOKENS * N_IN, 13);
    let shape = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N_IN,
        n_out: N_OUT,
    };
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(N_TOKENS, N_IN).expect("len")];
    quantize_activations(N_TOKENS, N_IN, &x, &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, N_TOKENS, N_IN).expect("view");

    let mut whole = vec![0.0f32; N_TOKENS * N_OUT];
    matmul_q4_0_q8a(shape, &weights, &quantized, &mut whole).expect("whole");

    for workers in [1usize, 2, 3, 4, 6, 12, 5] {
        let per_worker = N_TOKENS.div_ceil(workers);
        let mut split = vec![0.0f32; N_TOKENS * N_OUT];
        for (index, chunk) in split.chunks_mut(per_worker * N_OUT).enumerate() {
            let start = index * per_worker;
            let count = chunk.len() / N_OUT;
            matmul_q4_0_q8a_tokens(shape, &weights, &quantized, start, count, chunk)
                .expect("token range");
        }
        assert_eq!(
            split, whole,
            "{workers} workers disagreed with one call over {N_TOKENS} Q4 tokens"
        );
    }
}

#[test]
fn a_q4_token_range_past_the_end_denies() {
    const N: usize = 64;
    const N_TOKENS: usize = 4;
    let mut weight_payload = vec![0_u8; Q4Weights::derived_payload_len(N, N).expect("len")];
    quantize_q4_0(N, N, &values(N * N, 17), &mut weight_payload).expect("quantize");
    let weights = Q4Weights::new(&weight_payload, N, N).expect("weights");

    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(N_TOKENS, N).expect("len")];
    quantize_activations(N_TOKENS, N, &values(N_TOKENS * N, 19), &mut scratch).expect("quantize");
    let quantized = Q8Weights::new(&scratch, N_TOKENS, N).expect("view");
    let shape = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N,
        n_out: N,
    };

    let mut y = vec![0.0f32; 2 * N];
    // Starts inside, ends outside.
    assert!(matmul_q4_0_q8a_tokens(shape, &weights, &quantized, 3, 2, &mut y).is_err());
    // Starts outside.
    assert!(matmul_q4_0_q8a_tokens(shape, &weights, &quantized, N_TOKENS, 1, &mut y[..N]).is_err());
    // Empty range.
    assert!(matmul_q4_0_q8a_tokens(shape, &weights, &quantized, 0, 0, &mut y[..0]).is_err());
    // Right range, wrong destination length.
    assert!(matmul_q4_0_q8a_tokens(shape, &weights, &quantized, 0, 2, &mut y[..N]).is_err());
    // Shape disagreeing with the weight view.
    let wrong_out = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N,
        n_out: N / 2,
    };
    assert!(
        matmul_q4_0_q8a_tokens(wrong_out, &weights, &quantized, 0, 1, &mut y[..N / 2]).is_err()
    );
    // Shape disagreeing with the activation view.
    let mut narrow_payload = vec![0_u8; Q4Weights::derived_payload_len(N, N / 2).expect("len")];
    quantize_q4_0(N, N / 2, &values(N * N / 2, 21), &mut narrow_payload).expect("quantize");
    let narrow = Q4Weights::new(&narrow_payload, N, N / 2).expect("narrow weights");
    let wrong_in = MatMulShape {
        n_tokens: N_TOKENS,
        n_in: N / 2,
        n_out: N,
    };
    assert!(matmul_q4_0_q8a_tokens(wrong_in, &narrow, &quantized, 0, 1, &mut y[..N]).is_err());
}
