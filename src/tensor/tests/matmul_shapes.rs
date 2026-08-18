//! The `Q4_0` matmul, and every shape a kernel is supposed to refuse.
//!
//! # Why these were missing
//!
//! `matmul_q4_0_q8a` shipped with no test at all -- the coverage gate found the
//! whole function uncovered. The denial paths in the `Q8_0` kernels were in the
//! same state: written, reviewed, never executed.
//!
//! That matters more than the percentage. These crates are fail-closed by
//! design, and a guard that has never run is a guard nobody has watched fail.
//! BXW1 §7.5's rule is that disagreeing sources deny with no precedence rule,
//! and the only way to know a kernel obeys it is to hand it sources that
//! disagree.

use brainix_tensor::{
    matmul_q4_0_q8a, matmul_q8_0_q8a, matmul_q8_0_q8a_rows, quantize_activations, quantize_q4_0,
    MatMulShape, Q4Weights, Q8Weights, Q4_0_BLOCK,
};

fn values(count: usize, seed: u32) -> Vec<f32> {
    let mut state = seed | 1;
    (0..count)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            ((state >> 8) as f32 / 8_388_608.0) - 1.0
        })
        .collect()
}

/// Quantized activations for `n_tokens x n_in`, as the kernels want them.
fn activations(n_tokens: usize, n_in: usize, seed: u32) -> Vec<u8> {
    let x = values(n_tokens * n_in, seed);
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(n_tokens, n_in).expect("shape")];
    quantize_activations(n_tokens, n_in, &x, &mut scratch).expect("quantize");
    scratch
}

fn q4_weights(n_out: usize, n_in: usize, seed: u32) -> Vec<u8> {
    let w = values(n_out * n_in, seed);
    let mut payload = vec![0u8; Q4Weights::derived_payload_len(n_out, n_in).expect("shape")];
    quantize_q4_0(n_out, n_in, &w, &mut payload).expect("quantize");
    payload
}

/// Decode a `Q4_0` payload back to floats, independently of the kernel.
///
/// Written out here rather than reusing anything in the crate on purpose: a
/// reference that shares code with the thing it checks agrees with it about
/// any mistake they share.
fn decode_q4(payload: &[u8], n_out: usize, n_in: usize) -> Vec<f32> {
    let blocks = n_out * (n_in / Q4_0_BLOCK);
    let scale_len = blocks * 4;
    let quant_start = scale_len.next_multiple_of(16);
    let mut out = vec![0.0f32; n_out * n_in];
    for block in 0..blocks {
        let at = block * 4;
        let scale = f32::from_le_bytes([
            payload[at],
            payload[at + 1],
            payload[at + 2],
            payload[at + 3],
        ]);
        for byte_index in 0..Q4_0_BLOCK / 2 {
            let byte = payload[quant_start + block * (Q4_0_BLOCK / 2) + byte_index];
            // Low nibble first, sign-extended from four bits.
            let low = (((byte << 4) as i8) >> 4) as f32;
            let high = ((byte as i8) >> 4) as f32;
            out[block * Q4_0_BLOCK + byte_index * 2] = low * scale;
            out[block * Q4_0_BLOCK + byte_index * 2 + 1] = high * scale;
        }
    }
    out
}

/// Decode a `Q8_0` payload back to floats, same reasoning as above.
fn decode_q8(payload: &[u8], n_out: usize, n_in: usize) -> Vec<f32> {
    let blocks = n_out * (n_in / 32);
    let quant_start = payload.len() - blocks * 32;
    let mut out = vec![0.0f32; n_out * n_in];
    for block in 0..blocks {
        let at = block * 4;
        let scale = f32::from_le_bytes([
            payload[at],
            payload[at + 1],
            payload[at + 2],
            payload[at + 3],
        ]);
        for lane in 0..32 {
            let quant = payload[quant_start + block * 32 + lane] as i8;
            out[block * 32 + lane] = f32::from(quant) * scale;
        }
    }
    out
}

#[test]
fn the_q4_kernel_computes_the_dot_product_of_what_is_actually_stored() {
    const N_OUT: usize = 8;
    const N_IN: usize = Q4_0_BLOCK * 4;

    let weight_values = values(N_OUT * N_IN, 3);
    let mut payload = vec![0u8; Q4Weights::derived_payload_len(N_OUT, N_IN).expect("shape")];
    quantize_q4_0(N_OUT, N_IN, &weight_values, &mut payload).expect("quantize");
    let weights = Q4Weights::new(&payload, N_OUT, N_IN).expect("view");

    let x = values(N_IN, 11);
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, N_IN).expect("shape")];
    quantize_activations(1, N_IN, &x, &mut scratch).expect("quantize");
    let view = Q8Weights::new(&scratch, 1, N_IN).expect("view");

    let shape = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };
    let mut y = vec![0.0f32; N_OUT];
    matmul_q4_0_q8a(shape, &weights, &view, &mut y).expect("matmul");

    // The reference is built from the DECODED payloads, not from the floats
    // they were quantized from.
    //
    // Comparing against the original weights measures how lossy Q4 is -- about
    // 0.45 absolute on this shape, since fifteen levels over 128 elements
    // accumulate -- and a tolerance loose enough to admit that is loose enough
    // to admit a transposed loop. Comparing against what the payload actually
    // holds asks the only question this kernel is responsible for: given these
    // stored values, is this the right dot product. The answer should be exact
    // to within f32 summation order, so the bound is tight and a mis-packed
    // nibble or a swapped index fails loudly.
    let decoded_w = decode_q4(&payload, N_OUT, N_IN);
    let decoded_x = decode_q8(&scratch, 1, N_IN);

    for (out_index, produced) in y.iter().enumerate() {
        let expected: f32 = (0..N_IN)
            .map(|k| decoded_w[out_index * N_IN + k] * decoded_x[k])
            .sum();
        assert!(
            (produced - expected).abs() <= expected.abs().max(1.0) * 1e-4,
            "row {out_index}: kernel {produced} vs decoded-payload reference {expected}"
        );
    }
}

#[test]
fn the_q4_kernel_denies_every_disagreeing_shape() {
    const N_OUT: usize = 4;
    const N_IN: usize = Q4_0_BLOCK * 2;

    let payload = q4_weights(N_OUT, N_IN, 5);
    let weights = Q4Weights::new(&payload, N_OUT, N_IN).expect("view");
    let scratch = activations(1, N_IN, 6);
    let view = Q8Weights::new(&scratch, 1, N_IN).expect("view");
    let mut y = vec![0.0f32; N_OUT];

    let ok = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };
    assert!(matmul_q4_0_q8a(ok, &weights, &view, &mut y).is_ok());

    // A zero in any extent.
    for bad in [
        MatMulShape {
            n_tokens: 0,
            n_in: N_IN,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: 0,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN,
            n_out: 0,
        },
    ] {
        assert!(
            matmul_q4_0_q8a(bad, &weights, &view, &mut y).is_err(),
            "a zero extent must deny"
        );
    }

    // A shape that disagrees with the weight view.
    let wrong_out = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT + 1,
    };
    assert!(matmul_q4_0_q8a(wrong_out, &weights, &view, &mut y).is_err());

    // A shape that disagrees with the activation view.
    let wrong_tokens = MatMulShape {
        n_tokens: 2,
        n_in: N_IN,
        n_out: N_OUT,
    };
    let mut wide = vec![0.0f32; N_OUT * 2];
    assert!(matmul_q4_0_q8a(wrong_tokens, &weights, &view, &mut wide).is_err());

    // An output slice of the wrong length.
    let mut short = vec![0.0f32; N_OUT - 1];
    assert!(matmul_q4_0_q8a(ok, &weights, &view, &mut short).is_err());
}

#[test]
fn the_q8_kernel_denies_every_disagreeing_shape() {
    const N_OUT: usize = 4;
    const N_IN: usize = 64;

    let wp = {
        let w = values(N_OUT * N_IN, 21);
        let mut p = vec![0u8; Q8Weights::derived_payload_len(N_OUT, N_IN).expect("shape")];
        quantize_activations(N_OUT, N_IN, &w, &mut p).expect("quantize");
        p
    };
    let weights = Q8Weights::new(&wp, N_OUT, N_IN).expect("view");
    let scratch = activations(1, N_IN, 22);
    let view = Q8Weights::new(&scratch, 1, N_IN).expect("view");
    let mut y = vec![0.0f32; N_OUT];

    let ok = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };
    assert!(matmul_q8_0_q8a(ok, &weights, &view, &mut y).is_ok());

    for bad in [
        MatMulShape {
            n_tokens: 0,
            n_in: N_IN,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: 0,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN,
            n_out: 0,
        },
    ] {
        assert!(matmul_q8_0_q8a(bad, &weights, &view, &mut y).is_err());
    }

    // Output length disagreeing with n_tokens x n_out.
    let mut short = vec![0.0f32; N_OUT - 1];
    assert!(matmul_q8_0_q8a(ok, &weights, &view, &mut short).is_err());

    // Shape disagreeing with the weight view -- and `y` sized to match the
    // WRONG shape, so the output-length check passes and the weight-view check
    // is the one that has to catch it. Sized to the right shape, the length
    // check fires first and this guard never runs, which is how it stayed
    // uncovered while looking tested.
    let mut sized_for_wrong = vec![0.0f32; N_OUT + 1];
    assert!(matmul_q8_0_q8a(
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN,
            n_out: N_OUT + 1
        },
        &weights,
        &view,
        &mut sized_for_wrong
    )
    .is_err());
    // Same for a disagreeing n_in, which no length check can catch: the output
    // is the same size either way.
    assert!(matmul_q8_0_q8a(
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN * 2,
            n_out: N_OUT
        },
        &weights,
        &view,
        &mut y
    )
    .is_err());
    let mut wide = vec![0.0f32; N_OUT * 2];
    assert!(matmul_q8_0_q8a(
        MatMulShape {
            n_tokens: 2,
            n_in: N_IN,
            n_out: N_OUT
        },
        &weights,
        &view,
        &mut wide
    )
    .is_err());
}

#[test]
fn the_row_split_kernel_denies_every_disagreeing_shape() {
    const N_OUT: usize = 8;
    const N_IN: usize = 64;

    let wp = {
        let w = values(N_OUT * N_IN, 31);
        let mut p = vec![0u8; Q8Weights::derived_payload_len(N_OUT, N_IN).expect("shape")];
        quantize_activations(N_OUT, N_IN, &w, &mut p).expect("quantize");
        p
    };
    let weights = Q8Weights::new(&wp, N_OUT, N_IN).expect("view");
    let scratch = activations(1, N_IN, 32);
    let view = Q8Weights::new(&scratch, 1, N_IN).expect("view");

    let shape = MatMulShape {
        n_tokens: 1,
        n_in: N_IN,
        n_out: N_OUT,
    };

    // A valid half.
    let mut half = vec![0.0f32; 4];
    assert!(matmul_q8_0_q8a_rows(shape, &weights, &view, 0, 4, &mut half).is_ok());

    // Zero extents.
    for bad in [
        MatMulShape {
            n_tokens: 0,
            n_in: N_IN,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: 0,
            n_out: N_OUT,
        },
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN,
            n_out: 0,
        },
    ] {
        assert!(matmul_q8_0_q8a_rows(bad, &weights, &view, 0, 4, &mut half).is_err());
    }

    // Output sized for a different row count than requested.
    let mut wrong = vec![0.0f32; 3];
    assert!(matmul_q8_0_q8a_rows(shape, &weights, &view, 0, 4, &mut wrong).is_err());

    // A disagreeing n_in. The output length is identical either way, so only
    // the view cross-check can refuse it.
    assert!(matmul_q8_0_q8a_rows(
        MatMulShape {
            n_tokens: 1,
            n_in: N_IN * 2,
            n_out: N_OUT
        },
        &weights,
        &view,
        0,
        4,
        &mut half
    )
    .is_err());

    // Shape disagreeing with the activation view.
    let mut wide = vec![0.0f32; 8];
    assert!(matmul_q8_0_q8a_rows(
        MatMulShape {
            n_tokens: 2,
            n_in: N_IN,
            n_out: N_OUT
        },
        &weights,
        &view,
        0,
        4,
        &mut wide
    )
    .is_err());
}
