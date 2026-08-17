//! `Q8_0` activations against the `f32`-activation reference.
//!
//! The point of the `SDOT` path is speed; the point of these tests is that it
//! computes the same thing. "Same" cannot mean bit-identical -- quantizing the
//! activations is a lossy step by construction -- so the bound is stated and
//! checked rather than hoped for.

use brainix_tensor::{
    matmul_q8_0, matmul_q8_0_q8a, quantize_activations, MatMulShape, Q8Weights,
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
    let len = Q8Weights::derived_payload_len(n_out, n_in).expect("shape");
    let mut payload = vec![0u8; len];
    let blocks = n_out * (n_in / 32);
    let quant_start = len - blocks * 32;
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
            view.dequantize_row_into(row, &mut recovered).expect("dequantize");
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
    view.dequantize_row_into(0, &mut recovered).expect("dequantize");
    assert!(
        recovered.iter().all(|value| *value == 0.0),
        "an all-zero block must dequantize to zeros, got {recovered:?}"
    );
}

#[test]
fn a_shape_disagreement_denies() {
    let mut scratch = vec![0u8; Q8Weights::derived_payload_len(1, 32).expect("len")];
    assert!(quantize_activations(1, 32, &vec![0.0; 31], &mut scratch).is_err());
    assert!(quantize_activations(1, 32, &vec![0.0; 32], &mut scratch[..4]).is_err());
}
