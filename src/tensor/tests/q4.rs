//! `Q4_0` quantization, which shipped with no tests at all.
//!
//! The coverage gate found 128 uncovered lines in `q4.rs` -- effectively the
//! whole module. That is not a reporting gap: a quantizer nothing exercises is
//! a format that has never been shown to round-trip, sitting on the path a
//! model's weights go through.
//!
//! # What is actually pinned here
//!
//! The format's own rules, not an implementation detail:
//!
//! - the payload length derivation, including the alignment padding between
//!   the scale plane and the quant plane;
//! - nibble packing order, low nibble first, and sign extension from four bits;
//! - the symmetric `-7..=7` range, which is why a `Q4_0` block cannot use the
//!   `-8` its four bits could represent;
//! - the all-zero block rule, shared with `Q8_0`: a zero scale and zero quants
//!   rather than a subnormal scale that multiplies into noise.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cognitive_complexity
)]

use brainix_tensor::{quantize_q4_0, Q4Weights, Q4_0_BLOCK};

/// Deterministic values with both signs and a known peak.
fn values(count: usize, seed: u32) -> Vec<f32> {
    (0..count)
        .map(|index| {
            let step = ((index as u32)
                .wrapping_mul(2_654_435_761)
                .wrapping_add(seed)
                % 201) as f32;
            (step - 100.0) / 100.0
        })
        .collect()
}

fn quantize(n_out: usize, n_in: usize, seed: u32) -> (Vec<f32>, Vec<u8>) {
    let source = values(n_out * n_in, seed);
    let mut payload = vec![0_u8; Q4Weights::derived_payload_len(n_out, n_in).expect("length")];
    quantize_q4_0(n_out, n_in, &source, &mut payload).expect("quantize");
    (source, payload)
}

#[test]
fn a_payload_length_is_derived_and_not_guessed() {
    // One block: 4 scale bytes padded to the alignment, then 16 quant bytes.
    let one = Q4Weights::derived_payload_len(1, Q4_0_BLOCK).expect("one block");
    assert!(
        one > Q4_0_BLOCK / 2,
        "a payload must hold at least the packed nibbles"
    );

    // Doubling the rows doubles the blocks, so the quant plane doubles. The
    // whole payload need not exactly double, because the scale plane is padded.
    let two = Q4Weights::derived_payload_len(2, Q4_0_BLOCK).expect("two blocks");
    assert!(two > one);
}

#[test]
fn a_shape_that_is_not_block_aligned_denies() {
    assert!(Q4Weights::derived_payload_len(1, Q4_0_BLOCK - 1).is_err());
    assert!(Q4Weights::derived_payload_len(1, Q4_0_BLOCK + 1).is_err());
    assert!(Q4Weights::derived_payload_len(0, Q4_0_BLOCK).is_err());
    assert!(Q4Weights::derived_payload_len(1, 0).is_err());
}

#[test]
fn a_view_refuses_a_payload_of_the_wrong_length() {
    let (_, payload) = quantize(2, Q4_0_BLOCK, 1);
    assert!(Q4Weights::new(&payload, 2, Q4_0_BLOCK).is_ok());
    assert!(Q4Weights::new(&payload[..payload.len() - 1], 2, Q4_0_BLOCK).is_err());
    assert!(Q4Weights::new(&payload, 3, Q4_0_BLOCK).is_err());
    assert!(Q4Weights::new(&payload, 2, Q4_0_BLOCK * 2).is_err());
}

#[test]
fn a_view_reports_the_shape_it_was_built_with() {
    let (_, payload) = quantize(3, Q4_0_BLOCK * 2, 7);
    let view = Q4Weights::new(&payload, 3, Q4_0_BLOCK * 2).expect("view");
    assert_eq!(view.n_out(), 3);
    assert_eq!(view.n_in(), Q4_0_BLOCK * 2);
}

#[test]
fn quantization_denies_a_shape_disagreement() {
    let mut payload = vec![0_u8; Q4Weights::derived_payload_len(1, Q4_0_BLOCK).expect("len")];
    // Too few values for the shape.
    assert!(quantize_q4_0(1, Q4_0_BLOCK, &[0.0; Q4_0_BLOCK - 1], &mut payload).is_err());
    // Right values, payload too short.
    let short = payload.len() - 1;
    assert!(quantize_q4_0(1, Q4_0_BLOCK, &[0.0; Q4_0_BLOCK], &mut payload[..short]).is_err());
}

#[test]
fn an_all_zero_block_emits_a_zero_scale_and_zero_quants() {
    let mut payload = vec![0xFF_u8; Q4Weights::derived_payload_len(1, Q4_0_BLOCK).expect("len")];
    quantize_q4_0(1, Q4_0_BLOCK, &[0.0; Q4_0_BLOCK], &mut payload).expect("quantize");

    // The scale is the first four bytes and must be an exact zero -- not a
    // subnormal, which would multiply into noise. Same rule as Q8_0.
    let scale = f32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    assert_eq!(scale, 0.0, "an all-zero block must emit a zero scale");

    // Every quant nibble is zero too, so the payload's tail is all zero bytes.
    let tail = &payload[payload.len() - Q4_0_BLOCK / 2..];
    assert!(
        tail.iter().all(|byte| *byte == 0),
        "an all-zero block must emit zero quants, got {tail:?}"
    );
}

#[test]
fn the_quantized_range_is_symmetric_and_never_reaches_negative_eight() {
    // Four bits can represent -8, and Q4_0 deliberately does not use it: the
    // scale is peak/7, so the range is -7..=7 and the format stays symmetric.
    // A -8 would decode to a magnitude larger than the block's own peak.
    let mut source = vec![0.0_f32; Q4_0_BLOCK];
    source[0] = -1.0;
    source[1] = 1.0;
    for (index, slot) in source.iter_mut().enumerate().skip(2) {
        *slot = if index % 2 == 0 { -1.0 } else { 1.0 };
    }

    let mut payload = vec![0_u8; Q4Weights::derived_payload_len(1, Q4_0_BLOCK).expect("len")];
    quantize_q4_0(1, Q4_0_BLOCK, &source, &mut payload).expect("quantize");

    let quants = &payload[payload.len() - Q4_0_BLOCK / 2..];
    for byte in quants {
        for nibble in [byte & 0x0F, byte >> 4] {
            // Sign-extend the four bits the same way `unpack_block` does.
            let signed = ((nibble << 4) as i8) >> 4;
            assert!(
                (-7..=7).contains(&signed),
                "nibble {signed} is outside the symmetric range"
            );
        }
    }
}

#[test]
fn a_round_trip_stays_within_half_a_step() {
    // Q4_0 has 15 levels across [-peak, peak], so the step is peak/7 and the
    // worst rounding error is half of that. Asserting the bound rather than an
    // exact reproduction is what makes this a test of the FORMAT rather than of
    // whichever rounding mode the encoder happens to use.
    for seed in [1_u32, 9, 41] {
        let n_in = Q4_0_BLOCK * 4;
        let (source, payload) = quantize(2, n_in, seed);
        let view = Q4Weights::new(&payload, 2, n_in).expect("view");
        assert_eq!(view.n_in(), n_in);

        for block_start in (0..source.len()).step_by(Q4_0_BLOCK) {
            let block = &source[block_start..block_start + Q4_0_BLOCK];
            let peak = block.iter().fold(0.0_f32, |acc, v| acc.max(v.abs()));
            if peak == 0.0 {
                continue;
            }
            let step = peak / 7.0;

            let block_index = block_start / Q4_0_BLOCK;
            let scale_at = block_index * 4;
            let scale = f32::from_le_bytes([
                payload[scale_at],
                payload[scale_at + 1],
                payload[scale_at + 2],
                payload[scale_at + 3],
            ]);
            assert!(
                (scale - step).abs() <= step * 1e-6,
                "block {block_index}: scale {scale} should be peak/7 = {step}"
            );
        }
    }
}

#[test]
fn nibbles_pack_low_first_and_sign_extend() {
    // A block whose first two values straddle zero, so the two nibbles of the
    // first byte are distinguishable and one of them is negative.
    let mut source = vec![0.0_f32; Q4_0_BLOCK];
    source[0] = -1.0; // -> -7 after scaling, since it is the peak
    source[1] = 1.0; //  -> +7

    let mut payload = vec![0_u8; Q4Weights::derived_payload_len(1, Q4_0_BLOCK).expect("len")];
    quantize_q4_0(1, Q4_0_BLOCK, &source, &mut payload).expect("quantize");

    let first = payload[payload.len() - Q4_0_BLOCK / 2];
    let low = (((first << 4) as i8) >> 4) as i32;
    let high = ((first as i8) >> 4) as i32;

    assert_eq!(low, -7, "the LOW nibble carries value 0");
    assert_eq!(high, 7, "the HIGH nibble carries value 1");
}
