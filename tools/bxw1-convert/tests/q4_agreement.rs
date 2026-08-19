//! The writer's `Q4_0` encoder against the kernel's, byte for byte.
//!
//! # Why this exists
//!
//! `tools/bxw1-convert` deliberately has no dependencies -- the workspace
//! replaces crates.io with a vendored directory, so the converter carries its
//! own SHA-256, JSON and container code rather than making a host tool a reason
//! to vendor anything. The consequence is that it also carries its own `Q4_0`
//! encoder, while `brainix_tensor` carries the decoder and a quantizer of its
//! own.
//!
//! Two implementations of one format, compiled separately, is exactly the
//! arrangement that drifts. And the failure is silent: a blob whose nibbles are
//! transposed, or whose scale is `peak / 8` instead of `peak / 7`, parses
//! perfectly and produces a model that is merely worse. There is no error to
//! catch, only a perplexity nobody measured against a baseline.
//!
//! So they are compared here, on inputs chosen to separate the conventions:
//! a swapped nibble order shows up only when the two values in a byte differ,
//! and a wrong scale divisor shows up only near the clamp.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

// `bxw1.rs` refers to `crate::sha256` for the digests, so the sibling module
// comes along. Both are included by path because the converter is a binary
// crate: an integration test cannot `use bxw1_convert::...`.
#[path = "../src/sha256.rs"]
mod sha256;
#[path = "../src/bxw1.rs"]
mod bxw1;

/// The writer's payload for one row of `values`.
fn writer_payload(values: &[f32]) -> Vec<u8> {
    bxw1::encode_q4_0(values).0
}

/// The kernel's payload for the same row.
fn kernel_payload(values: &[f32]) -> Vec<u8> {
    let len = brainix_tensor::Q4Weights::derived_payload_len(1, values.len()).expect("length");
    let mut payload = vec![0u8; len];
    brainix_tensor::quantize_q4_0(1, values.len(), values, &mut payload).expect("quantize");
    payload
}

fn assert_agrees(label: &str, values: &[f32]) {
    let writer = writer_payload(values);
    let kernel = kernel_payload(values);
    assert_eq!(
        writer.len(),
        kernel.len(),
        "{label}: payload lengths differ"
    );
    let first = writer
        .iter()
        .zip(kernel.iter())
        .position(|(left, right)| left != right);
    assert!(
        first.is_none(),
        "{label}: first disagreement at byte {}, writer {:#04x} vs kernel {:#04x}",
        first.unwrap(),
        writer[first.unwrap()],
        kernel[first.unwrap()],
    );
}

#[test]
fn the_two_encoders_agree_on_a_block_where_every_pair_differs() {
    // Adjacent values differ in magnitude AND sign, so a swapped nibble order
    // cannot coincide with the right answer.
    let values: Vec<f32> = (0..32)
        .map(|index| {
            let magnitude = 0.1 + (index as f32) * 0.03;
            if index % 2 == 0 {
                magnitude
            } else {
                -magnitude * 0.5
            }
        })
        .collect();
    assert_agrees("alternating signs and magnitudes", &values);
}

#[test]
fn the_two_encoders_agree_at_the_clamp_where_the_divisor_shows() {
    // The peak sits at one end and the rest are spread beneath it. A `peak / 8`
    // divisor puts these on different integers than `peak / 7` does.
    let mut values = vec![0.0f32; 32];
    values[0] = 1.0;
    for (index, slot) in values.iter_mut().enumerate().skip(1) {
        *slot = -1.0 + (index as f32) / 16.0;
    }
    assert_agrees("peak at one end", &values);
}

#[test]
fn the_two_encoders_agree_on_the_degenerate_blocks() {
    // An all-zero block is +0.0 with zero nibbles, and a block whose scale
    // would be subnormal is treated the same way. Both are rules, not
    // accidents, and both are places an implementation can differ while
    // looking correct on ordinary input.
    assert_agrees("all zero", &[0.0f32; 32]);

    let tiny = vec![1.0e-40f32; 32];
    assert_agrees("subnormal scale", &tiny);

    let mut one_live = vec![0.0f32; 32];
    one_live[17] = 0.5;
    assert_agrees("single non-zero, odd index", &one_live);
}

#[test]
fn the_two_encoders_agree_across_many_rows() {
    // More than one block, so the plane padding and the block stride are
    // exercised rather than only the first block's layout.
    let values: Vec<f32> = (0..32 * 5)
        .map(|index| ((index * 37 % 101) as f32 / 50.0) - 1.0)
        .collect();
    assert_agrees("five blocks", &values);
}
