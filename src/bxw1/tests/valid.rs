//! What a well-formed blob must produce.
//!
//! The adversarial suite proves the loader refuses; this one proves it does
//! not refuse everything, that the values it hands back are the values the
//! blob declared, and that a validated `Q8_0` payload is exactly what the
//! tensor kernels expect at the seam.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

mod common;

use brainix_bxw1::{Bxw1Error, Dtype, RopePairing, WeightBlob};
use brainix_tensor::Q8Weights;
use common::{sha256, valid_blob, ModelShape, REGION_CAPACITY};

#[test]
fn a_well_formed_blob_parses() {
    let blob = valid_blob();
    let weights = blob.parse().expect("the reference fixture must parse");
    assert_eq!(weights.tensor_count(), 12);
}

#[test]
fn the_header_carries_the_declared_hyperparameters() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();
    let header = weights.header();

    assert_eq!(header.arch_id, 1);
    assert_eq!(header.n_layers, 1);
    assert_eq!(header.d_model, 64);
    assert_eq!(header.n_heads, 2);
    assert_eq!(header.n_kv_heads, 1);
    assert_eq!(header.d_head, 32);
    assert_eq!(header.d_ffn, 128);
    assert_eq!(header.vocab_size, 33);
    assert_eq!(header.max_seq_len, 128);
    assert_eq!(header.rope_dim, 32);
    assert_eq!(header.rope_pairing, RopePairing::Interleaved);
    assert_eq!(header.rope_theta, 10_000.0);
    assert_eq!(header.norm_eps, 1.0e-5);
    assert_eq!(header.bos_token_id, 1);
    assert_eq!(header.eos_token_id, 2);
    assert_eq!(header.vocab_len, 4096);
    assert!(!header.tied_output);
    assert_eq!(header.total_size, blob.bytes.len() as u64);
}

#[test]
fn a_tensor_is_resolved_by_name_with_its_dtype_and_shape() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();

    let embeddings = weights.tensor_by_name(b"tok_embeddings.weight").unwrap();
    assert_eq!(embeddings.dtype(), Dtype::Q8);
    assert_eq!(embeddings.rank(), 2);
    assert_eq!(embeddings.dims(), &[33, 64]);
    assert_eq!(embeddings.elements(), 33 * 64);

    let norm = weights.tensor_by_name(b"norm.weight").unwrap();
    assert_eq!(norm.dtype(), Dtype::F32);
    assert_eq!(norm.rank(), 1);
    assert_eq!(norm.dims(), &[64]);
    assert_eq!(norm.data().len(), 64 * 4);
}

#[test]
fn tensor_data_is_borrowed_never_copied() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();
    let tensor = weights
        .tensor_by_name(b"layers.0.attention.wq.weight")
        .unwrap();

    let start = tensor.offset() as usize;
    let expected = &blob.bytes[start..start + tensor.data().len()];
    assert!(
        core::ptr::eq(tensor.data(), expected),
        "the payload must be the caller's bytes, not a copy of them"
    );
    assert_eq!(tensor.offset() % 128, 0, "every extent is 128-aligned");
}

#[test]
fn every_record_is_reachable_by_index() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();
    for index in 0..weights.tensor_count() {
        let tensor = weights.tensor(index).unwrap();
        assert!(!tensor.name().is_empty());
        assert_eq!(tensor.data().len() as u64 % 4, 0);
    }
    assert_eq!(
        weights.tensor(weights.tensor_count()).unwrap_err(),
        Bxw1Error::TensorIndexOutOfRange
    );
    assert_eq!(
        weights.tensor_by_name(b"not.a.tensor").unwrap_err(),
        Bxw1Error::TensorNameNotFound
    );
}

#[test]
fn the_blob_digest_covers_every_byte() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();
    assert_eq!(weights.blob_digest(), sha256(&blob.bytes));
}

#[test]
fn a_tied_output_model_parses_without_an_output_weight() {
    let shape = ModelShape {
        tied_output: true,
        ..ModelShape::default()
    };
    let blob = common::blob_for(&shape);
    let weights = blob.parse().expect("a tied model must parse");

    assert!(weights.header().tied_output);
    assert_eq!(weights.tensor_count(), 11);
    assert_eq!(
        weights.tensor_by_name(b"output.weight").unwrap_err(),
        Bxw1Error::TensorNameNotFound
    );
}

#[test]
fn a_validated_q8_payload_is_what_the_kernels_expect() {
    let blob = valid_blob();
    let weights = blob.parse().unwrap();
    let tensor = weights.tensor_by_name(b"tok_embeddings.weight").unwrap();

    // The seam this crate exists to feed: P3-T4's split-plane view derives the
    // same plane offsets from the same shape, so agreement here is two
    // independent readings of §4.2 matching.
    Q8Weights::new(tensor.data(), 33, 64).expect("the payload must satisfy the Q8_0 layout");
}

#[test]
fn a_region_exactly_the_size_of_the_blob_is_enough() {
    let blob = valid_blob();
    let capacity = blob.bytes.len() as u64;
    WeightBlob::parse(&blob.bytes, capacity).expect("a region of exactly the blob's size fits");
    assert_eq!(
        WeightBlob::parse(&blob.bytes, capacity - 1).unwrap_err(),
        Bxw1Error::BlobExceedsRegionCapacity
    );
    assert!(REGION_CAPACITY > capacity);
}

// ------------------------------------------------ round trips found by coverage
//
// `to_bxw1` is the encoder half of the enum mapping. Coverage showed only the
// decoder half (`from_bxw1`) had ever run, which means the tool that WRITES a
// blob and the loader that reads one had never been checked against each other.
// A drift there produces a file that this loader rejects and no test catches.

#[test]
fn dtype_round_trips_through_its_bxw1_value() {
    for dtype in [Dtype::F32, Dtype::Q8] {
        assert_eq!(
            Dtype::from_bxw1(dtype.to_bxw1()),
            Ok(dtype),
            "{dtype:?} did not survive the encode/decode round trip"
        );
    }
    // Normative values (§5.4): a blob written by any other tool carries these
    // numbers, so they are not free to follow the enum's declaration order.
    assert_eq!(Dtype::F32.to_bxw1(), Dtype::BXW1_F32);
    assert_eq!(Dtype::Q8.to_bxw1(), Dtype::BXW1_Q8_0);
}

#[test]
fn rope_pairing_round_trips_through_its_bxw1_value() {
    for pairing in [RopePairing::Interleaved, RopePairing::HalfSplit] {
        assert_eq!(
            RopePairing::from_bxw1(pairing.to_bxw1()),
            Ok(pairing),
            "{pairing:?} did not survive the encode/decode round trip"
        );
    }
    assert_eq!(
        RopePairing::Interleaved.to_bxw1(),
        RopePairing::BXW1_INTERLEAVED
    );
    assert_eq!(
        RopePairing::HalfSplit.to_bxw1(),
        RopePairing::BXW1_HALF_SPLIT
    );
}

/// `Q4_0`'s wire value, both directions.
///
/// The pair matters more than either half: a loader that decodes `0x0002` but
/// re-encodes it as something else writes a blob it cannot read back.
#[test]
fn the_q4_dtype_round_trips_through_its_wire_value() {
    assert_eq!(Dtype::from_bxw1(Dtype::BXW1_Q4_0), Ok(Dtype::Q4));
    assert_eq!(Dtype::Q4.to_bxw1(), Dtype::BXW1_Q4_0);
    assert_eq!(Dtype::BXW1_Q4_0, 0x0002);

    // The other two are unchanged by the addition, which is the compatibility
    // claim: a v1.0 blob written before Q4_0 existed still reads identically.
    assert_eq!(Dtype::from_bxw1(0x0000), Ok(Dtype::F32));
    assert_eq!(Dtype::from_bxw1(0x0001), Ok(Dtype::Q8));
    assert_eq!(Dtype::F32.to_bxw1(), 0x0000);
    assert_eq!(Dtype::Q8.to_bxw1(), 0x0001);
}
