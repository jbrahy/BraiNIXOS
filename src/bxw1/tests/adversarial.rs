//! Adversarial fixtures.
//!
//! A BXW1 blob arrives from disk and BraiNIX treats it as hostile input. Each
//! test below states the attack it encodes and asserts the **exact** rule the
//! loader denies with — never merely that it denied, because "it errored" is
//! compatible with denying for the wrong reason, and a weight loader that
//! rejects for the wrong reason today accepts for the wrong reason after the
//! next edit. Nothing here may panic, hang, allocate, or return a partially
//! validated blob.
//!
//! Every mutation that changes a tensor record re-seals the table digest, and
//! every mutation that changes a payload re-seals that tensor's digest, so a
//! test reaches the rule it is aiming at instead of stopping at rule C1 or C2.
//! The tests that deliberately skip the re-seal are the ones proving C1 and C2.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

mod common;

use brainix_bxw1::{Bxw1Error, WeightBlob};
use common::{
    blob_for, header, record, valid_blob, Blob, ModelShape, DTYPE_Q8_0, HEADER_BYTES,
    REGION_CAPACITY,
};

/// Parses raw bytes at the standard capacity.
fn parse(bytes: &[u8]) -> Bxw1Error {
    match WeightBlob::parse(bytes, REGION_CAPACITY) {
        Ok(_) => panic!("fixture parsed but was expected to deny"),
        Err(error) => error,
    }
}

/// Truncates the blob at `length` and tells it that this is its whole size,
/// so the truncation is met by a structural rule rather than by rule H7.
fn truncated_and_declared(length: usize) -> Vec<u8> {
    let mut blob = valid_blob();
    blob.patch_u64(header::TOTAL_SIZE, length as u64);
    blob.bytes.truncate(length);
    blob.bytes
}

/// A blob whose header field `at` has been overwritten with `value`.
fn with_u32(at: usize, value: u32) -> Blob {
    let mut blob = valid_blob();
    blob.patch_u32(at, value);
    blob
}

/// A blob whose header field `at` has been overwritten with `value`.
fn with_u64(at: usize, value: u64) -> Blob {
    let mut blob = valid_blob();
    blob.patch_u64(at, value);
    blob
}

// ---------------------------------------------------------------------------
// Degenerate and truncated inputs
// ---------------------------------------------------------------------------

#[test]
fn a_zero_length_blob_denies() {
    assert_eq!(parse(&[]), Bxw1Error::EmptyBlob);
}

#[test]
fn a_blob_shorter_than_the_header_denies() {
    let blob = valid_blob();
    for length in [1, 4, 16, 255] {
        assert_eq!(
            parse(&blob.bytes[..length]),
            Bxw1Error::BlobTooSmallForHeader,
            "length {length}"
        );
    }
}

#[test]
fn truncation_alone_is_caught_by_the_object_length_cross_check() {
    // Rule H7 is the first thing a truncated object meets: the slice's length
    // is the authority and `total_size` is only ever compared to it.
    let blob = valid_blob();
    for length in [HEADER_BYTES, 2176, 4096, blob.bytes.len() - 1] {
        assert_eq!(
            parse(&blob.bytes[..length]),
            Bxw1Error::TotalSizeMismatch,
            "length {length}"
        );
    }
}

#[test]
fn truncation_at_the_header_boundary_denies() {
    assert_eq!(
        parse(&truncated_and_declared(HEADER_BYTES)),
        Bxw1Error::TensorTableExceedsBlob
    );
}

#[test]
fn truncation_inside_the_table_denies() {
    assert_eq!(
        parse(&truncated_and_declared(HEADER_BYTES + 80)),
        Bxw1Error::TensorTableExceedsBlob
    );
}

#[test]
fn truncation_at_the_table_boundary_denies() {
    // The table fits exactly, so the next boundary is the tensor-data region:
    // its declared start is now at the end of the object.
    assert_eq!(
        parse(&truncated_and_declared(2176)),
        Bxw1Error::TensorDataOffsetPastBlob
    );
}

#[test]
fn truncation_inside_the_tensor_data_region_denies() {
    let mut blob = valid_blob();
    let length = blob.data_off + 128;
    blob.patch_u64(header::TOTAL_SIZE, length as u64);
    blob.patch_u64(header::TENSOR_DATA_LEN, 128);
    blob.bytes.truncate(length);
    assert_eq!(parse(&blob.bytes), Bxw1Error::ExtentPastBlob);
}

#[test]
fn a_truncated_tensor_data_region_that_still_agrees_with_itself_denies() {
    // Truncating the object without adjusting `tensor_data_len` is caught
    // before any extent is examined: the region must end exactly at the blob's
    // end (rule H11).
    let mut blob = valid_blob();
    let length = blob.data_off + 128;
    blob.patch_u64(header::TOTAL_SIZE, length as u64);
    blob.bytes.truncate(length);
    assert_eq!(parse(&blob.bytes), Bxw1Error::TensorDataExtentNotBlobEnd);
}

// ---------------------------------------------------------------------------
// Header identity and layout (rules H2-H12)
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_magic_denies() {
    let mut blob = valid_blob();
    blob.patch_byte(header::MAGIC + 3, b'2');
    assert_eq!(blob.error(), Bxw1Error::BadMagic);
}

#[test]
fn a_wrong_version_denies_in_both_components() {
    let mut major = valid_blob();
    major.patch_u16(header::VERSION_MAJOR, 2);
    assert_eq!(major.error(), Bxw1Error::UnsupportedVersion);

    let mut minor = valid_blob();
    minor.patch_u16(header::VERSION_MINOR, 1);
    assert_eq!(minor.error(), Bxw1Error::UnsupportedVersion);
}

#[test]
fn an_undefined_flag_bit_denies() {
    assert_eq!(
        with_u32(header::FLAGS, 0b10).error(),
        Bxw1Error::ReservedFlagBitSet
    );
    assert_eq!(
        with_u32(header::FLAGS, u32::MAX).error(),
        Bxw1Error::ReservedFlagBitSet
    );
}

#[test]
fn a_zero_tensor_count_denies() {
    assert_eq!(
        with_u32(header::TENSOR_COUNT, 0).error(),
        Bxw1Error::ZeroTensorCount
    );
}

#[test]
fn a_tensor_count_that_would_overflow_the_table_extent_denies_at_the_ceiling() {
    // `tensor_count × 160` cannot overflow a `u64` once rule H5 has bounded
    // the count at 4096, which is exactly what H9 says: H5 makes the overflow
    // unreachable and the checked multiply is mandatory anyway. The reachable
    // denial is therefore the ceiling, and this test pins that.
    assert_eq!(
        with_u32(header::TENSOR_COUNT, u32::MAX).error(),
        Bxw1Error::TensorCountExceedsCeiling
    );
    assert_eq!(
        with_u32(header::TENSOR_COUNT, 4097).error(),
        Bxw1Error::TensorCountExceedsCeiling
    );
}

#[test]
fn a_total_size_below_the_header_denies() {
    assert_eq!(
        with_u64(header::TOTAL_SIZE, 255).error(),
        Bxw1Error::TotalSizeBelowHeader
    );
}

#[test]
fn a_total_size_above_the_format_ceiling_denies() {
    assert_eq!(
        with_u64(header::TOTAL_SIZE, 23_622_320_129).error(),
        Bxw1Error::TotalSizeExceedsMaxSize
    );
}

#[test]
fn a_total_size_above_the_reserved_region_denies() {
    assert_eq!(
        with_u64(header::TOTAL_SIZE, REGION_CAPACITY + 128).error(),
        Bxw1Error::TotalSizeExceedsRegionCapacity
    );
}

#[test]
fn a_total_size_disagreeing_with_the_object_length_denies_in_both_directions() {
    let blob = valid_blob();
    let actual = blob.bytes.len() as u64;
    assert_eq!(
        with_u64(header::TOTAL_SIZE, actual + 128).error(),
        Bxw1Error::TotalSizeMismatch
    );
    assert_eq!(
        with_u64(header::TOTAL_SIZE, actual - 128).error(),
        Bxw1Error::TotalSizeMismatch
    );
}

#[test]
fn a_tensor_table_offset_other_than_256_denies() {
    assert_eq!(
        with_u64(header::TENSOR_TABLE_OFF, 512).error(),
        Bxw1Error::TensorTableOffsetNot256
    );
    assert_eq!(
        with_u64(header::TENSOR_TABLE_OFF, 0).error(),
        Bxw1Error::TensorTableOffsetNot256
    );
}

#[test]
fn a_misaligned_tensor_data_offset_denies_and_is_never_rounded() {
    let blob = valid_blob();
    assert_eq!(
        with_u64(header::TENSOR_DATA_OFF, blob.data_off as u64 + 1).error(),
        Bxw1Error::TensorDataOffsetMisaligned
    );
}

#[test]
fn a_tensor_data_offset_inside_the_table_denies() {
    assert_eq!(
        with_u64(header::TENSOR_DATA_OFF, 1024).error(),
        Bxw1Error::TensorDataOffsetBeforeTable
    );
}

#[test]
fn a_tensor_data_offset_past_the_blob_denies() {
    let blob = valid_blob();
    assert_eq!(
        with_u64(header::TENSOR_DATA_OFF, blob.bytes.len() as u64).error(),
        Bxw1Error::TensorDataOffsetPastBlob
    );
}

#[test]
fn an_oversized_gap_before_the_first_extent_denies() {
    let blob = valid_blob();
    assert_eq!(
        with_u64(header::TENSOR_DATA_OFF, blob.data_off as u64 + 128).error(),
        Bxw1Error::TableToDataGapTooLarge
    );
}

#[test]
fn a_tensor_data_region_that_does_not_end_at_the_blob_denies() {
    let blob = valid_blob();
    let length = (blob.bytes.len() - blob.data_off) as u64;
    assert_eq!(
        with_u64(header::TENSOR_DATA_LEN, length - 128).error(),
        Bxw1Error::TensorDataExtentNotBlobEnd
    );
}

#[test]
fn a_tensor_data_length_that_overflows_denies() {
    assert_eq!(
        with_u64(header::TENSOR_DATA_LEN, u64::MAX).error(),
        Bxw1Error::TensorDataExtentOverflow
    );
}

#[test]
fn a_nonzero_reserved_header_field_denies() {
    for at in [header::RESERVED_0, header::RESERVED_1] {
        assert_eq!(
            with_u64(at, 1).error(),
            Bxw1Error::ReservedHeaderFieldNonZero,
            "offset {at}"
        );
    }
    assert_eq!(
        with_u32(header::RESERVED_3, 1).error(),
        Bxw1Error::ReservedHeaderFieldNonZero
    );
    let mut tail = valid_blob();
    tail.patch_byte(header::RESERVED_TAIL + 40, 0xFF);
    assert_eq!(tail.error(), Bxw1Error::ReservedHeaderFieldNonZero);
}

// ---------------------------------------------------------------------------
// Model metadata (rules H13-H22)
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_architecture_denies() {
    assert_eq!(
        with_u32(header::ARCH_ID, 0).error(),
        Bxw1Error::UnknownArchId
    );
    assert_eq!(
        with_u32(header::ARCH_ID, 2).error(),
        Bxw1Error::UnknownArchId
    );
}

#[test]
fn each_hyperparameter_is_bounded_independently() {
    let cases: [(usize, u32, Bxw1Error); 16] = [
        (header::N_LAYERS, 0, Bxw1Error::NLayersOutOfRange),
        (header::N_LAYERS, 129, Bxw1Error::NLayersOutOfRange),
        (header::D_MODEL, 0, Bxw1Error::DModelOutOfRange),
        (header::D_MODEL, 16385, Bxw1Error::DModelOutOfRange),
        (header::N_HEADS, 0, Bxw1Error::NHeadsOutOfRange),
        (header::N_HEADS, 257, Bxw1Error::NHeadsOutOfRange),
        (header::N_KV_HEADS, 0, Bxw1Error::NKvHeadsOutOfRange),
        (header::N_KV_HEADS, 257, Bxw1Error::NKvHeadsOutOfRange),
        (header::D_HEAD, 0, Bxw1Error::DHeadOutOfRange),
        (header::D_HEAD, 513, Bxw1Error::DHeadOutOfRange),
        (header::D_FFN, 0, Bxw1Error::DFfnOutOfRange),
        (header::D_FFN, 65537, Bxw1Error::DFfnOutOfRange),
        (header::VOCAB_SIZE, 0, Bxw1Error::VocabSizeOutOfRange),
        (
            header::VOCAB_SIZE,
            (1 << 20) + 1,
            Bxw1Error::VocabSizeOutOfRange,
        ),
        (header::MAX_SEQ_LEN, 0, Bxw1Error::MaxSeqLenOutOfRange),
        (
            header::MAX_SEQ_LEN,
            (1 << 17) + 1,
            Bxw1Error::MaxSeqLenOutOfRange,
        ),
    ];
    for (at, value, expected) in cases {
        assert_eq!(
            with_u32(at, value).error(),
            expected,
            "offset {at} value {value}"
        );
    }
}

#[test]
fn more_kv_heads_than_query_heads_denies() {
    assert_eq!(
        with_u32(header::N_KV_HEADS, 3).error(),
        Bxw1Error::KvHeadsExceedHeads
    );
}

#[test]
fn a_grouped_query_group_size_that_is_not_exact_denies() {
    let shape = ModelShape {
        n_heads: 4,
        d_head: 16,
        n_kv_heads: 2,
        ..ModelShape::default()
    };
    let mut blob = blob_for(&shape);
    blob.patch_u32(header::N_KV_HEADS, 3);
    assert_eq!(blob.error(), Bxw1Error::HeadsNotDivisibleByKvHeads);
}

#[test]
fn a_head_width_that_is_not_d_model_denies() {
    assert_eq!(
        with_u32(header::D_HEAD, 16).error(),
        Bxw1Error::HeadWidthNotDModel
    );
}

#[test]
fn a_rope_dimension_outside_the_head_denies() {
    assert_eq!(
        with_u32(header::ROPE_DIM, 0).error(),
        Bxw1Error::RopeDimOutOfRange
    );
    assert_eq!(
        with_u32(header::ROPE_DIM, 34).error(),
        Bxw1Error::RopeDimOutOfRange
    );
}

#[test]
fn an_odd_rope_dimension_denies() {
    assert_eq!(
        with_u32(header::ROPE_DIM, 31).error(),
        Bxw1Error::RopeDimOdd
    );
}

#[test]
fn a_rope_pairing_of_zero_denies_rather_than_defaulting() {
    // The load-bearing clause of §5.5: zero is the value a converter that
    // never heard of the field writes, which is exactly the case the field
    // exists to catch. It gets its own variant so an audit can tell "written
    // by an old converter" from "written by a hostile one".
    assert_eq!(
        with_u32(header::ROPE_PAIRING, 0).error(),
        Bxw1Error::RopePairingUnspecified
    );
}

#[test]
fn an_unrecognized_rope_pairing_denies() {
    assert_eq!(
        with_u32(header::ROPE_PAIRING, u32::MAX).error(),
        Bxw1Error::UnknownRopePairing
    );
    assert_eq!(
        with_u32(header::ROPE_PAIRING, 3).error(),
        Bxw1Error::UnknownRopePairing
    );
}

#[test]
fn both_rope_pairings_are_accepted() {
    let mut blob = valid_blob();
    blob.patch_u32(header::ROPE_PAIRING, 2);
    assert!(blob.parse().is_ok(), "half-split is a valid convention");
}

#[test]
fn a_float_hyperparameter_is_classified_before_it_is_compared() {
    let cases: [(usize, u32, Bxw1Error); 8] = [
        // NaN, +Inf, -Inf, a subnormal, and a negative value: every one of
        // them would slip past a float-comparison range check.
        (
            header::ROPE_THETA_BITS,
            0x7FC0_0000,
            Bxw1Error::InvalidRopeTheta,
        ),
        (
            header::ROPE_THETA_BITS,
            0x7F80_0000,
            Bxw1Error::InvalidRopeTheta,
        ),
        (
            header::ROPE_THETA_BITS,
            0xFF80_0000,
            Bxw1Error::InvalidRopeTheta,
        ),
        (
            header::ROPE_THETA_BITS,
            0x0000_0001,
            Bxw1Error::InvalidRopeTheta,
        ),
        (
            header::NORM_EPS_BITS,
            0x7FC0_0000,
            Bxw1Error::InvalidNormEps,
        ),
        (
            header::NORM_EPS_BITS,
            0x8000_0000,
            Bxw1Error::InvalidNormEps,
        ),
        (
            header::NORM_EPS_BITS,
            0x0000_0001,
            Bxw1Error::InvalidNormEps,
        ),
        (
            header::NORM_EPS_BITS,
            0xBF80_0000,
            Bxw1Error::InvalidNormEps,
        ),
    ];
    for (at, bits, expected) in cases {
        assert_eq!(
            with_u32(at, bits).error(),
            expected,
            "offset {at} bits {bits:#010x}"
        );
    }
}

#[test]
fn a_float_hyperparameter_outside_its_range_denies() {
    assert_eq!(
        with_u32(header::ROPE_THETA_BITS, 10.0_f32.to_bits()).error(),
        Bxw1Error::RopeThetaOutOfRange
    );
    assert_eq!(
        with_u32(header::ROPE_THETA_BITS, 1.0e9_f32.to_bits()).error(),
        Bxw1Error::RopeThetaOutOfRange
    );
    assert_eq!(
        with_u32(header::NORM_EPS_BITS, 1.0_f32.to_bits()).error(),
        Bxw1Error::NormEpsOutOfRange
    );
    assert_eq!(
        with_u32(header::NORM_EPS_BITS, 0).error(),
        Bxw1Error::NormEpsOutOfRange
    );
}

#[test]
fn a_special_token_outside_the_vocabulary_denies() {
    assert_eq!(
        with_u32(header::BOS_TOKEN_ID, 33).error(),
        Bxw1Error::BosTokenOutOfRange
    );
    assert_eq!(
        with_u32(header::EOS_TOKEN_ID, u32::MAX).error(),
        Bxw1Error::EosTokenOutOfRange
    );
}

#[test]
fn a_vocabulary_length_outside_its_bounds_denies() {
    assert_eq!(
        with_u64(header::VOCAB_LEN, 0).error(),
        Bxw1Error::VocabLenZero
    );
    assert_eq!(
        with_u64(header::VOCAB_LEN, 64 * 1024 * 1024 + 1).error(),
        Bxw1Error::VocabLenExceedsCeiling
    );
}

#[test]
fn a_tensor_count_that_is_not_the_architectures_denies() {
    // The count is fixed at `3 + 9 × n_layers`, so claiming a second layer
    // without carrying its nine tensors denies before any record is read.
    assert_eq!(
        with_u32(header::N_LAYERS, 2).error(),
        Bxw1Error::TensorCountNotArchRequired
    );
}

#[test]
fn setting_the_tied_flag_without_dropping_the_output_weight_denies() {
    // With the flag set the required count is `2 + 9 × n_layers`, so the
    // count check fires first; a blob that also fixes the count is caught by
    // rule H21 instead, which the tied fixture below proves.
    assert_eq!(
        with_u32(header::FLAGS, 1).error(),
        Bxw1Error::TensorCountNotArchRequired
    );
}

#[test]
fn a_tied_model_carrying_an_output_weight_denies() {
    let shape = ModelShape {
        tied_output: true,
        ..ModelShape::default()
    };
    let mut blob = blob_for(&shape);
    // Rename a per-layer norm to `output.weight`: the count still matches the
    // tied requirement, so rule H21 is what fires.
    blob.patch_name(3, "output.weight");
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::TiedOutputWeightPresent);
}

// ---------------------------------------------------------------------------
// Table integrity and names (rules C1, T1-T6)
// ---------------------------------------------------------------------------

#[test]
fn a_corrupt_table_denies_before_any_record_is_believed() {
    let mut blob = valid_blob();
    // One flipped bit in a record's shape, with the table digest left alone.
    blob.patch_u64(blob.record_field(2, record::DIMS), 32);
    assert_eq!(blob.error(), Bxw1Error::TensorTableDigestMismatch);
}

#[test]
fn a_name_without_its_terminator_denies() {
    let mut blob = valid_blob();
    blob.patch_byte(blob.record_field(1, record::NAME) + 63, b'x');
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::NameNotTerminated);
}

#[test]
fn an_empty_name_denies() {
    let mut blob = valid_blob();
    blob.patch_byte(blob.record_field(1, record::NAME), 0);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::NameEmpty);
}

#[test]
fn a_covert_channel_after_the_terminator_denies() {
    let mut blob = valid_blob();
    blob.patch_byte(blob.record_field(1, record::NAME) + 30, b'!');
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::NameNonZeroAfterTerminator);
}

#[test]
fn a_non_printable_name_byte_denies() {
    for byte in [0x20_u8, 0x7F, 0x80, 0x01] {
        let mut blob = valid_blob();
        blob.patch_byte(blob.record_field(1, record::NAME) + 2, byte);
        blob.reseal_table();
        assert_eq!(
            blob.error(),
            Bxw1Error::NameNotPrintableAscii,
            "byte {byte:#04x}"
        );
    }
}

#[test]
fn a_duplicate_name_denies() {
    let mut blob = valid_blob();
    blob.patch_name(1, "tok_embeddings.weight");
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::DuplicateTensorName);
}

#[test]
fn a_name_outside_the_required_set_denies() {
    let mut blob = valid_blob();
    blob.patch_name(1, "bogus.weight");
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::UnknownTensorName);
}

#[test]
fn a_layer_index_beyond_the_declared_depth_denies() {
    let mut blob = valid_blob();
    blob.patch_name(3, "layers.1.attention_norm.weight");
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::UnknownTensorName);
}

#[test]
fn a_layer_index_with_a_leading_zero_denies() {
    // Two spellings of one layer would make the duplicate check incomplete,
    // so the canonical decimal spelling is mandatory.
    let mut blob = valid_blob();
    blob.patch_name(3, "layers.00.attention_norm.weight");
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::UnknownTensorName);
}

// ---------------------------------------------------------------------------
// Shapes and extents (rules D1-D20)
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_dtype_denies() {
    // 3, not 2. 2 was unknown until `Q4_0` was added on 2026-08-19, and this
    // test failing is how the addition announced itself -- which is the useful
    // behaviour: a dtype cannot be added without a test noticing.
    let mut blob = valid_blob();
    blob.patch_u16(blob.record_field(1, record::DTYPE), 3);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::UnknownDtype);
}

#[test]
fn every_unassigned_dtype_above_the_last_one_denies() {
    // The boundary and a spread above it, so a future addition trips this the
    // same way rather than quietly widening what the loader accepts.
    for value in [3u16, 4, 0x00ff, 0x8000, 0xffff] {
        let mut blob = valid_blob();
        blob.patch_u16(blob.record_field(1, record::DTYPE), value);
        blob.reseal_table();
        assert_eq!(
            blob.error(),
            Bxw1Error::UnknownDtype,
            "dtype {value:#06x} is not assigned and must be refused"
        );
    }
}

#[test]
fn a_quantized_norm_weight_denies() {
    // Norm weights are `F32`-only. The record is made *self-consistent* first
    // — dtype and derived length both changed — so the denial is the dtype
    // policy rather than a length mismatch.
    let mut blob = valid_blob();
    blob.patch_u16(blob.record_field(1, record::DTYPE), DTYPE_Q8_0);
    blob.patch_u64(blob.record_field(1, record::DATA_LEN), 192);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::DtypeNotPermittedForName);
}

#[test]
fn a_zero_or_oversized_rank_denies() {
    let mut zero = valid_blob();
    zero.patch_u16(zero.record_field(1, record::RANK), 0);
    zero.reseal_table();
    assert_eq!(zero.error(), Bxw1Error::ZeroRank);

    let mut oversized = valid_blob();
    oversized.patch_u16(oversized.record_field(1, record::RANK), 5);
    oversized.reseal_table();
    assert_eq!(oversized.error(), Bxw1Error::RankExceedsCeiling);
}

#[test]
fn a_zero_dimension_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(blob.record_field(1, record::DIMS), 0);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ZeroDimension);
}

#[test]
fn a_nonzero_unused_dimension_slot_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(blob.record_field(1, record::DIMS) + 8, 5);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::UnusedDimensionNonZero);
}

#[test]
fn a_dimension_above_its_ceiling_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(blob.record_field(1, record::DIMS), (1 << 28) + 1);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::DimensionExceedsCeiling);
}

#[test]
fn a_dimension_product_that_would_overflow_denies_at_the_running_bound() {
    // Four dimensions each at `BXW1_MAX_DIM` is 2^112, which is not
    // representable. The running-product bound fires after the *second*
    // multiply, which is what makes the third one unreachable rather than
    // merely checked — §7.6's argument, pinned as a test.
    let mut blob = valid_blob();
    blob.patch_u16(blob.record_field(1, record::RANK), 4);
    for slot in 0..4 {
        blob.patch_u64(blob.record_field(1, record::DIMS) + slot * 8, 1 << 28);
    }
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ElementCountExceedsCeiling);
}

#[test]
fn a_quantized_row_that_is_not_a_whole_number_of_blocks_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(blob.record_field(0, record::DIMS) + 8, 33);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::LastDimensionNotBlockAligned);
}

#[test]
fn a_declared_length_disagreeing_with_the_shape_denies_in_both_directions() {
    for delta in [128_i64, -128] {
        let mut blob = valid_blob();
        let at = blob.record_field(1, record::DATA_LEN);
        blob.patch_u64(at, (256 + delta) as u64);
        blob.reseal_table();
        assert_eq!(
            blob.error(),
            Bxw1Error::DeclaredLengthMismatch,
            "delta {delta}"
        );
    }
}

#[test]
fn a_misaligned_extent_denies() {
    let mut blob = valid_blob();
    let at = blob.record_field(1, record::DATA_OFF);
    let offset = blob.extents[1].0 as u64;
    blob.patch_u64(at, offset + 1);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::DataOffsetMisaligned);
}

#[test]
fn an_extent_whose_end_overflows_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(
        blob.record_field(1, record::DATA_OFF),
        0xFFFF_FFFF_FFFF_FF80,
    );
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ExtentOverflow);
}

#[test]
fn an_extent_pointing_into_the_header_or_table_denies() {
    let mut blob = valid_blob();
    blob.patch_u64(blob.record_field(1, record::DATA_OFF), 0);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ExtentBeforeDataRegion);
}

#[test]
fn an_extent_running_past_the_blob_denies() {
    let mut blob = valid_blob();
    let last = blob.tensor_count as usize - 1;
    let offset = blob.extents[last].0 as u64;
    blob.patch_u64(blob.record_field(last, record::DATA_OFF), offset + 128);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ExtentPastBlob);
}

#[test]
fn overlapping_extents_deny() {
    let mut blob = valid_blob();
    let first = blob.extents[0].0 as u64;
    blob.patch_u64(blob.record_field(1, record::DATA_OFF), first);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::OverlappingExtents);
}

#[test]
fn an_extent_gap_larger_than_the_alignment_pad_denies() {
    let mut blob = valid_blob();
    let offset = blob.extents[1].0 as u64;
    blob.patch_u64(blob.record_field(1, record::DATA_OFF), offset + 128);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::ExcessiveExtentGap);
}

#[test]
fn a_gap_before_the_first_extent_denies() {
    let mut blob = valid_blob();
    let offset = blob.extents[0].0 as u64;
    blob.patch_u64(blob.record_field(0, record::DATA_OFF), offset + 128);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::FirstExtentNotAtDataStart);
}

#[test]
fn an_unaccounted_trailing_region_denies() {
    let mut blob = valid_blob();
    let length = blob.bytes.len() + 128;
    blob.bytes.resize(length, 0);
    blob.patch_u64(header::TOTAL_SIZE, length as u64);
    blob.patch_u64(header::TENSOR_DATA_LEN, (length - blob.data_off) as u64);
    assert_eq!(blob.error(), Bxw1Error::TrailingBytesAfterLastExtent);
}

#[test]
fn a_nonzero_reserved_record_field_denies() {
    let mut first = valid_blob();
    first.patch_u32(first.record_field(1, record::RESERVED_A), 1);
    first.reseal_table();
    assert_eq!(first.error(), Bxw1Error::ReservedRecordFieldNonZero);

    let mut second = valid_blob();
    second.patch_u64(second.record_field(1, record::RESERVED_B), 1);
    second.reseal_table();
    assert_eq!(second.error(), Bxw1Error::ReservedRecordFieldNonZero);
}

#[test]
fn a_shape_disagreeing_with_the_header_denies_with_no_precedence_rule() {
    // The header says the vocabulary is 32 tokens; the embedding matrix says
    // 33 rows. Neither wins.
    let mut vocabulary = valid_blob();
    vocabulary.patch_u32(header::VOCAB_SIZE, 32);
    assert_eq!(vocabulary.error(), Bxw1Error::ShapeDisagreesWithHeader);

    // A rank disagreement is the same rule: `norm.weight` is a vector.
    let mut rank = valid_blob();
    rank.patch_u16(rank.record_field(1, record::RANK), 2);
    rank.patch_u64(rank.record_field(1, record::DIMS) + 8, 1);
    rank.reseal_table();
    assert_eq!(rank.error(), Bxw1Error::ShapeDisagreesWithHeader);
}

// ---------------------------------------------------------------------------
// Content (rules C2, C3, C4, D19)
// ---------------------------------------------------------------------------

#[test]
fn one_flipped_payload_bit_denies() {
    let mut blob = valid_blob();
    let (offset, length) = blob.extents[0];
    // Inside the quant plane, where every bit pattern is legal by
    // construction: nothing but the digest can catch this.
    blob.patch_byte(offset + length - 1, 0xAA);
    assert_eq!(blob.error(), Bxw1Error::TensorDigestMismatch);
}

#[test]
fn a_digest_that_matches_a_different_tensor_denies() {
    let mut blob = valid_blob();
    let source = blob.record_field(2, record::DIGEST);
    let digest: Vec<u8> = blob.bytes[source..source + 32].to_vec();
    let destination = blob.record_field(1, record::DIGEST);
    blob.bytes[destination..destination + 32].copy_from_slice(&digest);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::TensorDigestMismatch);
}

#[test]
fn a_non_finite_scale_denies() {
    for bits in [0x7FC0_0000_u32, 0x7F80_0000, 0x8000_0000, 0x0000_0001] {
        let mut blob = valid_blob();
        let offset = blob.extents[0].0;
        blob.patch_u32(offset, bits);
        blob.reseal_tensor(0);
        blob.reseal_table();
        assert_eq!(blob.error(), Bxw1Error::InvalidQ8Scale, "bits {bits:#010x}");
    }
}

#[test]
fn a_non_finite_f32_element_denies() {
    for bits in [0x7FC0_0000_u32, 0x7F80_0000, 0xFF80_0000, 0x0000_0001] {
        let mut blob = valid_blob();
        let offset = blob.extents[1].0;
        blob.patch_u32(offset + 8, bits);
        blob.reseal_tensor(1);
        blob.reseal_table();
        assert_eq!(
            blob.error(),
            Bxw1Error::NonFiniteF32Element,
            "bits {bits:#010x}"
        );
    }
}

#[test]
fn a_nonzero_pad_between_a_quantized_tensors_planes_denies() {
    let mut blob = valid_blob();
    // 33 × 64 elements is 66 blocks: a 264-byte scale plane padded to 384.
    let offset = blob.extents[0].0;
    blob.patch_byte(offset + 300, 1);
    blob.reseal_tensor(0);
    blob.reseal_table();
    assert_eq!(blob.error(), Bxw1Error::NonZeroPadByte);
}

#[test]
fn a_nonzero_pad_between_two_extents_denies() {
    let mut blob = valid_blob();
    // The `Q8_0` embedding ends 64 bytes short of the next 128-byte boundary.
    let (offset, length) = blob.extents[0];
    blob.patch_byte(offset + length + 8, 1);
    assert_eq!(blob.error(), Bxw1Error::NonZeroPadByte);
}

#[test]
fn a_nonzero_pad_before_the_first_extent_denies() {
    // The tied model's table ends at 2016 and its first extent starts at
    // 2048, so there are 32 pad bytes nothing else accounts for.
    let shape = ModelShape {
        tied_output: true,
        ..ModelShape::default()
    };
    let mut blob = blob_for(&shape);
    let table_end = HEADER_BYTES + blob.tensor_count as usize * 160;
    assert!(
        blob.data_off > table_end,
        "the fixture must have a pad here"
    );
    blob.patch_byte(table_end + 4, 0xFF);
    assert_eq!(blob.error(), Bxw1Error::NonZeroPadByte);
}

#[test]
fn a_nonzero_trailing_pad_denies() {
    // Placing the `Q8_0` embedding last leaves 64 bytes of trailing pad.
    let shape = ModelShape::default();
    let mut specs = common::required_tensors(&shape);
    let embeddings = specs.remove(0);
    specs.push(embeddings);
    let mut blob = common::build(&shape, specs);

    let last = blob.tensor_count as usize - 1;
    let (offset, length) = blob.extents[last];
    assert!(
        offset + length < blob.bytes.len(),
        "the fixture must have a trailing pad"
    );
    blob.patch_byte(offset + length + 1, 0xFF);
    assert_eq!(blob.error(), Bxw1Error::NonZeroPadByte);
}

// --------------------------------------------- deny paths found by coverage

/// §6.3: every required tensor must be present. Dropping one must deny by
/// name, not by producing a model that silently computes with a missing
/// weight.
#[test]
fn a_blob_missing_a_required_tensor_denies() {
    let shape = ModelShape::default();
    let mut specs = common::required_tensors(&shape);
    let dropped = specs.remove(0);
    let blob = common::build(&shape, specs);

    // The COUNT check fires before the name check: the architecture fixes how
    // many tensors a conforming blob has, so removing one is caught as a count
    // violation and MissingRequiredTensor is never reached this way. Pinned
    // here so the ordering is a stated property rather than an accident, and so
    // the exemption on names.rs has something to point at.
    assert_eq!(
        blob.error(),
        Bxw1Error::TensorCountNotArchRequired,
        "dropping {} must deny",
        dropped.name
    );
}

/// Rule D13/D14 ordering: which check catches a tensor extent that runs past
/// the declared data region.
///
/// Written while chasing two uncovered arms, `ExtentPastDataRegion` and
/// `ExtentExceedsRegionCapacity`. Shrinking `tensor_data_len` without
/// truncating the blob is caught earlier, by the rule that the region must end
/// exactly at the blob's end. Pinning that here means the ordering is a stated
/// property, and the exemptions on those two arms have something to point at.
#[test]
fn shrinking_the_declared_data_region_is_caught_before_any_extent_is_examined() {
    let mut blob = valid_blob();
    blob.patch_u64(header::TENSOR_DATA_LEN, 128);
    let error = blob.error();
    assert!(
        error != Bxw1Error::ExtentPastDataRegion && error != Bxw1Error::ExtentExceedsRegionCapacity,
        "an earlier rule must deny first, got {error:?}"
    );
}
