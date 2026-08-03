//! Adversarial vocabulary blobs.
//!
//! Every fixture asserts a **specific** [`VocabularyError`] variant, never
//! `is_err()`. A parser that denies for the wrong reason is a parser whose
//! rules are not the rules it is documented to have, and a rule that never
//! fires is a rule that is not there.
//!
//! The fixtures are organised by the section they attack, in the order
//! `Vocabulary::parse` validates them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use brainix_tokenizer::{Vocabulary, VocabularyError};
use common::*;

/// Parses and returns the error, failing the test if the blob was accepted.
fn refusal(blob: &[u8]) -> VocabularyError {
    match Vocabulary::parse(blob) {
        Ok(_) => panic!("a malformed vocabulary was accepted"),
        Err(reason) => reason,
    }
}

/// A small, valid vocabulary: 256 byte tokens plus three merges.
fn valid() -> BuiltVocabulary {
    let mut builder = VocabularyBuilder::new();
    builder.merge_bytes(b"a", b"b");
    builder.merge_bytes(b"ab", b"c");
    builder.merge_bytes(b"x", b"y");
    builder.build()
}

#[test]
fn the_baseline_fixture_is_actually_valid() {
    let built = valid();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    assert_eq!(vocabulary.token_count(), 259);
    assert_eq!(vocabulary.merge_count(), 3);
}

// ---------------------------------------------------------------- header ---

#[test]
fn a_zero_length_blob_denies() {
    assert_eq!(refusal(&[]), VocabularyError::EmptyBlob);
}

#[test]
fn a_blob_shorter_than_the_header_denies() {
    let built = valid();
    for length in [1usize, 4, 32, 63] {
        assert_eq!(
            refusal(&truncated(&built.bytes, length)),
            VocabularyError::BlobTooSmallForHeader,
            "a {length}-byte blob was not refused as a short header"
        );
    }
}

#[test]
fn a_blob_of_zeros_the_size_of_a_header_denies_on_magic() {
    assert_eq!(refusal(&[0u8; 64]), VocabularyError::BadMagic);
}

#[test]
fn a_wrong_magic_denies() {
    let built = valid();
    let blob = patched_byte(&built.bytes, MAGIC_OFFSET + 3, b'2');
    assert_eq!(refusal(&blob), VocabularyError::BadMagic);
}

#[test]
fn a_wrong_version_denies_in_either_half() {
    let built = valid();
    let major = patched_u16(&built.bytes, VERSION_MAJOR_OFFSET, 2);
    assert_eq!(refusal(&major), VocabularyError::UnsupportedVersion);
    let minor = patched_u16(&built.bytes, VERSION_MINOR_OFFSET, 1);
    assert_eq!(refusal(&minor), VocabularyError::UnsupportedVersion);
}

#[test]
fn a_nonzero_flags_word_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, FLAGS_OFFSET, 1);
    assert_eq!(refusal(&blob), VocabularyError::NonZeroReservedField);
}

#[test]
fn a_nonzero_reserved_tail_byte_denies() {
    let built = valid();
    for offset in RESERVED_TAIL_OFFSET..HEADER_BYTES {
        let blob = patched_byte(&built.bytes, offset, 0xff);
        assert_eq!(
            refusal(&blob),
            VocabularyError::NonZeroReservedField,
            "reserved byte at {offset} was accepted"
        );
    }
}

#[test]
fn a_token_count_below_the_byte_alphabet_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, TOKEN_COUNT_OFFSET, 255);
    assert_eq!(refusal(&blob), VocabularyError::TokenCountBelowMinimum);
}

#[test]
fn a_token_count_that_would_overflow_the_table_arithmetic_denies_before_the_multiply() {
    let built = valid();
    // `token_count × 8` overflows a 32-bit product and, on a 64-bit host, still
    // describes a table 32 GiB long. The ceiling fires first, by design: the
    // count is bounded against a `const` *before* it is used in any arithmetic
    // or to bound any read, so the overflow is never reached.
    for count in [u32::MAX, u32::MAX / 2, 0x2000_0001] {
        let blob = patched_u32(&built.bytes, TOKEN_COUNT_OFFSET, count);
        assert_eq!(
            refusal(&blob),
            VocabularyError::TokenCountExceedsCeiling,
            "token_count {count} was not refused by the ceiling"
        );
    }
}

#[test]
fn a_merge_count_that_would_overflow_the_table_arithmetic_denies_before_the_multiply() {
    let built = valid();
    for count in [u32::MAX, u32::MAX / 2, 0x0010_0001] {
        let blob = patched_u32(&built.bytes, MERGE_COUNT_OFFSET, count);
        assert_eq!(
            refusal(&blob),
            VocabularyError::MergeCountExceedsCeiling,
            "merge_count {count} was not refused by the ceiling"
        );
    }
}

#[test]
fn a_token_count_within_the_ceiling_but_wrong_denies_on_the_layout() {
    let built = valid();
    let blob = patched_u32(&built.bytes, TOKEN_COUNT_OFFSET, 260);
    assert_eq!(refusal(&blob), VocabularyError::SectionOffsetMismatch);
}

#[test]
fn every_declared_section_offset_is_asserted_not_followed() {
    let built = valid();
    let offsets = [
        BYTE_TOKEN_TABLE_OFFSET_OFFSET,
        TOKEN_TABLE_OFFSET_OFFSET,
        TOKEN_INDEX_OFFSET_OFFSET,
        MERGE_TABLE_OFFSET_OFFSET,
        MERGE_INDEX_OFFSET_OFFSET,
        TOKEN_BYTES_OFFSET_OFFSET,
    ];
    for offset in offsets {
        let stated = u32::from_le_bytes(built.bytes[offset..offset + 4].try_into().unwrap());
        let blob = patched_u32(&built.bytes, offset, stated + 4);
        assert_eq!(
            refusal(&blob),
            VocabularyError::SectionOffsetMismatch,
            "section offset at {offset} was followed rather than asserted"
        );
    }
}

#[test]
fn a_total_size_disagreeing_with_the_object_length_denies_in_both_directions() {
    let built = valid();
    let stated = built.bytes.len() as u32;
    let larger = patched_u32(&built.bytes, TOTAL_SIZE_OFFSET, stated + 1);
    assert_eq!(refusal(&larger), VocabularyError::TotalSizeMismatch);
    let smaller = patched_u32(&built.bytes, TOTAL_SIZE_OFFSET, stated - 1);
    assert_eq!(refusal(&smaller), VocabularyError::TotalSizeMismatch);
}

#[test]
fn a_token_bytes_length_disagreeing_with_the_residual_region_denies() {
    let built = valid();
    let stated = u32::from_le_bytes(
        built.bytes[TOKEN_BYTES_LENGTH_OFFSET..TOKEN_BYTES_LENGTH_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    let blob = patched_u32(&built.bytes, TOKEN_BYTES_LENGTH_OFFSET, stated + 1);
    assert_eq!(refusal(&blob), VocabularyError::TokenBytesRegionMismatch);
}

// ------------------------------------------------------------ truncation ---

#[test]
fn truncation_at_every_structural_boundary_denies() {
    let built = valid();
    let cuts = [
        built.byte_token_table,
        built.byte_token_table + 4,
        built.token_table,
        built.token_table + 4,
        built.token_index,
        built.token_index + 4,
        built.merge_table,
        built.merge_table + 4,
        built.merge_index,
        built.merge_index + 4,
        built.token_bytes,
        built.token_bytes + 1,
        built.bytes.len() - 1,
    ];
    for cut in cuts {
        let blob = truncated(&built.bytes, cut);
        assert_eq!(
            refusal(&blob),
            VocabularyError::TotalSizeMismatch,
            "truncation at {cut} was not caught by the total-size rule"
        );
    }
}

#[test]
fn truncation_with_the_total_size_forged_to_match_still_denies() {
    let built = valid();
    let cuts = [
        built.byte_token_table + 4,
        built.token_table + 4,
        built.token_index + 4,
        built.merge_table + 4,
        built.merge_index + 4,
    ];
    for cut in cuts {
        let blob = patched_u32(&truncated(&built.bytes, cut), TOTAL_SIZE_OFFSET, cut as u32);
        assert_eq!(
            refusal(&blob),
            VocabularyError::TokenBytesRegionMismatch,
            "forged truncation at {cut} was accepted past the layout check"
        );
    }
}

#[test]
fn truncation_inside_the_token_bytes_region_with_both_lengths_forged_still_denies() {
    let built = valid();
    let cut = built.bytes.len() - 3;
    let region = (cut - built.token_bytes) as u32;
    let blob = truncated(&built.bytes, cut);
    let blob = patched_u32(&blob, TOTAL_SIZE_OFFSET, cut as u32);
    let blob = patched_u32(&blob, TOKEN_BYTES_LENGTH_OFFSET, region);
    assert_eq!(refusal(&blob), VocabularyError::TruncatedTokenBytes);
}

// ----------------------------------------------------------- token table ---

#[test]
fn a_zero_length_token_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.token_record(7) + 4, 0);
    assert_eq!(refusal(&blob), VocabularyError::TokenLengthZero);
}

#[test]
fn a_token_longer_than_the_ceiling_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.token_record(7) + 4, 257);
    assert_eq!(refusal(&blob), VocabularyError::TokenLengthExceedsCeiling);
    let huge = patched_u32(&built.bytes, built.token_record(7) + 4, u32::MAX);
    assert_eq!(refusal(&huge), VocabularyError::TokenLengthExceedsCeiling);
}

#[test]
fn a_token_offset_that_leaves_a_gap_denies() {
    let built = valid();
    let stated = built.token_bytes as u32;
    let blob = patched_u32(&built.bytes, built.token_record(0), stated + 1);
    assert_eq!(refusal(&blob), VocabularyError::TokenBytesNotContiguous);
}

#[test]
fn a_token_offset_pointing_into_the_header_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.token_record(0), 0);
    assert_eq!(refusal(&blob), VocabularyError::TokenBytesNotContiguous);
}

#[test]
fn a_token_offset_past_the_end_of_the_blob_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.token_record(0), u32::MAX);
    assert_eq!(refusal(&blob), VocabularyError::TokenBytesNotContiguous);
}

#[test]
fn a_token_length_that_overruns_the_region_denies() {
    let built = valid();
    let last = 258u32;
    let blob = patched_u32(&built.bytes, built.token_record(last) + 4, 200);
    assert_eq!(refusal(&blob), VocabularyError::TruncatedTokenBytes);
}

#[test]
fn a_token_length_that_shifts_the_tiling_denies() {
    let built = valid();
    let grown = patched_u32(&built.bytes, built.token_record(4) + 4, 2);
    assert_eq!(refusal(&grown), VocabularyError::TokenBytesNotContiguous);
}

#[test]
fn a_short_final_token_leaves_unaccounted_bytes_and_denies() {
    let mut builder = VocabularyBuilder::new();
    builder.merge_bytes(b"a", b"b");
    let with_long_tail = builder.build();
    let last = 256u32;
    let blob = patched_u32(
        &with_long_tail.bytes,
        with_long_tail.token_record(last) + 4,
        1,
    );
    assert_eq!(refusal(&blob), VocabularyError::TokenBytesNotContiguous);
}

// ----------------------------------------------------------- token index ---

#[test]
fn a_token_index_entry_past_the_token_count_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.token_index_entry(0), 259);
    assert_eq!(refusal(&blob), VocabularyError::TokenIndexOutOfRange);
    let far = patched_u32(&built.bytes, built.token_index_entry(5), u32::MAX);
    assert_eq!(refusal(&far), VocabularyError::TokenIndexOutOfRange);
}

#[test]
fn a_token_index_that_is_not_ascending_denies() {
    let built = valid();
    let first = built.bytes[built.token_index_entry(0)..built.token_index_entry(0) + 4].to_vec();
    let second = built.bytes[built.token_index_entry(1)..built.token_index_entry(1) + 4].to_vec();
    let mut blob = built.bytes.clone();
    blob[built.token_index_entry(0)..built.token_index_entry(0) + 4].copy_from_slice(&second);
    blob[built.token_index_entry(1)..built.token_index_entry(1) + 4].copy_from_slice(&first);
    assert_eq!(refusal(&blob), VocabularyError::TokenIndexNotAscending);
}

#[test]
fn duplicate_tokens_deny() {
    let mut builder = VocabularyBuilder::new();
    builder.merge_bytes(b"a", b"b");
    builder.add_token(b"ab");
    let built = builder.build();
    assert_eq!(refusal(&built.bytes), VocabularyError::DuplicateToken);
}

#[test]
fn duplicate_single_byte_tokens_deny() {
    let mut builder = VocabularyBuilder::new();
    builder.add_token(b"a");
    let built = builder.build();
    assert_eq!(refusal(&built.bytes), VocabularyError::DuplicateToken);
}

// ------------------------------------------------------ byte-token table ---

#[test]
fn a_byte_token_entry_past_the_token_count_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.byte_token_entry(b'a'), 259);
    assert_eq!(refusal(&blob), VocabularyError::ByteTokenIdOutOfRange);
}

#[test]
fn a_byte_token_entry_naming_the_wrong_byte_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.byte_token_entry(b'a'), u32::from(b'b'));
    assert_eq!(refusal(&blob), VocabularyError::ByteTokenNotSingleByte);
}

#[test]
fn a_byte_token_entry_naming_a_multi_byte_token_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.byte_token_entry(b'a'), 256);
    assert_eq!(refusal(&blob), VocabularyError::ByteTokenNotSingleByte);
}

// ----------------------------------------------------------- merge table ---

#[test]
fn a_merge_naming_a_token_that_does_not_exist_denies() {
    let built = valid();
    for word in 0..3usize {
        let blob = patched_u32(&built.bytes, built.merge_record(0) + word * 4, 259);
        assert_eq!(
            refusal(&blob),
            VocabularyError::MergeTokenIdOutOfRange,
            "merge word {word} accepted an out-of-range token identifier"
        );
        let far = patched_u32(&built.bytes, built.merge_record(0) + word * 4, u32::MAX);
        assert_eq!(refusal(&far), VocabularyError::MergeTokenIdOutOfRange);
    }
}

#[test]
fn a_merge_rank_that_is_not_its_table_index_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.merge_record(1) + 12, 0);
    assert_eq!(refusal(&blob), VocabularyError::MergeRankMismatch);
    let high = patched_u32(&built.bytes, built.merge_record(1) + 12, u32::MAX);
    assert_eq!(refusal(&high), VocabularyError::MergeRankMismatch);
}

#[test]
fn a_self_referential_merge_denies() {
    let mut builder = VocabularyBuilder::new();
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, a);
    let built = builder.build();
    assert_eq!(refusal(&built.bytes), VocabularyError::MergeSelfReferential);
}

#[test]
fn a_merge_whose_result_is_its_right_operand_denies() {
    let mut builder = VocabularyBuilder::new();
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, b);
    let built = builder.build();
    assert_eq!(refusal(&built.bytes), VocabularyError::MergeSelfReferential);
}

#[test]
fn a_cyclic_merge_graph_denies() {
    // (a,b) -> c and (c,d) -> a would close a cycle in the "is built from"
    // relation. It cannot be expressed: a result token's bytes must be the
    // concatenation of its operands', so a result is strictly longer than
    // either operand and the relation strictly increases a natural number.
    // The attempt therefore denies at the very first record.
    let mut builder = VocabularyBuilder::new();
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    let c = builder.token_id(b"c").unwrap();
    let d = builder.token_id(b"d").unwrap();
    builder.add_merge(a, b, c);
    builder.add_merge(c, d, a);
    let built = builder.build();
    assert_eq!(
        refusal(&built.bytes),
        VocabularyError::MergeResultBytesMismatch
    );
}

#[test]
fn a_two_step_cycle_through_a_longer_token_denies() {
    let mut builder = VocabularyBuilder::new();
    let ab = builder.add_token(b"ab");
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, ab);
    builder.add_merge(ab, b, a);
    let built = builder.build();
    assert_eq!(
        refusal(&built.bytes),
        VocabularyError::MergeResultBytesMismatch
    );
}

#[test]
fn a_merge_result_that_is_not_the_concatenation_denies() {
    let mut builder = VocabularyBuilder::new();
    let wrong = builder.add_token(b"ac");
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, wrong);
    let built = builder.build();
    assert_eq!(
        refusal(&built.bytes),
        VocabularyError::MergeResultBytesMismatch
    );
}

#[test]
fn a_merge_result_of_the_wrong_length_denies() {
    let mut builder = VocabularyBuilder::new();
    let long = builder.add_token(b"abc");
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, long);
    let built = builder.build();
    assert_eq!(
        refusal(&built.bytes),
        VocabularyError::MergeResultBytesMismatch
    );
}

// ----------------------------------------------------------- merge index ---

#[test]
fn a_merge_index_entry_past_the_merge_count_denies() {
    let built = valid();
    let blob = patched_u32(&built.bytes, built.merge_index_entry(0), 3);
    assert_eq!(refusal(&blob), VocabularyError::MergeIndexOutOfRange);
    let far = patched_u32(&built.bytes, built.merge_index_entry(0), u32::MAX);
    assert_eq!(refusal(&far), VocabularyError::MergeIndexOutOfRange);
}

#[test]
fn a_merge_index_that_is_not_ascending_denies() {
    let built = valid();
    let first = built.bytes[built.merge_index_entry(0)..built.merge_index_entry(0) + 4].to_vec();
    let second = built.bytes[built.merge_index_entry(1)..built.merge_index_entry(1) + 4].to_vec();
    let mut blob = built.bytes.clone();
    blob[built.merge_index_entry(0)..built.merge_index_entry(0) + 4].copy_from_slice(&second);
    blob[built.merge_index_entry(1)..built.merge_index_entry(1) + 4].copy_from_slice(&first);
    assert_eq!(refusal(&blob), VocabularyError::MergeIndexNotAscending);
}

#[test]
fn a_duplicate_merge_pair_denies() {
    let mut builder = VocabularyBuilder::new();
    let ab = builder.add_token(b"ab");
    let a = builder.token_id(b"a").unwrap();
    let b = builder.token_id(b"b").unwrap();
    builder.add_merge(a, b, ab);
    builder.add_merge(a, b, ab);
    let built = builder.build();
    assert_eq!(refusal(&built.bytes), VocabularyError::DuplicateMergePair);
}

// ------------------------------------------------------------- integrity ---

#[test]
fn every_single_byte_flipped_in_the_header_is_either_harmless_or_denied() {
    // Not an integrity claim — that is the loader's SHA-256, not this
    // decoder's job. What this pins is that no header mutation reaches a
    // panic, an unchecked read, or an accepted-but-different vocabulary.
    let built = valid();
    for offset in 0..HEADER_BYTES {
        for bit in 0..8u32 {
            let flipped = built.bytes[offset] ^ (1u8 << bit);
            let blob = patched_byte(&built.bytes, offset, flipped);
            if let Ok(vocabulary) = Vocabulary::parse(&blob) {
                assert_eq!(vocabulary.token_count(), 259);
                assert_eq!(vocabulary.merge_count(), 3);
            }
        }
    }
}
