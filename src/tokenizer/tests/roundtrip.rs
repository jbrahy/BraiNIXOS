//! Round-trip, determinism, and codec-boundary behaviour.
//!
//! The property under test is the one the crate documentation states as the
//! invalid-UTF-8 rule: the tokenizer is byte-level, so **every** byte sequence
//! round-trips exactly, whether or not it is valid UTF-8.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use brainix_tokenizer::{Vocabulary, VocabularyError};
use common::{sample_vocabulary, VocabularyBuilder};

/// Encodes then decodes and asserts the bytes survived unchanged.
fn assert_round_trip(vocabulary: &Vocabulary<'_>, input: &[u8]) {
    let mut scratch = vec![0u32; input.len().max(1)];
    let mut tokens = vec![0u32; input.len().max(1)];
    let count = vocabulary.encode(input, &mut scratch, &mut tokens).unwrap();
    assert!(
        count <= input.len(),
        "encode produced more tokens than bytes"
    );
    let mut bytes = vec![0u8; input.len()];
    let written = vocabulary.decode(&tokens[..count], &mut bytes).unwrap();
    assert_eq!(&bytes[..written], input, "round trip changed the bytes");
}

#[test]
fn round_trip_holds_for_ascii() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    assert_round_trip(&vocabulary, b"");
    assert_round_trip(&vocabulary, b"a");
    assert_round_trip(&vocabulary, b"abc");
    assert_round_trip(&vocabulary, b"hello world");
    assert_round_trip(&vocabulary, b"ababababcabcabc");
}

#[test]
fn round_trip_holds_for_multibyte_utf8() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    assert_round_trip(&vocabulary, "café".as_bytes());
    assert_round_trip(&vocabulary, "naïve résumé".as_bytes());
    assert_round_trip(&vocabulary, "日本語のテキスト".as_bytes());
    assert_round_trip(&vocabulary, "Ωμέγα".as_bytes());
}

#[test]
fn round_trip_holds_for_emoji() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    assert_round_trip(&vocabulary, "🙂".as_bytes());
    assert_round_trip(&vocabulary, "a🙂b🙂c".as_bytes());
    assert_round_trip(&vocabulary, "👩‍💻🇯🇵".as_bytes());
}

#[test]
fn round_trip_holds_for_arbitrary_non_utf8_bytes() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    // A lone continuation byte, a truncated sequence, an overlong form, a
    // surrogate encoding, and 0xFE/0xFF, which can never appear in UTF-8.
    assert_round_trip(&vocabulary, &[0x80]);
    assert_round_trip(&vocabulary, &[0xc3]);
    assert_round_trip(&vocabulary, &[0xf0, 0x9f]);
    assert_round_trip(&vocabulary, &[0xc0, 0xaf]);
    assert_round_trip(&vocabulary, &[0xed, 0xa0, 0x80]);
    assert_round_trip(&vocabulary, &[0xfe, 0xff, 0x00, 0x01]);
    assert_round_trip(&vocabulary, &[0x00; 32]);
}

#[test]
fn round_trip_holds_for_every_single_byte() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    for byte_value in 0..=255u8 {
        assert_round_trip(&vocabulary, &[byte_value]);
    }
}

#[test]
fn round_trip_holds_for_the_whole_byte_range_in_one_input() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input: Vec<u8> = (0..=255u8).collect();
    assert_round_trip(&vocabulary, &input);
    let reversed: Vec<u8> = (0..=255u8).rev().collect();
    assert_round_trip(&vocabulary, &reversed);
}

#[test]
fn encoding_is_deterministic_across_repeated_calls() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = b"abcabc hello world abcabc\xff\x00\xfe caf\xc3\xa9";
    let mut first = vec![0u32; input.len()];
    let mut second = vec![0u32; input.len()];
    let mut scratch = vec![0u32; input.len()];
    let first_count = vocabulary.encode(input, &mut scratch, &mut first).unwrap();
    for _ in 0..8 {
        let mut noisy_scratch = vec![0xabcd_ef01u32; input.len()];
        let count = vocabulary
            .encode(input, &mut noisy_scratch, &mut second)
            .unwrap();
        assert_eq!(count, first_count, "token count changed between calls");
        assert_eq!(first[..count], second[..count], "token sequence changed");
    }
}

#[test]
fn encoding_is_deterministic_across_independently_parsed_handles() {
    let built = sample_vocabulary();
    let first_handle = Vocabulary::parse(&built.bytes).unwrap();
    let copied = built.bytes.clone();
    let second_handle = Vocabulary::parse(&copied).unwrap();
    let input = b"abcabcabc hello";
    let mut left = vec![0u32; input.len()];
    let mut right = vec![0u32; input.len()];
    let mut scratch = vec![0u32; input.len()];
    let left_count = first_handle.encode(input, &mut scratch, &mut left).unwrap();
    let right_count = second_handle
        .encode(input, &mut scratch, &mut right)
        .unwrap();
    assert_eq!(left_count, right_count);
    assert_eq!(left[..left_count], right[..right_count]);
}

#[test]
fn token_output_slice_too_small_denies_rather_than_truncating() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = b"abcabc";
    let mut scratch = vec![0u32; input.len()];
    let mut tokens = vec![0u32; input.len() - 1];
    let outcome = vocabulary.encode(input, &mut scratch, &mut tokens);
    assert_eq!(outcome, Err(VocabularyError::TokenOutputTooSmall));
    assert!(
        tokens.iter().all(|token| *token == 0),
        "a denied encode wrote into the output slice"
    );
}

#[test]
fn scratch_slice_too_small_denies() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = b"abcabc";
    let mut scratch = vec![0u32; input.len() - 1];
    let mut tokens = vec![0u32; input.len()];
    let outcome = vocabulary.encode(input, &mut scratch, &mut tokens);
    assert_eq!(outcome, Err(VocabularyError::ScratchTooSmall));
}

#[test]
fn byte_output_slice_too_small_denies_rather_than_truncating() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = b"abc";
    let mut scratch = vec![0u32; input.len()];
    let mut tokens = vec![0u32; input.len()];
    let count = vocabulary.encode(input, &mut scratch, &mut tokens).unwrap();
    let mut bytes = vec![0u8; 2];
    let outcome = vocabulary.decode(&tokens[..count], &mut bytes);
    assert_eq!(outcome, Err(VocabularyError::ByteOutputTooSmall));
}

#[test]
fn decoding_an_unknown_token_identifier_denies() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let mut bytes = vec![0u8; 64];
    let count = vocabulary.token_count();
    let outcome = vocabulary.decode(&[0, count], &mut bytes);
    assert_eq!(outcome, Err(VocabularyError::TokenIdOutOfRange));
}

#[test]
fn an_input_above_the_encode_ceiling_denies() {
    let built = sample_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = vec![b'a'; brainix_tokenizer::MAX_ENCODE_INPUT_BYTES + 1];
    let mut scratch = vec![0u32; input.len()];
    let mut tokens = vec![0u32; input.len()];
    let outcome = vocabulary.encode(&input, &mut scratch, &mut tokens);
    assert_eq!(outcome, Err(VocabularyError::PromptTooLong));
}

#[test]
fn a_vocabulary_with_no_merges_encodes_one_token_per_byte() {
    let built = VocabularyBuilder::new().build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = b"anything at all \xff\xfe";
    let mut scratch = vec![0u32; input.len()];
    let mut tokens = vec![0u32; input.len()];
    let count = vocabulary.encode(input, &mut scratch, &mut tokens).unwrap();
    assert_eq!(count, input.len());
    assert_round_trip(&vocabulary, input);
}
