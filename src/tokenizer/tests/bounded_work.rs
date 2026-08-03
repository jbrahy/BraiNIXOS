//! Bounded work per input byte.
//!
//! The stated bound is: encoding an `N`-byte input performs **at most `N − 1`
//! merge iterations**, because the sequence starts at `N` tokens, every
//! iteration removes exactly one, and the loop stops at one token. Each
//! iteration scans at most `N − 1` recorded ranks and performs at most three
//! binary searches over the merge index, so the total is `≤ (N − 1)²`
//! comparisons and `≤ 3N` lookups, with `N ≤ MAX_ENCODE_INPUT_BYTES`.
//!
//! The fixture below is built to make the iteration count as close to `N − 1`
//! as a vocabulary can drive it: a chain of rules where the highest-priority
//! rule is the one that extends the longest token, so each round grows one
//! token by one byte instead of collapsing the sequence in halves.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use brainix_tokenizer::{Vocabulary, MAX_ENCODE_INPUT_BYTES};
use common::{BuiltVocabulary, VocabularyBuilder};

/// Longest token in the adversarial chain.
const CHAIN_LENGTH: usize = 32;

/// A vocabulary of `a`, `aa`, ..., `a^CHAIN_LENGTH`, whose rules are ranked so
/// that extending the longest run always outranks starting a new one. Against
/// a run of `a`s this is the worst case: the encoder cannot collapse pairs in
/// parallel, it must walk one byte at a time.
fn chain_vocabulary() -> BuiltVocabulary {
    let mut builder = VocabularyBuilder::new();
    for length in 2..=CHAIN_LENGTH {
        builder.add_token(&vec![b'a'; length]);
    }
    for length in (2..=CHAIN_LENGTH).rev() {
        let left = vec![b'a'; length - 1];
        builder.merge_bytes(&left, b"a");
    }
    builder.build()
}

/// Encodes and returns the measured outcome, asserting the stated bound.
fn encode_within_bound(
    vocabulary: &Vocabulary<'_>,
    input: &[u8],
) -> brainix_tokenizer::EncodeOutcome {
    let mut scratch = vec![0u32; input.len().max(1)];
    let mut tokens = vec![0u32; input.len().max(1)];
    let outcome = vocabulary
        .encode_measured(input, &mut scratch, &mut tokens)
        .unwrap();
    let ceiling = input.len().saturating_sub(1);
    assert!(
        outcome.merge_iterations <= ceiling,
        "merge iterations {} exceeded the stated bound of {} for {} input bytes",
        outcome.merge_iterations,
        ceiling,
        input.len()
    );
    assert_eq!(
        outcome.merge_iterations,
        input.len() - outcome.token_count,
        "every iteration must remove exactly one token"
    );
    outcome
}

#[test]
fn the_adversarial_chain_stays_within_the_stated_bound() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    for length in [2usize, 3, 17, 64, 255, 512, 1024, 4096] {
        let input = vec![b'a'; length];
        encode_within_bound(&vocabulary, &input);
    }
}

#[test]
fn the_adversarial_chain_actually_drives_the_iteration_count_up() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = vec![b'a'; 1024];
    let outcome = encode_within_bound(&vocabulary, &input);
    assert!(
        outcome.merge_iterations > input.len() / 2,
        "the fixture is not adversarial: only {} iterations for {} bytes",
        outcome.merge_iterations,
        input.len()
    );
    // Its finished form is runs of the longest token, so the ratio of input
    // bytes to output tokens is close to CHAIN_LENGTH.
    assert!(outcome.token_count <= input.len() / (CHAIN_LENGTH - 1));
}

#[test]
fn the_bound_holds_for_mixed_and_non_utf8_adversarial_inputs() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let mut input = Vec::new();
    for index in 0..2048usize {
        // Runs of `a` separated by bytes with no rule, so the encoder keeps
        // restarting the chain rather than settling into one long token.
        input.push(b'a');
        if index % 7 == 0 {
            input.push((index % 256) as u8);
        }
    }
    encode_within_bound(&vocabulary, &input);
}

#[test]
fn a_maximum_length_input_is_accepted_and_bounded() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let input = vec![b'z'; MAX_ENCODE_INPUT_BYTES];
    let outcome = encode_within_bound(&vocabulary, &input);
    assert_eq!(outcome.merge_iterations, 0, "no rule applies to `z`");
    assert_eq!(outcome.token_count, MAX_ENCODE_INPUT_BYTES);
}

#[test]
fn an_input_of_one_byte_performs_no_merge_iteration() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let outcome = encode_within_bound(&vocabulary, b"a");
    assert_eq!(outcome.merge_iterations, 0);
    assert_eq!(outcome.token_count, 1);
}

#[test]
fn an_empty_input_performs_no_work_and_produces_no_tokens() {
    let built = chain_vocabulary();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
    let outcome = encode_within_bound(&vocabulary, b"");
    assert_eq!(outcome.merge_iterations, 0);
    assert_eq!(outcome.token_count, 0);
}
