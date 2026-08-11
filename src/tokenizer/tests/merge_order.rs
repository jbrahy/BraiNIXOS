//! Merge-order correctness — the place BPE implementations are usually wrong.
//!
//! A greedy left-to-right encoder walks the sequence and collapses the first
//! pair it finds a rule for. A correct BPE encoder collapses the pair whose
//! rule has the **lowest rank**, wherever in the sequence that pair is. The two
//! agree on most inputs, which is exactly what makes the bug survive: the wrong
//! implementation returns a plausible token sequence that the model was never
//! trained on, and nothing crashes.
//!
//! Each test below builds a vocabulary where the two strategies provably
//! disagree, runs a reference greedy encoder alongside the real one, asserts
//! that they differ, and pins the rank-priority answer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

mod common;

use brainix_tokenizer::Vocabulary;
use common::VocabularyBuilder;

/// A deliberately wrong reference: scan left to right, collapse the first pair
/// that has any rule at all, repeat. This is the implementation the real one
/// must not be.
fn encode_greedy_left_to_right(vocabulary: &Vocabulary<'_>, input: &[u8]) -> Vec<u32> {
    let mut tokens: Vec<u32> = input
        .iter()
        .map(|byte| vocabulary.byte_token(*byte).unwrap())
        .collect();
    loop {
        let mut merged = false;
        for position in 0..tokens.len().saturating_sub(1) {
            let found = vocabulary
                .find_merge(tokens[position], tokens[position + 1])
                .unwrap();
            if let Some(record) = found {
                tokens[position] = record.result;
                tokens.remove(position + 1);
                merged = true;
                break;
            }
        }
        if !merged {
            return tokens;
        }
    }
}

/// Runs the real encoder and returns the token sequence.
fn encode(vocabulary: &Vocabulary<'_>, input: &[u8]) -> Vec<u32> {
    let mut scratch = vec![0u32; input.len()];
    let mut tokens = vec![0u32; input.len()];
    let count = vocabulary.encode(input, &mut scratch, &mut tokens).unwrap();
    tokens.truncate(count);
    tokens
}

#[test]
fn a_lower_ranked_rule_further_right_binds_before_a_higher_ranked_rule_on_the_left() {
    let mut builder = VocabularyBuilder::new();
    // Rank 0 — highest priority — is the rule for the *rightmost* pair.
    let bc = builder.merge_bytes(b"b", b"c");
    let ab = builder.merge_bytes(b"a", b"b");
    let a = builder.token_id(b"a").unwrap();
    let c = builder.token_id(b"c").unwrap();
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    let greedy = encode_greedy_left_to_right(&vocabulary, b"abc");
    let actual = encode(&vocabulary, b"abc");

    assert_eq!(greedy, vec![ab, c], "the reference greedy encoder changed");
    assert_ne!(actual, greedy, "the two strategies must disagree here");
    assert_eq!(actual, vec![a, bc], "rank priority was not followed");
}

#[test]
fn rank_priority_composes_across_three_rules() {
    let mut builder = VocabularyBuilder::new();
    // Ranks 0, 1, 2. Greedy would take the rank-2 rule first because it is the
    // leftmost applicable one.
    let cd = builder.merge_bytes(b"c", b"d");
    let bcd = builder.merge_bytes(b"b", b"cd");
    let ab = builder.merge_bytes(b"a", b"b");
    let a = builder.token_id(b"a").unwrap();
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    let greedy = encode_greedy_left_to_right(&vocabulary, b"abcd");
    let actual = encode(&vocabulary, b"abcd");

    assert_eq!(greedy, vec![ab, cd], "the reference greedy encoder changed");
    assert_ne!(actual, greedy, "the two strategies must disagree here");
    assert_eq!(actual, vec![a, bcd], "rank priority was not followed");
}

#[test]
fn the_leftmost_occurrence_wins_when_one_rule_matches_twice() {
    let mut builder = VocabularyBuilder::new();
    let double = builder.merge_bytes(b"a", b"a");
    let a = builder.token_id(b"a").unwrap();
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    assert_eq!(encode(&vocabulary, b"aaa"), vec![double, a]);
    assert_eq!(encode(&vocabulary, b"aaaa"), vec![double, double]);
}

#[test]
fn a_rule_reachable_only_after_another_fires_still_fires() {
    let mut builder = VocabularyBuilder::new();
    // "ab" cannot exist until rank 1 has run, and the rule that consumes it is
    // rank 0 — so the encoder must re-examine the sequence after every merge
    // rather than making one pass in rank order.
    let abc = {
        builder.add_token(b"ab");
        builder.merge_bytes(b"ab", b"c")
    };
    builder.merge_bytes(b"a", b"b");
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    assert_eq!(encode(&vocabulary, b"abc"), vec![abc]);
}

#[test]
fn rank_priority_is_global_not_windowed() {
    let mut builder = VocabularyBuilder::new();
    // The rank-0 rule matches only at the very end of a long input. An encoder
    // that scanned a window, or that stopped at the first rule it could apply,
    // would take the rank-1 rule to its left instead.
    let yz = builder.merge_bytes(b"y", b"z");
    let xy = builder.merge_bytes(b"x", b"y");
    let x = builder.token_id(b"x").unwrap();
    let z = builder.token_id(b"z").unwrap();
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    let mut input = vec![b'.'; 512];
    input.extend_from_slice(b"xyz");
    let actual = encode(&vocabulary, &input);
    let tail = &actual[actual.len() - 2..];
    assert_eq!(
        tail,
        [x, yz],
        "the rank-0 rule at the tail did not bind first"
    );
    assert_ne!(tail, [xy, z]);
    assert_eq!(
        actual.len(),
        514,
        "the filler bytes must stay one token each"
    );
}
