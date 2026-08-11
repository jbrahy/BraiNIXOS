//! Pre-tokenization: exact segmentations, mode distinguishability, and the
//! boundary BPE must not cross.
//!
//! The failure this suite exists to catch is silent. A vocabulary trained
//! behind a splitter, encoded without one — or with the wrong one — yields a
//! valid-looking token sequence the model was never trained on. No rule is
//! violated and nothing errors, so the only thing that catches it is a test
//! that pins each mode's output *and* asserts the modes differ from each
//! other. A test that only checks "some segmentation happened" would pass with
//! every mode wired to the same splitter.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]
#![allow(clippy::cognitive_complexity, clippy::manual_range_contains)]

mod common;

use brainix_tokenizer::{Pretokenizer, Vocabulary, VocabularyError};
use common::VocabularyBuilder;

/// Drives a mode over a whole input, asserting progress at every step.
fn segments(mode: Pretokenizer, input: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut position = 0usize;
    while position < input.len() {
        let end = mode.segment_end(input, position).unwrap();
        assert!(
            end > position,
            "{mode:?} made no progress at {position} of {input:?}"
        );
        assert!(end <= input.len(), "{mode:?} ran past the end of the input");
        out.push(&input[position..end]);
        position = end;
    }
    out
}

/// Segments as printable strings, for readable assertions.
fn split(mode: Pretokenizer, input: &str) -> Vec<&str> {
    segments(mode, input.as_bytes())
        .into_iter()
        .map(|piece| core::str::from_utf8(piece).unwrap())
        .collect()
}

// ---------------------------------------------------------- mode decoding ---

#[test]
fn the_mode_codes_round_trip() {
    for mode in [
        Pretokenizer::None,
        Pretokenizer::Gpt2,
        Pretokenizer::WhitespacePrefixed,
    ] {
        assert_eq!(Pretokenizer::from_code(mode.code()), Ok(mode));
    }
}

#[test]
fn zero_is_not_a_default() {
    assert_eq!(
        Pretokenizer::from_code(0),
        Err(VocabularyError::PretokenizerUnspecified)
    );
}

#[test]
fn an_unrecognized_mode_denies_and_is_distinguishable_from_zero() {
    for code in [4u32, 5, 100, u32::MAX] {
        assert_eq!(
            Pretokenizer::from_code(code),
            Err(VocabularyError::PretokenizerUnrecognized),
            "mode code {code} was not refused"
        );
    }
}

// ------------------------------------------------------- exact splittings ---

#[test]
fn gpt2_splits_words_carrying_their_leading_space() {
    assert_eq!(
        split(Pretokenizer::Gpt2, "Hello world"),
        ["Hello", " world"]
    );
    assert_eq!(
        split(Pretokenizer::Gpt2, "one two three"),
        ["one", " two", " three"]
    );
}

#[test]
fn gpt2_splits_contractions() {
    assert_eq!(split(Pretokenizer::Gpt2, "don't"), ["don", "'t"]);
    assert_eq!(split(Pretokenizer::Gpt2, "it's"), ["it", "'s"]);
    assert_eq!(split(Pretokenizer::Gpt2, "we're"), ["we", "'re"]);
    assert_eq!(split(Pretokenizer::Gpt2, "I've"), ["I", "'ve"]);
    assert_eq!(split(Pretokenizer::Gpt2, "I'm"), ["I", "'m"]);
    assert_eq!(split(Pretokenizer::Gpt2, "we'll"), ["we", "'ll"]);
    assert_eq!(split(Pretokenizer::Gpt2, "he'd"), ["he", "'d"]);
    // Not a contraction: the apostrophe falls back to a punctuation run. The
    // reference pattern is lowercase-only, and that wart is reproduced.
    assert_eq!(split(Pretokenizer::Gpt2, "he'D"), ["he", "'", "D"]);
    assert_eq!(split(Pretokenizer::Gpt2, "''"), ["''"]);
}

#[test]
fn gpt2_separates_letters_digits_and_punctuation() {
    assert_eq!(split(Pretokenizer::Gpt2, "ab12!!"), ["ab", "12", "!!"]);
    assert_eq!(
        split(Pretokenizer::Gpt2, "ab 123 !!"),
        ["ab", " 123", " !!"]
    );
    assert_eq!(split(Pretokenizer::Gpt2, "v2.0"), ["v", "2", ".", "0"]);
}

#[test]
fn gpt2_yields_the_last_byte_of_a_whitespace_run_to_the_next_segment() {
    assert_eq!(split(Pretokenizer::Gpt2, "a  b"), ["a", " ", " b"]);
    assert_eq!(split(Pretokenizer::Gpt2, "a   b"), ["a", "  ", " b"]);
}

#[test]
fn gpt2_keeps_a_whitespace_run_whole_at_the_end_of_the_input() {
    assert_eq!(
        split(Pretokenizer::Gpt2, "trailing   "),
        ["trailing", "   "]
    );
    assert_eq!(split(Pretokenizer::Gpt2, "   "), ["   "]);
}

#[test]
fn gpt2_absorbs_only_a_literal_space_not_any_whitespace() {
    // The reference pattern's optional prefix is a literal space, not `\s?`.
    assert_eq!(split(Pretokenizer::Gpt2, "a\nb"), ["a", "\n", "b"]);
    assert_eq!(split(Pretokenizer::Gpt2, "a\tb"), ["a", "\t", "b"]);
    assert_eq!(split(Pretokenizer::Gpt2, "a \nb"), ["a", " ", "\n", "b"]);
}

#[test]
fn gpt2_treats_every_byte_above_the_ascii_range_as_a_letter() {
    assert_eq!(
        split(Pretokenizer::Gpt2, "café au lait"),
        ["café", " au", " lait"]
    );
    assert_eq!(split(Pretokenizer::Gpt2, "日本語"), ["日本語"]);
    // The documented divergence from the Unicode original: a non-ASCII digit
    // and a non-ASCII punctuation mark are both letters here.
    assert_eq!(split(Pretokenizer::Gpt2, "a\u{ff10}"), ["a\u{ff10}"]);
}

#[test]
fn whitespace_prefixed_gives_every_word_its_whole_leading_run() {
    assert_eq!(
        split(Pretokenizer::WhitespacePrefixed, "Hello world"),
        ["Hello", " world"]
    );
    assert_eq!(
        split(Pretokenizer::WhitespacePrefixed, "a  b"),
        ["a", "  b"]
    );
    assert_eq!(split(Pretokenizer::WhitespacePrefixed, "  ab"), ["  ab"]);
    assert_eq!(
        split(Pretokenizer::WhitespacePrefixed, "don't stop"),
        ["don't", " stop"]
    );
    assert_eq!(split(Pretokenizer::WhitespacePrefixed, "a\nb"), ["a\nb"]);
}

#[test]
fn none_never_splits() {
    for text in ["Hello world", "a  b", "don't stop", "", "a\nb"] {
        let expected: Vec<&str> = if text.is_empty() {
            Vec::new()
        } else {
            vec![text]
        };
        assert_eq!(split(Pretokenizer::None, text), expected);
    }
}

// ------------------------------------------------- the mutation guard -------

#[test]
fn the_three_modes_disagree_on_the_same_input() {
    // This is the test that fails if any mode is silently wired to another's
    // splitter. It compares all three pairwise on one input, so a fall-through
    // in either direction is caught.
    let text = "Hello  world don't";
    let none = split(Pretokenizer::None, text);
    let gpt2 = split(Pretokenizer::Gpt2, text);
    let whitespace = split(Pretokenizer::WhitespacePrefixed, text);

    assert_eq!(none, ["Hello  world don't"]);
    assert_eq!(gpt2, ["Hello", " ", " world", " don", "'t"]);
    assert_eq!(whitespace, ["Hello", "  world", " don't"]);

    assert_ne!(none, gpt2, "None fell through to Gpt2, or the reverse");
    assert_ne!(
        gpt2, whitespace,
        "Gpt2 fell through to WhitespacePrefixed, or the reverse"
    );
    assert_ne!(
        none, whitespace,
        "None fell through to WhitespacePrefixed, or the reverse"
    );
}

#[test]
fn the_three_modes_produce_different_token_sequences() {
    // The same property one level up: it is the *tokens* that reach the model,
    // so the modes must be distinguishable there too, not only in the splitter.
    let mut builder = VocabularyBuilder::new();
    builder.merge_bytes(b"l", b"d");
    builder.merge_bytes(b"o", b" ");
    builder.merge_bytes(b"o ", b"w");
    builder.merge_bytes(b"w", b"o");
    let text = b"hello world";

    let sequences: Vec<Vec<u32>> = [
        brainix_tokenizer::PRETOKENIZER_NONE,
        brainix_tokenizer::PRETOKENIZER_GPT2,
        brainix_tokenizer::PRETOKENIZER_WHITESPACE_PREFIXED,
    ]
    .iter()
    .map(|code| {
        let mut with_mode = VocabularyBuilder::with_pretokenizer(*code);
        with_mode.tokens = builder.tokens.clone();
        with_mode.merges = builder.merges.clone();
        let built = with_mode.build();
        let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
        let mut scratch = vec![0u32; text.len()];
        let mut tokens = vec![0u32; text.len()];
        let count = vocabulary.encode(text, &mut scratch, &mut tokens).unwrap();
        tokens.truncate(count);
        tokens
    })
    .collect();

    assert_ne!(
        sequences[0], sequences[1],
        "None and Gpt2 produced the same tokens"
    );
    assert_ne!(
        sequences[0], sequences[2],
        "None and WhitespacePrefixed produced the same tokens"
    );
}

// --------------------------------------------- boundaries confine merging ---

#[test]
fn bpe_cannot_merge_across_a_gpt2_segment_boundary() {
    // The merge (b, ' ') exists and would fire on "ab cd" if the encoder ran
    // over the whole input. GPT-2 splits ["ab", " cd"], so the pair is never
    // adjacent inside a segment and the rule must not fire.
    let mut builder = VocabularyBuilder::new();
    let spanning = builder.merge_bytes(b"b", b" ");
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    let text = b"ab cd";
    let mut scratch = vec![0u32; text.len()];
    let mut tokens = vec![0u32; text.len()];
    let count = vocabulary.encode(text, &mut scratch, &mut tokens).unwrap();

    assert_eq!(count, text.len(), "a merge fired across the boundary");
    assert!(
        !tokens[..count].contains(&spanning),
        "the boundary-spanning token {spanning} was produced"
    );
    // The same vocabulary with no splitting *does* fire it — which is what
    // makes the assertion above about the boundary rather than about the rule
    // being unreachable.
    let mut unsplit = VocabularyBuilder::with_pretokenizer(brainix_tokenizer::PRETOKENIZER_NONE);
    unsplit.tokens = builder.tokens.clone();
    unsplit.merges = builder.merges.clone();
    let other = unsplit.build();
    let without = Vocabulary::parse(&other.bytes).unwrap();
    let unsplit_count = without.encode(text, &mut scratch, &mut tokens).unwrap();
    assert!(
        tokens[..unsplit_count].contains(&spanning),
        "the control case did not fire the rule, so the test proves nothing"
    );
}

#[test]
fn bpe_cannot_merge_across_a_whitespace_prefixed_segment_boundary() {
    let mut builder =
        VocabularyBuilder::with_pretokenizer(brainix_tokenizer::PRETOKENIZER_WHITESPACE_PREFIXED);
    let spanning = builder.merge_bytes(b"a", b" ");
    let built = builder.build();
    let vocabulary = Vocabulary::parse(&built.bytes).unwrap();

    let text = b"a b";
    let mut scratch = vec![0u32; text.len()];
    let mut tokens = vec![0u32; text.len()];
    let count = vocabulary.encode(text, &mut scratch, &mut tokens).unwrap();
    assert_eq!(count, 3);
    assert!(!tokens[..count].contains(&spanning));
}

#[test]
fn segmentation_partitions_the_input_so_the_round_trip_survives() {
    for code in [
        brainix_tokenizer::PRETOKENIZER_NONE,
        brainix_tokenizer::PRETOKENIZER_GPT2,
        brainix_tokenizer::PRETOKENIZER_WHITESPACE_PREFIXED,
    ] {
        let mut builder = VocabularyBuilder::with_pretokenizer(code);
        builder.merge_bytes(b"l", b"l");
        builder.merge_bytes(b"h", b"e");
        builder.merge_bytes(b" ", b"w");
        let built = builder.build();
        let vocabulary = Vocabulary::parse(&built.bytes).unwrap();
        let inputs: [&[u8]; 5] = [
            b"hello world",
            b"a  b\tc\nd",
            b"",
            &[0x00, 0xff, 0x20, 0x80, 0x20, 0x20, 0x41],
            "caf\u{e9} \u{1f642}".as_bytes(),
        ];
        for input in inputs {
            let mut scratch = vec![0u32; input.len().max(1)];
            let mut tokens = vec![0u32; input.len().max(1)];
            let count = vocabulary.encode(input, &mut scratch, &mut tokens).unwrap();
            let mut bytes = vec![0u8; input.len()];
            let written = vocabulary.decode(&tokens[..count], &mut bytes).unwrap();
            assert_eq!(
                &bytes[..written],
                input,
                "round trip broke under mode {code}"
            );
        }
    }
}

// ------------------------------------------------------------ progress -----

#[test]
fn every_mode_consumes_at_least_one_byte_for_every_byte_value() {
    // The termination property the segment loop rests on, checked exhaustively
    // over every first byte and every second byte.
    for mode in [
        Pretokenizer::None,
        Pretokenizer::Gpt2,
        Pretokenizer::WhitespacePrefixed,
    ] {
        for first in 0..=255u8 {
            assert!(mode.segment_end(&[first], 0).unwrap() >= 1);
            for second in 0..=255u8 {
                let input = [first, second];
                let end = mode.segment_end(&input, 0).unwrap();
                assert!(end >= 1 && end <= 2, "{mode:?} on {input:?} gave {end}");
                let tail = mode.segment_end(&input, 1).unwrap();
                assert!(tail == 2, "{mode:?} on {input:?} at 1 gave {tail}");
            }
        }
    }
}

#[test]
fn every_mode_covers_a_three_byte_input_exactly() {
    for mode in [
        Pretokenizer::None,
        Pretokenizer::Gpt2,
        Pretokenizer::WhitespacePrefixed,
    ] {
        for first in 0..=255u8 {
            for second in [0u8, 0x09, 0x20, b'\'', b'a', b'0', b'!', 0xff] {
                for third in [0u8, 0x0a, 0x20, b's', b'1', b'.', 0x80] {
                    let input = [first, second, third];
                    let covered: usize = segments(mode, &input).iter().map(|s| s.len()).sum();
                    assert_eq!(covered, 3, "{mode:?} lost bytes on {input:?}");
                }
            }
        }
    }
}
