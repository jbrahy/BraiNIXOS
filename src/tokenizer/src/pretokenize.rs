//! Pre-tokenization — the bounded splitters that run before BPE.
//!
//! # Why this exists at all
//!
//! A vocabulary trained behind a pre-tokenizer encodes merges that **assume
//! certain boundaries are never crossed**. Running BPE without the same
//! splitting lets those merges fire across a boundary the trainer forbade, and
//! the result is a token sequence the model was never trained on. Nothing
//! crashes, no rule is violated, no test fails — the model simply produces
//! confident nonsense. This is the same silent-wrongness class as BXW1's
//! `rope_pairing` ambiguity, and it is fixed the same way: **an enumerated
//! field with no default, denying on zero and on anything unrecognized.**
//!
//! Which pre-tokenizer applies is a property of whoever trained the
//! vocabulary, not of this runtime, so it belongs in the blob. Hard-coding any
//! single rule would silently mis-tokenize every model that used a different
//! one.
//!
//! # Why there is no regex engine
//!
//! The reference pre-tokenizers are published as regular expressions. A general
//! regex engine on the prompt path would be a large new hostile-input surface
//! with its own catastrophic-backtracking failure mode — precisely the failure
//! this crate's work bound exists to prevent. Instead the modes are enumerated
//! and each is hand-written as a bounded left-to-right splitter. No engine, no
//! new parser, and each mode is auditable on its own.
//!
//! # The cost of hand-writing them
//!
//! The reference GPT-2 pattern is written over Unicode general categories
//! (`\p{L}`, `\p{N}`). Honouring those exactly would mean shipping Unicode
//! tables, which this crate deliberately does not have. [`Pretokenizer::Gpt2`]
//! therefore approximates them **in bytes**, and §5.5 of
//! `docs/architecture/BPE-vocabulary-format.md` states exactly where the
//! approximation diverges. The divergence is recorded rather than smoothed
//! over, because a divergence nobody wrote down is a divergence nobody can
//! test for.
//!
//! # Work bound
//!
//! Every mode is a single left-to-right pass that examines each input byte a
//! bounded number of times — at most **four** examinations per byte, from the
//! three-byte contraction lookahead in [`Pretokenizer::Gpt2`]. So splitting is
//! `O(1)` per input byte with a stated constant, and it *reduces* the BPE bound
//! rather than adding to it: merging within segments of lengths `L₁..L_k`
//! summing to `N` costs at most `Σ(Lᵢ − 1) ≤ N − 1` iterations and
//! `Σ(Lᵢ − 1)² ≤ (N − 1)²` comparisons.
//!
//! Every mode consumes **at least one byte per call**, which is what makes the
//! segment loop terminate. That is asserted for every mode over every byte
//! value in `tests/pretokenize.rs`, and checked again at the call site.

use crate::error::VocabularyError;

/// Code for [`Pretokenizer::None`].
pub const PRETOKENIZER_NONE: u32 = 1;

/// Code for [`Pretokenizer::Gpt2`].
pub const PRETOKENIZER_GPT2: u32 = 2;

/// Code for [`Pretokenizer::WhitespacePrefixed`].
pub const PRETOKENIZER_WHITESPACE_PREFIXED: u32 = 3;

/// The contraction segments [`Pretokenizer::Gpt2`] splits off, in the
/// alternation order the reference pattern lists them.
const CONTRACTIONS: [&[u8]; 7] = [b"'s", b"'t", b"'re", b"'ve", b"'m", b"'ll", b"'d"];

/// Which pre-tokenizer a vocabulary was trained behind.
///
/// **There is no default and no `Copy` from thin air**: a value is always read
/// from the blob's `pretokenizer` field, and `0` denies (§7.2 rule H15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pretokenizer {
    /// No splitting. The whole input is one segment, so BPE may merge across
    /// any boundary.
    ///
    /// This is for vocabularies genuinely trained without a pre-tokenizer. It
    /// is an explicit, numbered choice rather than the absence of one,
    /// precisely so that "no pre-tokenizer" and "the converter forgot" cannot
    /// be the same bytes.
    None,

    /// The GPT-2 family rule, approximated in bytes.
    ///
    /// Segments are: a contraction suffix; an optional single leading `0x20`
    /// followed by a run of letters, of digits, or of neither; or a run of
    /// whitespace, which yields its final byte to the following segment unless
    /// it ends the input. See
    /// `docs/architecture/BPE-vocabulary-format.md` §5.5 for the rule stated
    /// byte by byte, and for where it diverges from the Unicode original.
    Gpt2,

    /// The SentencePiece-family whitespace convention: a segment begins at each
    /// whitespace run and carries it as a prefix.
    ///
    /// The `U+2581` substitution the reference implementation performs is
    /// deliberately **not** done — it would break the byte-exact round trip.
    /// See §5.6 for what a converter must do instead.
    WhitespacePrefixed,
}

impl Pretokenizer {
    /// Maps the blob's `pretokenizer` field to a mode, denying on `0` and on
    /// any value this build does not implement.
    pub fn from_code(code: u32) -> Result<Self, VocabularyError> {
        match code {
            0 => Err(VocabularyError::PretokenizerUnspecified),
            PRETOKENIZER_NONE => Ok(Self::None),
            PRETOKENIZER_GPT2 => Ok(Self::Gpt2),
            PRETOKENIZER_WHITESPACE_PREFIXED => Ok(Self::WhitespacePrefixed),
            _ => Err(VocabularyError::PretokenizerUnrecognized),
        }
    }

    /// The code this mode is written as in a blob.
    pub fn code(self) -> u32 {
        match self {
            Self::None => PRETOKENIZER_NONE,
            Self::Gpt2 => PRETOKENIZER_GPT2,
            Self::WhitespacePrefixed => PRETOKENIZER_WHITESPACE_PREFIXED,
        }
    }

    /// One past the last byte of the segment beginning at `position`.
    ///
    /// The caller guarantees `position < input.len()`. The return value is
    /// always strictly greater than `position` and never greater than
    /// `input.len()`; the caller checks both anyway.
    pub fn segment_end(self, input: &[u8], position: usize) -> Result<usize, VocabularyError> {
        match self {
            Self::None => Ok(input.len()),
            Self::Gpt2 => gpt2_segment_end(input, position),
            Self::WhitespacePrefixed => whitespace_prefixed_segment_end(input, position),
        }
    }
}

/// The four byte classes [`Pretokenizer::Gpt2`] distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteClass {
    /// ASCII letters and every byte at or above `0x80`.
    Letter,
    /// ASCII digits.
    Digit,
    /// Space and the ASCII control whitespace `0x09..=0x0D`.
    Space,
    /// Everything else: ASCII punctuation and the remaining control bytes.
    Other,
}

/// Classifies one byte.
///
/// Bytes at or above `0x80` are **Letter**. That is the byte-level
/// approximation of `\p{L}`: it is right for the letters of every multi-byte
/// script and wrong for non-ASCII digits and non-ASCII punctuation, which the
/// Unicode original would place in other classes. The divergence is stated in
/// the spec rather than hidden here.
fn classify(byte: u8) -> ByteClass {
    if byte.is_ascii_alphabetic() || byte >= 0x80 {
        return ByteClass::Letter;
    }
    if byte.is_ascii_digit() {
        return ByteClass::Digit;
    }
    if byte == b' ' || (0x09..=0x0d).contains(&byte) {
        return ByteClass::Space;
    }
    ByteClass::Other
}

/// One past the last byte of the maximal run of `class` starting at `start`.
fn run_end(input: &[u8], start: usize, class: ByteClass) -> usize {
    let mut end = start;
    while let Some(byte) = input.get(end) {
        if classify(*byte) != class {
            break;
        }
        end = match end.checked_add(1) {
            Some(next) => next,
            None => break,
        };
    }
    end
}

/// Length of the contraction beginning at `position`, if one does.
fn contraction_length(input: &[u8], position: usize) -> Option<usize> {
    let rest = input.get(position..)?;
    for candidate in CONTRACTIONS {
        if rest.starts_with(candidate) {
            return Some(candidate.len());
        }
    }
    None
}

/// [`Pretokenizer::Gpt2`]'s rule. See the module documentation for the bound.
fn gpt2_segment_end(input: &[u8], position: usize) -> Result<usize, VocabularyError> {
    let first = *input
        .get(position)
        .ok_or(VocabularyError::SplitterMadeNoProgress)?;
    if let Some(length) = contraction_length(input, position) {
        return position
            .checked_add(length)
            .ok_or(VocabularyError::ArithmeticOverflow);
    }
    let class = classify(first);
    if class != ByteClass::Space {
        return Ok(run_end(input, position, class));
    }
    space_segment_end(input, position)
}

/// The whitespace branch, which reproduces the reference pattern's
/// `\s+(?!\S)` / `\s+` alternation without a backtracking engine.
///
/// - A run that ends the input keeps all of its bytes, because there is no
///   following segment to give one to.
/// - A run of two or more bytes followed by anything else yields its **final**
///   byte to the following segment.
/// - A single whitespace byte followed by anything else is absorbed as the
///   prefix of the run that follows it — **but only if it is a literal
///   `0x20`.** The reference pattern's optional prefix is a literal space, not
///   `\s?`, so a tab or a newline forms a segment of its own instead. That
///   asymmetry is the original's, and it is reproduced rather than tidied up.
fn space_segment_end(input: &[u8], position: usize) -> Result<usize, VocabularyError> {
    let end = run_end(input, position, ByteClass::Space);
    if end >= input.len() {
        return Ok(end);
    }
    let length = end
        .checked_sub(position)
        .ok_or(VocabularyError::SplitterMadeNoProgress)?;
    if length >= 2 {
        return end
            .checked_sub(1)
            .ok_or(VocabularyError::SplitterMadeNoProgress);
    }
    absorb_single_space(input, position)
}

/// The one-whitespace-byte case. `position + 1` is known to exist and to hold a
/// non-whitespace byte.
fn absorb_single_space(input: &[u8], position: usize) -> Result<usize, VocabularyError> {
    let next = position
        .checked_add(1)
        .ok_or(VocabularyError::ArithmeticOverflow)?;
    if input.get(position) != Some(&b' ') {
        return Ok(next);
    }
    let following = *input
        .get(next)
        .ok_or(VocabularyError::SplitterMadeNoProgress)?;
    Ok(run_end(input, next, classify(following)))
}

/// [`Pretokenizer::WhitespacePrefixed`]'s rule: a boundary sits immediately
/// before every space that begins a run of spaces.
fn whitespace_prefixed_segment_end(
    input: &[u8],
    position: usize,
) -> Result<usize, VocabularyError> {
    let mut end = position
        .checked_add(1)
        .ok_or(VocabularyError::ArithmeticOverflow)?;
    while let Some(byte) = input.get(end) {
        if *byte == b' ' && !preceded_by_space(input, end) {
            break;
        }
        end = end
            .checked_add(1)
            .ok_or(VocabularyError::ArithmeticOverflow)?;
    }
    Ok(end)
}

/// Whether the byte before `position` is a space. `position` is always at least
/// one here, so the absence of a previous byte means "not a space".
fn preceded_by_space(input: &[u8], position: usize) -> bool {
    let previous = match position.checked_sub(1) {
        Some(index) => index,
        None => return false,
    };
    input.get(previous) == Some(&b' ')
}
