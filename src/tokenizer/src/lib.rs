//! Byte-level BPE tokenizer and BXV1 vocabulary decoder — P3-T5.
//!
//! Two things live here, and both sit on the hostile path:
//!
//! 1. **The BXV1 vocabulary decoder.** The vocabulary blob arrives from disk,
//!    which the project did not write and cannot audit, and it is parsed before
//!    a single request is served. `docs/security/SECURITY_INVARIANTS.md` §16
//!    lists the "Tokenizer vocab parser" as **Full tier**, so it gets the same
//!    treatment as the ADT decoder and the BXW1 loader: fixed-size header,
//!    explicit counts with build-time ceilings, per-record bounds, and a single
//!    enumerated denial for every malformed shape.
//! 2. **Encode and decode.** A remote client's prompt bytes go through
//!    [`Vocabulary::encode`] verbatim. The prompt is attacker-controlled, so the
//!    work the encoder performs is bounded by a `const` before the first byte is
//!    looked at.
//!
//! The byte layout is specified in `docs/architecture/BPE-vocabulary-format.md`;
//! the binding that ties a vocabulary to a model — SHA-256 digest and exact
//! length — is `docs/architecture/BXW1-weight-format.md` §5.4 and belongs to the
//! weight loader, not here.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, the crate-level forbid attribute below, and **no allocation
//!   of any kind** — no heap, no arena, no growable buffer. Every working set is
//!   a caller-supplied slice or a fixed-size array (`INV-MEM`,
//!   `INV-PARSE-001`).
//! - **Total decoding.** Every malformed blob returns a [`VocabularyError`].
//!   There is no panicking index, no unchecked `Option` access, and no
//!   arithmetic that can wrap: every operation on a blob-supplied value is
//!   checked, and a value that does not fit **denies** — it never saturates and
//!   never wraps.
//! - **Fail closed.** A violation ends the operation. Nothing is skipped,
//!   nothing is clamped, and no length is truncated to what fits. In particular
//!   [`Vocabulary::encode`] returns an error rather than writing as many tokens
//!   as the caller's slice happens to hold.
//! - **Bounds are checked immediately before each read.** [`Vocabulary::parse`]
//!   additionally validates the whole blob up front so no caller ever holds a
//!   handle into an unvalidated vocabulary, but that pass is defence in depth on
//!   top of the per-read checks, never a substitute for them.
//! - **Bounded work.** Encoding an `N`-byte prompt performs **at most `N − 1`
//!   merge iterations**, because each segment's token sequence starts at one
//!   entry per byte and every iteration removes exactly one. `N` is itself
//!   bounded by [`MAX_ENCODE_INPUT_BYTES`], so the total work is bounded by a
//!   compile-time constant and not by anything a client sends. Pre-tokenization
//!   adds `O(1)` per byte and only *reduces* the merge term. The budget is
//!   enforced by a counter, so termination is a property of the program rather
//!   than of an argument.
//! - **Pre-tokenization is an explicit, enumerated property of the
//!   vocabulary.** [`Pretokenizer`] has no default: the blob names its mode or
//!   the blob is refused. Getting this wrong is silent — see that type's
//!   documentation — so it is treated exactly as BXW1 treats `rope_pairing`.
//!
//! # Bytes in, bytes out — the invalid-UTF-8 rule
//!
//! **This tokenizer is byte-level and never inspects UTF-8 structure.**
//! [`Vocabulary::encode`] takes `&[u8]`, [`Vocabulary::decode`] writes `&mut
//! [u8]`, and neither validates, rejects, replaces, or normalizes anything.
//! Invalid UTF-8 is not an error: every one of the 256 byte values is
//! guaranteed to have a token, because the byte-token table is validated at
//! parse time against the token bytes themselves, so **any** byte sequence
//! encodes and decodes back to itself exactly.
//!
//! The alternative — validating UTF-8 on the way in — was rejected for two
//! reasons. It would make the round trip lossy in exactly the case an attacker
//! chooses (a replacement character means the model sees bytes the client did
//! not send), and it would put a second hostile-input parser on the prompt path
//! to do work the model does not need. A tokenizer that cannot represent a byte
//! is a tokenizer with a hole in it.
//!
//! # Example
//!
//! ```no_run
//! use brainix_tokenizer::{Vocabulary, VocabularyError};
//!
//! fn encode_prompt(blob: &[u8], prompt: &[u8]) -> Result<usize, VocabularyError> {
//!     let vocabulary = Vocabulary::parse(blob)?;
//!     let mut scratch = [0u32; 64];
//!     let mut tokens = [0u32; 64];
//!     vocabulary.encode(prompt, &mut scratch, &mut tokens)
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod codec;
mod error;
mod pretokenize;
mod raw;
mod validate;

pub use crate::codec::EncodeOutcome;
pub use crate::error::VocabularyError;
pub use crate::pretokenize::{
    Pretokenizer, PRETOKENIZER_GPT2, PRETOKENIZER_NONE, PRETOKENIZER_WHITESPACE_PREFIXED,
};

use crate::raw::{read_u32_le, Sections};

/// The four-byte format tag: ASCII `"BXV1"`.
pub const BXV1_MAGIC: [u8; 4] = *b"BXV1";

/// The only accepted major version. Exact match, not a range.
pub const BXV1_VERSION_MAJOR: u16 = 1;

/// The only accepted minor version. Exact match, not a range.
pub const BXV1_VERSION_MINOR: u16 = 0;

/// Bytes in the fixed header. No variable-length field appears in it.
pub const BXV1_HEADER_BYTES: usize = 64;

/// Bytes in the byte-token table: 256 entries of four bytes.
pub const BXV1_BYTE_TOKEN_TABLE_BYTES: usize = 1024;

/// Number of distinct byte values a byte-level vocabulary must cover.
pub const BXV1_BYTE_VALUE_COUNT: usize = 256;

/// Bytes in one token record: a `u32` offset and a `u32` length.
pub const BXV1_TOKEN_RECORD_BYTES: usize = 8;

/// Bytes in one merge record: left, right, result, and rank.
pub const BXV1_MERGE_RECORD_BYTES: usize = 16;

/// Bytes in one entry of either sort index: a `u32` record number.
pub const BXV1_INDEX_ENTRY_BYTES: usize = 4;

/// Smallest accepted `token_count`. A vocabulary that cannot name all 256 byte
/// values cannot encode arbitrary input, and byte-level BPE has no other base
/// case.
pub const BXV1_MIN_TOKENS: u32 = 256;

/// Hard ceiling on `token_count`, matching `BXW1_MAX_VOCAB`.
pub const BXV1_MAX_TOKENS: u32 = 1 << 20;

/// Hard ceiling on `merge_count`. A trained byte-level vocabulary has roughly
/// `token_count − 256` merges, so this is the same order as the token ceiling.
pub const BXV1_MAX_MERGES: u32 = 1 << 20;

/// Hard ceiling on the byte length of a single token.
///
/// It bounds the byte output a single token identifier can demand from
/// [`Vocabulary::decode`], and it is the reason a decode buffer can be sized
/// from a `const` rather than from the blob.
pub const BXV1_MAX_TOKEN_BYTES: u32 = 256;

/// Hard ceiling on the whole blob: 64 MiB.
///
/// The same value `BXW1_MAX_VOCAB_BLOB_BYTES` states, deliberately: the loader
/// checks the length before handing the bytes over, and this decoder checks it
/// again without assuming the loader ran.
pub const BXV1_MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Hard ceiling on the byte length of one call to [`Vocabulary::encode`].
///
/// Equal to BSP v2 §8's `MAX_PROMPT_BYTES`, which is the size of the fixed
/// per-session prompt buffer a prompt is reassembled into. Encoding is
/// quadratic in this quantity (see the crate documentation), so it is bounded
/// by a `const` rather than by whatever the client sent.
pub const MAX_ENCODE_INPUT_BYTES: usize = 16384;

/// Rank sentinel meaning "no merge rule applies to this position".
///
/// `merge_count ≤ BXV1_MAX_MERGES`, so no real rank can reach `u32::MAX` and
/// the sentinel can never be selected as a minimum.
pub(crate) const NO_MERGE_RANK: u32 = u32::MAX;

/// One token record: where its bytes are and how many there are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenRecord {
    /// Blob-relative offset of the token's bytes.
    pub byte_offset: u32,
    /// Number of bytes the token spells. Always at least one.
    pub byte_length: u32,
}

/// One merge rule: two token identifiers, the identifier they produce, and the
/// rank that decides which rule applies first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MergeRecord {
    /// Left operand token identifier.
    pub left: u32,
    /// Right operand token identifier.
    pub right: u32,
    /// Token identifier the pair collapses to.
    pub result: u32,
    /// Priority. **Lower binds first.** Equal to the record's table index.
    pub rank: u32,
}

/// A parsed and fully validated BXV1 vocabulary.
///
/// Construction is the validation: holding one of these means every rule in
/// `docs/architecture/BPE-vocabulary-format.md` §7 passed over the whole blob.
#[derive(Debug, Clone, Copy)]
pub struct Vocabulary<'a> {
    blob: &'a [u8],
    token_count: u32,
    merge_count: u32,
    pretokenizer: Pretokenizer,
    sections: Sections,
}

impl<'a> Vocabulary<'a> {
    /// Parses and fully validates a vocabulary from a byte slice.
    ///
    /// The pass reads the fixed header, derives every section offset from the
    /// two counts and compares it against the declared one, then walks the
    /// token table, the token index, the byte-token table, the merge table, and
    /// the merge index in that order. Nothing is produced unless all of it
    /// passes.
    ///
    /// The caller is expected to have already checked the blob's length against
    /// `vocab_len` and its SHA-256 against `vocab_digest` (BXW1 §5.4). This
    /// decoder does not assume that happened and does not verify it.
    pub fn parse(blob: &'a [u8]) -> Result<Self, VocabularyError> {
        let header = crate::raw::decode_header(blob)?;
        let sections = crate::raw::derive_sections(blob, header)?;
        let vocabulary = Self {
            blob,
            token_count: header.token_count,
            merge_count: header.merge_count,
            pretokenizer: header.pretokenizer,
            sections,
        };
        crate::validate::validate_all(&vocabulary)?;
        Ok(vocabulary)
    }

    /// Number of tokens. The BXW1 loader compares this against `vocab_size`
    /// (BXW1 §7.5 rule C7); the disagreement is a denial with no precedence
    /// rule.
    pub fn token_count(&self) -> u32 {
        self.token_count
    }

    /// Number of merge rules.
    pub fn merge_count(&self) -> u32 {
        self.merge_count
    }

    /// The pre-tokenizer this vocabulary was trained behind.
    ///
    /// Read from the blob, never defaulted. Encoding runs this splitter first
    /// and applies BPE **within each segment only** — see
    /// [`Pretokenizer`] for why getting this wrong is silent.
    pub fn pretokenizer(&self) -> Pretokenizer {
        self.pretokenizer
    }

    /// The bytes a token spells.
    pub fn token_bytes(&self, token_id: u32) -> Result<&'a [u8], VocabularyError> {
        let record = self.token_record(token_id)?;
        let start = record.byte_offset as usize;
        let end = start
            .checked_add(record.byte_length as usize)
            .ok_or(VocabularyError::ArithmeticOverflow)?;
        self.blob
            .get(start..end)
            .ok_or(VocabularyError::TruncatedTokenBytes)
    }

    /// The token record for `token_id`.
    pub fn token_record(&self, token_id: u32) -> Result<TokenRecord, VocabularyError> {
        if token_id >= self.token_count {
            return Err(VocabularyError::TokenIdOutOfRange);
        }
        let base = record_base(
            // `record_base` computes `stride x index` where `stride` is a
            // crate constant of at most 16 and `index` is a u32, so the product
            // is under 2^36 and the section base it is added to is a byte
            // offset into a blob that exists. The bounds check above does not
            // supply this and never did.
            // COVERAGE-EXEMPT: no index the header can express overflows a
            // 64-bit usize here. The check earns its place on a 32-bit target.
            self.sections.token_table,
            BXV1_TOKEN_RECORD_BYTES,
            token_id,
            VocabularyError::TruncatedTokenTable,
        )?;
        read_token_record(self.blob, base)
    }

    /// The merge record at table index `merge_id`.
    pub fn merge_record(&self, merge_id: u32) -> Result<MergeRecord, VocabularyError> {
        if merge_id >= self.merge_count {
            return Err(VocabularyError::MergeIndexOutOfRange);
        }
        let base = record_base(
            // `record_base` computes `stride x index` where `stride` is a
            // crate constant of at most 16 and `index` is a u32, so the product
            // is under 2^36 and the section base it is added to is a byte
            // offset into a blob that exists. The bounds check above does not
            // supply this and never did.
            // COVERAGE-EXEMPT: no index the header can express overflows a
            // 64-bit usize here. The check earns its place on a 32-bit target.
            self.sections.merge_table,
            BXV1_MERGE_RECORD_BYTES,
            merge_id,
            VocabularyError::TruncatedMergeTable,
        )?;
        read_merge_record(self.blob, base)
    }

    /// The token identifier that spells the single byte `byte`.
    ///
    /// Validated at parse time against that token's actual bytes, so this is a
    /// table lookup rather than a claim.
    pub fn byte_token(&self, byte: u8) -> Result<u32, VocabularyError> {
        let base = record_base(
            // `record_base` computes `stride x index` where `stride` is a
            // crate constant of at most 16 and `index` is a u32, so the product
            // is under 2^36 and the section base it is added to is a byte
            // offset into a blob that exists. The bounds check above does not
            // supply this and never did.
            // COVERAGE-EXEMPT: no index the header can express overflows a
            // 64-bit usize here. The check earns its place on a 32-bit target.
            self.sections.byte_token_table,
            BXV1_INDEX_ENTRY_BYTES,
            byte as u32,
            VocabularyError::TruncatedByteTokenTable,
        )?;
        read_u32_le(self.blob, base).ok_or(VocabularyError::TruncatedByteTokenTable)
    }

    /// The `position`-th entry of the token sort index.
    pub(crate) fn token_index_entry(&self, position: u32) -> Result<u32, VocabularyError> {
        let base = record_base(
            // `record_base` computes `stride x index` where `stride` is a
            // crate constant of at most 16 and `index` is a u32, so the product
            // is under 2^36 and the section base it is added to is a byte
            // offset into a blob that exists. The bounds check above does not
            // supply this and never did.
            // COVERAGE-EXEMPT: no index the header can express overflows a
            // 64-bit usize here. The check earns its place on a 32-bit target.
            self.sections.token_index,
            BXV1_INDEX_ENTRY_BYTES,
            position,
            VocabularyError::TruncatedTokenIndex,
        )?;
        read_u32_le(self.blob, base).ok_or(VocabularyError::TruncatedTokenIndex)
    }

    /// The `position`-th entry of the merge sort index.
    pub(crate) fn merge_index_entry(&self, position: u32) -> Result<u32, VocabularyError> {
        let base = record_base(
            // `record_base` computes `stride x index` where `stride` is a
            // crate constant of at most 16 and `index` is a u32, so the product
            // is under 2^36 and the section base it is added to is a byte
            // offset into a blob that exists. The bounds check above does not
            // supply this and never did.
            // COVERAGE-EXEMPT: no index the header can express overflows a
            // 64-bit usize here. The check earns its place on a 32-bit target.
            self.sections.merge_index,
            BXV1_INDEX_ENTRY_BYTES,
            position,
            VocabularyError::TruncatedMergeIndex,
        )?;
        read_u32_le(self.blob, base).ok_or(VocabularyError::TruncatedMergeIndex)
    }

    /// Start of the token-bytes region.
    pub(crate) fn token_bytes_start(&self) -> usize {
        self.sections.token_bytes
    }

    /// End of the token-bytes region, which is also the end of the blob.
    pub(crate) fn token_bytes_end(&self) -> usize {
        self.sections.token_bytes_end
    }
}

/// `section + stride × index`, checked, with a caller-chosen failure reason.
fn record_base(
    section: usize,
    stride: usize,
    index: u32,
    reason: VocabularyError,
) -> Result<usize, VocabularyError> {
    let span = stride.checked_mul(index as usize).ok_or(reason)?;
    section.checked_add(span).ok_or(reason)
}

/// Reads the two words of a token record.
fn read_token_record(blob: &[u8], base: usize) -> Result<TokenRecord, VocabularyError> {
    let byte_offset = read_word(blob, base, 0, VocabularyError::TruncatedTokenTable)?;
    let byte_length = read_word(blob, base, 1, VocabularyError::TruncatedTokenTable)?;
    Ok(TokenRecord {
        byte_offset,
        byte_length,
    })
}

/// Reads the four words of a merge record.
fn read_merge_record(blob: &[u8], base: usize) -> Result<MergeRecord, VocabularyError> {
    Ok(MergeRecord {
        left: read_word(blob, base, 0, VocabularyError::TruncatedMergeTable)?,
        right: read_word(blob, base, 1, VocabularyError::TruncatedMergeTable)?,
        result: read_word(blob, base, 2, VocabularyError::TruncatedMergeTable)?,
        rank: read_word(blob, base, 3, VocabularyError::TruncatedMergeTable)?,
    })
}

/// Reads the `word`-th little-endian `u32` of a record starting at `base`.
fn read_word(
    blob: &[u8],
    base: usize,
    word: usize,
    reason: VocabularyError,
) -> Result<u32, VocabularyError> {
    let offset = record_base(base, BXV1_INDEX_ENTRY_BYTES, word as u32, reason)?;
    read_u32_le(blob, offset).ok_or(reason)
}
