//! The single failure enum for the BXV1 vocabulary decoder and the codec.
//!
//! One variant per failure mode, so a rejected vocabulary can be audited for
//! *why* it was rejected rather than merely *that* it was. Deliberately not
//! `#[non_exhaustive]`: callers inside BraiNIX are meant to match exhaustively,
//! so that a newly added failure mode is a compile error rather than a silent
//! wildcard arm.

/// Every way a BXV1 vocabulary blob, or a call into the codec, can be refused.
///
/// There is no "warning" and no partial success. Any value of this type means
/// the operation denied and produced nothing: no token was written, no byte was
/// written, and no vocabulary handle was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VocabularyError {
    /// The supplied blob was zero bytes long.
    EmptyBlob,

    /// The blob is shorter than the fixed 64-byte header.
    BlobTooSmallForHeader,

    /// The blob is larger than
    /// [`BXV1_MAX_BLOB_BYTES`](crate::BXV1_MAX_BLOB_BYTES), which is the same
    /// ceiling `BXW1_MAX_VOCAB_BLOB_BYTES` states for this artifact.
    BlobExceedsCeiling,

    /// `magic` is not ASCII `"BXV1"`.
    BadMagic,

    /// `version_major` is not 1, or `version_minor` is not 0. Exact match, not
    /// a negotiation and not a compatibility range.
    UnsupportedVersion,

    /// A defined-as-zero field is nonzero: `flags`, or any byte of
    /// `reserved_tail`. A reserved field is not an extension point.
    NonZeroReservedField,

    /// `pretokenizer` is `0`.
    ///
    /// **Zero is not a default and not "unspecified"** — it is the value a
    /// converter that never heard of the field writes, which is exactly the
    /// case the field exists to catch. There is no fallback, no operator
    /// override, and no "try the common one".
    PretokenizerUnspecified,

    /// `pretokenizer` is a nonzero value this build does not implement.
    /// Kept distinct from [`VocabularyError::PretokenizerUnspecified`] so a log
    /// can tell "the converter is old" from "this vocabulary needs a mode we do
    /// not have".
    PretokenizerUnrecognized,

    /// `token_count` is below [`BXV1_MIN_TOKENS`](crate::BXV1_MIN_TOKENS). A
    /// vocabulary that cannot even name all 256 byte values cannot encode
    /// arbitrary input, and byte-level BPE has no other base case.
    TokenCountBelowMinimum,

    /// `token_count` is above [`BXV1_MAX_TOKENS`](crate::BXV1_MAX_TOKENS).
    TokenCountExceedsCeiling,

    /// `merge_count` is above [`BXV1_MAX_MERGES`](crate::BXV1_MAX_MERGES).
    MergeCountExceedsCeiling,

    /// A checked addition, subtraction, multiplication or division on a
    /// blob-supplied or caller-supplied value would have overflowed. Overflow
    /// denies; it never wraps and never saturates.
    ArithmeticOverflow,

    /// A declared section offset in the header does not equal the offset
    /// derived from the counts. Every offset is asserted, never followed.
    SectionOffsetMismatch,

    /// `total_size` does not equal the blob's actual byte length, in either
    /// direction. A `total_size` below the object length leaves trailing bytes
    /// nothing accounts for; above it is a read past the end.
    TotalSizeMismatch,

    /// `token_bytes_length` does not equal `total_size − token_bytes_offset`.
    TokenBytesRegionMismatch,

    /// A read of the token table would run past the end of the blob.
    TruncatedTokenTable,

    /// A read of the token index would run past the end of the blob.
    TruncatedTokenIndex,

    /// A read of the byte-token table would run past the end of the blob.
    TruncatedByteTokenTable,

    /// A read of the merge table would run past the end of the blob.
    TruncatedMergeTable,

    /// A read of the merge index would run past the end of the blob.
    TruncatedMergeIndex,

    /// A token's declared byte range runs past the end of the blob.
    TruncatedTokenBytes,

    /// A token record declares a zero-byte token. A token that spells nothing
    /// would make encoding non-terminating in the general case and has no
    /// meaning in this one.
    TokenLengthZero,

    /// A token record declares more than
    /// [`BXV1_MAX_TOKEN_BYTES`](crate::BXV1_MAX_TOKEN_BYTES) bytes.
    TokenLengthExceedsCeiling,

    /// A token's bytes do not begin exactly where the previous token's bytes
    /// ended. Tokens tile the token-bytes region in ascending identifier order
    /// with no gap and no overlap, so every byte of the blob is accounted for.
    TokenBytesNotContiguous,

    /// A token identifier is at or above `token_count`.
    TokenIdOutOfRange,

    /// A token-index entry is at or above `token_count`.
    TokenIndexOutOfRange,

    /// The token index is not in strictly ascending byte order. It is a
    /// declared sort permutation and is validated, never trusted.
    TokenIndexNotAscending,

    /// Two token records hold identical bytes. Duplicate tokens make the
    /// mapping from bytes to identifiers ambiguous, and two readers that
    /// resolve it differently would disagree about the same vocabulary.
    DuplicateToken,

    /// A byte-token table entry names a token identifier at or above
    /// `token_count`.
    ByteTokenIdOutOfRange,

    /// A byte-token table entry names a token whose bytes are not exactly the
    /// one byte the entry stands for. The table is redundant with the token
    /// bytes on purpose, so the two can be compared.
    ByteTokenNotSingleByte,

    /// A merge record names a token identifier at or above `token_count`, in
    /// its left, right, or result position.
    MergeTokenIdOutOfRange,

    /// A merge record's `rank` field does not equal its index in the merge
    /// table. Rank is stored redundantly so the two can be compared, and rank
    /// order is what makes encoding deterministic.
    MergeRankMismatch,

    /// A merge's result identifier equals its left or right identifier. Such a
    /// rule rewrites a token to itself or drops one side.
    MergeSelfReferential,

    /// A merge's result token's bytes are not the concatenation of its left and
    /// right tokens' bytes. This is the rule that makes a merge mean what BPE
    /// says it means, and — because a result is therefore strictly longer than
    /// either operand — it is also what makes a cyclic merge graph
    /// unconstructible.
    MergeResultBytesMismatch,

    /// A merge-index entry is at or above `merge_count`.
    MergeIndexOutOfRange,

    /// The merge index is not in strictly ascending `(left, right)` order.
    MergeIndexNotAscending,

    /// Two merge records name the same `(left, right)` pair. Which one applies
    /// would then depend on the reader.
    DuplicateMergePair,

    /// The input to encode is longer than
    /// [`MAX_ENCODE_INPUT_BYTES`](crate::MAX_ENCODE_INPUT_BYTES). The bound on
    /// merge work is quadratic in the input length, so the input length is
    /// itself a `const`-bounded quantity rather than a client-chosen one.
    PromptTooLong,

    /// The caller's scratch slice holds fewer than `input.len()` entries.
    ScratchTooSmall,

    /// The caller's token output slice holds fewer than `input.len()` entries.
    /// Nothing is truncated and nothing is written on this path.
    TokenOutputTooSmall,

    /// The caller's byte output slice cannot hold the decoded bytes. Nothing is
    /// truncated; decoding denies.
    ByteOutputTooSmall,

    /// The merge loop ran more iterations than the input length admits.
    /// Unreachable given that every iteration removes exactly one token from a
    /// sequence that started at `input.len()`; retained as a termination
    /// guarantee that is a property of the program rather than of an argument.
    MergeBudgetExhausted,

    /// A pair whose rank was recorded no longer resolves to a merge. Unreachable
    /// for a validated vocabulary; retained for the same reason as
    /// [`VocabularyError::MergeBudgetExhausted`].
    MergeLookupInconsistent,

    /// The pre-tokenizer returned a segment end at or before the position it
    /// was asked about, or past the end of the input.
    ///
    /// Unreachable: every mode consumes at least one byte per call, and
    /// `src/tokenizer/tests/pretokenize.rs` asserts that for every mode over
    /// every byte value. It is checked anyway, because a splitter that failed
    /// to advance would be an unbounded loop on the prompt path, and that is
    /// the one failure this crate exists to make impossible.
    SplitterMadeNoProgress,
}
