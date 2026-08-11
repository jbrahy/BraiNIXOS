//! The structural walks that turn a byte slice into a [`Vocabulary`].
//!
//! Five passes, in a fixed order, each of which must complete before the next
//! begins. The order is not cosmetic: the merge walk compares token bytes, so
//! the token table must already tile the token-bytes region; the byte-token
//! walk compares against token bytes for the same reason.
//!
//! Every pass is a single forward loop bounded by a count that was checked
//! against a `const` in the header decoder, carries at most one `u32` or one
//! borrowed slice of state, and allocates nothing.

use core::cmp::Ordering;

use crate::error::VocabularyError;
use crate::Vocabulary;

/// Runs every structural pass over an already-laid-out vocabulary.
pub(crate) fn validate_all(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    validate_token_table(vocabulary)?;
    validate_token_index(vocabulary)?;
    validate_byte_token_table(vocabulary)?;
    validate_merge_table(vocabulary)?;
    validate_merge_index(vocabulary)
}

/// Walks the token table and requires the tokens to tile the token-bytes region
/// exactly: ascending, contiguous, no gap, no overlap, ending at the end of the
/// blob.
///
/// The tiling is what makes "every byte of the blob is accounted for" a checked
/// property. An unaccounted region inside a digest-covered blob is a smuggling
/// channel that the digest would faithfully cover and never object to.
fn validate_token_table(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    let mut cursor = vocabulary.token_bytes_start();
    for token_id in 0..vocabulary.token_count() {
        cursor = validate_token_record(vocabulary, token_id, cursor)?;
    }
    if cursor != vocabulary.token_bytes_end() {
        return Err(VocabularyError::TokenBytesNotContiguous);
    }
    Ok(())
}

/// Checks one token record against the running tiling cursor and returns the
/// cursor for the next record.
fn validate_token_record(
    vocabulary: &Vocabulary<'_>,
    token_id: u32,
    cursor: usize,
) -> Result<usize, VocabularyError> {
    let record = vocabulary.token_record(token_id)?;
    require_token_length(record.byte_length)?;
    if record.byte_offset as usize != cursor {
        return Err(VocabularyError::TokenBytesNotContiguous);
    }
    let end = cursor
        .checked_add(record.byte_length as usize)
        .ok_or(VocabularyError::ArithmeticOverflow)?;
    if end > vocabulary.token_bytes_end() {
        return Err(VocabularyError::TruncatedTokenBytes);
    }
    Ok(end)
}

/// Applies the two length bounds a token record's length word must satisfy.
fn require_token_length(byte_length: u32) -> Result<(), VocabularyError> {
    if byte_length == 0 {
        return Err(VocabularyError::TokenLengthZero);
    }
    if byte_length > crate::BXV1_MAX_TOKEN_BYTES {
        return Err(VocabularyError::TokenLengthExceedsCeiling);
    }
    Ok(())
}

/// Walks the token index and requires it to be strictly ascending in byte
/// order.
///
/// Strictness is what detects duplicate tokens in a single forward pass with no
/// scratch. It also makes the index a permutation of `0..token_count` without
/// needing a visited set: entries with distinct sort keys are distinct records,
/// and there are exactly `token_count` of them, all in range.
fn validate_token_index(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    let mut previous: Option<&[u8]> = None;
    for position in 0..vocabulary.token_count() {
        let entry = vocabulary.token_index_entry(position)?;
        if entry >= vocabulary.token_count() {
            return Err(VocabularyError::TokenIndexOutOfRange);
        }
        let bytes = vocabulary.token_bytes(entry)?;
        require_ascending_token(previous, bytes)?;
        previous = Some(bytes);
    }
    Ok(())
}

/// Requires `bytes` to sort strictly after `previous`, distinguishing "equal"
/// (a duplicate token) from "out of order".
fn require_ascending_token(previous: Option<&[u8]>, bytes: &[u8]) -> Result<(), VocabularyError> {
    let earlier = match previous {
        Some(value) => value,
        None => return Ok(()),
    };
    match bytes.cmp(earlier) {
        Ordering::Greater => Ok(()),
        Ordering::Equal => Err(VocabularyError::DuplicateToken),
        Ordering::Less => Err(VocabularyError::TokenIndexNotAscending),
    }
}

/// Walks all 256 byte-token entries and compares each against the bytes of the
/// token it names.
///
/// This is what makes the byte-level claim true rather than asserted: after
/// this pass, every byte value has a token that spells exactly that byte, so
/// no input can fail to encode.
fn validate_byte_token_table(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    for byte_value in 0..crate::BXV1_BYTE_VALUE_COUNT {
        let byte = u8::try_from(byte_value).map_err(|_| VocabularyError::ArithmeticOverflow)?;
        validate_byte_token(vocabulary, byte)?;
    }
    Ok(())
}

/// Checks one byte-token entry: in range, and spelling exactly its own byte.
fn validate_byte_token(vocabulary: &Vocabulary<'_>, byte: u8) -> Result<(), VocabularyError> {
    let token_id = vocabulary.byte_token(byte)?;
    if token_id >= vocabulary.token_count() {
        return Err(VocabularyError::ByteTokenIdOutOfRange);
    }
    let bytes = vocabulary.token_bytes(token_id)?;
    if bytes != [byte] {
        return Err(VocabularyError::ByteTokenNotSingleByte);
    }
    Ok(())
}

/// Walks the merge table in table order and applies every per-record rule.
fn validate_merge_table(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    for merge_id in 0..vocabulary.merge_count() {
        validate_merge_record(vocabulary, merge_id)?;
    }
    Ok(())
}

/// Checks one merge record: rank, identifier ranges, self-reference, and the
/// concatenation rule.
fn validate_merge_record(
    vocabulary: &Vocabulary<'_>,
    merge_id: u32,
) -> Result<(), VocabularyError> {
    let record = vocabulary.merge_record(merge_id)?;
    if record.rank != merge_id {
        return Err(VocabularyError::MergeRankMismatch);
    }
    require_merge_ids_in_range(vocabulary, record.left, record.right, record.result)?;
    if record.result == record.left || record.result == record.right {
        return Err(VocabularyError::MergeSelfReferential);
    }
    require_concatenation(vocabulary, record.left, record.right, record.result)
}

/// Requires all three identifiers of a merge record to name existing tokens.
fn require_merge_ids_in_range(
    vocabulary: &Vocabulary<'_>,
    left: u32,
    right: u32,
    result: u32,
) -> Result<(), VocabularyError> {
    let count = vocabulary.token_count();
    if left >= count || right >= count || result >= count {
        return Err(VocabularyError::MergeTokenIdOutOfRange);
    }
    Ok(())
}

/// Requires the result token's bytes to be exactly the left token's bytes
/// followed by the right token's bytes.
///
/// This is the rule that makes a merge mean what BPE says it means, and it is
/// also what makes a cyclic merge graph unconstructible: a result is strictly
/// longer in bytes than either operand, so the "is built from" relation
/// strictly increases a natural number and cannot close a cycle.
fn require_concatenation(
    vocabulary: &Vocabulary<'_>,
    left: u32,
    right: u32,
    result: u32,
) -> Result<(), VocabularyError> {
    let left_bytes = vocabulary.token_bytes(left)?;
    let right_bytes = vocabulary.token_bytes(right)?;
    let result_bytes = vocabulary.token_bytes(result)?;
    let split = left_bytes.len();
    let head = result_bytes.get(..split);
    let tail = result_bytes.get(split..);
    if head != Some(left_bytes) || tail != Some(right_bytes) {
        return Err(VocabularyError::MergeResultBytesMismatch);
    }
    Ok(())
}

/// Walks the merge index and requires it to be strictly ascending in
/// `(left, right)` order.
///
/// Strictness detects a duplicate `(left, right)` pair in the same pass, and it
/// is what makes the binary search in [`crate::codec`] sound: a lookup finds
/// the one rule for a pair, or none.
fn validate_merge_index(vocabulary: &Vocabulary<'_>) -> Result<(), VocabularyError> {
    let mut previous: Option<u64> = None;
    for position in 0..vocabulary.merge_count() {
        let entry = vocabulary.merge_index_entry(position)?;
        if entry >= vocabulary.merge_count() {
            return Err(VocabularyError::MergeIndexOutOfRange);
        }
        let record = vocabulary.merge_record(entry)?;
        let key = crate::codec::merge_key(record.left, record.right);
        require_ascending_key(previous, key)?;
        previous = Some(key);
    }
    Ok(())
}

/// Requires `key` to sort strictly after `previous`, distinguishing a duplicate
/// pair from an out-of-order one.
fn require_ascending_key(previous: Option<u64>, key: u64) -> Result<(), VocabularyError> {
    let earlier = match previous {
        Some(value) => value,
        None => return Ok(()),
    };
    match key.cmp(&earlier) {
        Ordering::Greater => Ok(()),
        Ordering::Equal => Err(VocabularyError::DuplicateMergePair),
        Ordering::Less => Err(VocabularyError::MergeIndexNotAscending),
    }
}
