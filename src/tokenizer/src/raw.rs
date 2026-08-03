//! Bounds-checked primitive reads, the fixed header decoder, and the derived
//! section layout.
//!
//! Everything here works in **blob-relative offsets**. The decoder takes a
//! `&[u8]` and nothing else; obtaining the bytes, checking their length against
//! `vocab_len`, and verifying their SHA-256 against `vocab_digest` are the
//! caller's obligations and belong to the BXW1 loader
//! (`docs/architecture/BXW1-weight-format.md` §5.4).
//!
//! Two properties make the header decoder total from the first byte: it is a
//! fixed 64 bytes with no variable-length field, and the only two values that
//! govern how much is read afterwards — `token_count` and `merge_count` — are
//! bounds-checked against a `const` before any arithmetic uses them.

use crate::error::VocabularyError;
use crate::pretokenize::Pretokenizer;

/// Bytes in a little-endian `u16`.
const U16_LEN: usize = 2;

/// Bytes in a little-endian `u32`.
const U32_LEN: usize = 4;

/// Offset of `magic`.
const MAGIC_OFFSET: usize = 0;

/// Offset of `version_major`.
const VERSION_MAJOR_OFFSET: usize = 4;

/// Offset of `version_minor`.
const VERSION_MINOR_OFFSET: usize = 6;

/// Offset of `flags`.
const FLAGS_OFFSET: usize = 8;

/// Offset of `token_count`.
const TOKEN_COUNT_OFFSET: usize = 12;

/// Offset of `merge_count`.
const MERGE_COUNT_OFFSET: usize = 16;

/// Offset of `byte_token_table_offset`.
const BYTE_TOKEN_TABLE_OFFSET_OFFSET: usize = 20;

/// Offset of `token_table_offset`.
const TOKEN_TABLE_OFFSET_OFFSET: usize = 24;

/// Offset of `token_index_offset`.
const TOKEN_INDEX_OFFSET_OFFSET: usize = 28;

/// Offset of `merge_table_offset`.
const MERGE_TABLE_OFFSET_OFFSET: usize = 32;

/// Offset of `merge_index_offset`.
const MERGE_INDEX_OFFSET_OFFSET: usize = 36;

/// Offset of `token_bytes_offset`.
const TOKEN_BYTES_OFFSET_OFFSET: usize = 40;

/// Offset of `token_bytes_length`.
const TOKEN_BYTES_LENGTH_OFFSET: usize = 44;

/// Offset of `total_size`.
const TOTAL_SIZE_OFFSET: usize = 48;

/// Offset of `pretokenizer`.
const PRETOKENIZER_OFFSET: usize = 52;

/// Offset of the first byte of `reserved_tail`.
const RESERVED_TAIL_OFFSET: usize = 56;

/// Reads a little-endian `u16` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u16_le(blob: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(U16_LEN)?;
    let bytes = blob.get(offset..end)?;
    let array: [u8; U16_LEN] = bytes.try_into().ok()?;
    Some(u16::from_le_bytes(array))
}

/// Reads a little-endian `u32` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u32_le(blob: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(U32_LEN)?;
    let bytes = blob.get(offset..end)?;
    let array: [u8; U32_LEN] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

/// The fixed header, decoded but not yet cross-checked against the layout.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    /// Number of token records.
    pub(crate) token_count: u32,
    /// Number of merge records.
    pub(crate) merge_count: u32,
    /// The pre-tokenizer this vocabulary was trained behind. No default: the
    /// blob states it or the blob is refused.
    pub(crate) pretokenizer: Pretokenizer,
    /// Declared offsets, in the order the sections appear.
    pub(crate) declared: DeclaredOffsets,
}

/// The six section offsets, the token-bytes length, and the total size, exactly
/// as the blob declares them. Every one is compared against a derived value and
/// none is ever followed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DeclaredOffsets {
    /// Declared `byte_token_table_offset`.
    pub(crate) byte_token_table: u32,
    /// Declared `token_table_offset`.
    pub(crate) token_table: u32,
    /// Declared `token_index_offset`.
    pub(crate) token_index: u32,
    /// Declared `merge_table_offset`.
    pub(crate) merge_table: u32,
    /// Declared `merge_index_offset`.
    pub(crate) merge_index: u32,
    /// Declared `token_bytes_offset`.
    pub(crate) token_bytes: u32,
    /// Declared `token_bytes_length`.
    pub(crate) token_bytes_length: u32,
    /// Declared `total_size`.
    pub(crate) total_size: u32,
}

/// The validated section layout, in `usize`, after every declared offset has
/// been compared against the value derived from the counts.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Sections {
    /// Start of the 1024-byte byte-token table.
    pub(crate) byte_token_table: usize,
    /// Start of the token table.
    pub(crate) token_table: usize,
    /// Start of the token index.
    pub(crate) token_index: usize,
    /// Start of the merge table.
    pub(crate) merge_table: usize,
    /// Start of the merge index.
    pub(crate) merge_index: usize,
    /// Start of the token-bytes region.
    pub(crate) token_bytes: usize,
    /// One past the last byte of the token-bytes region, which is also the end
    /// of the blob.
    pub(crate) token_bytes_end: usize,
}

/// Decodes the 64-byte header and applies every rule that needs no other
/// section: identity, version, reserved fields, and the two count ceilings.
pub(crate) fn decode_header(blob: &[u8]) -> Result<Header, VocabularyError> {
    require_header_space(blob)?;
    require_identity(blob)?;
    require_zeroed_fields(blob)?;
    let pretokenizer = Pretokenizer::from_code(read_field(blob, PRETOKENIZER_OFFSET)?)?;
    let token_count = read_field(blob, TOKEN_COUNT_OFFSET)?;
    let merge_count = read_field(blob, MERGE_COUNT_OFFSET)?;
    require_counts_in_range(token_count, merge_count)?;
    Ok(Header {
        token_count,
        merge_count,
        pretokenizer,
        declared: read_declared_offsets(blob)?,
    })
}

/// Refuses a blob that is empty, shorter than the header, or above the ceiling,
/// before any field is read.
fn require_header_space(blob: &[u8]) -> Result<(), VocabularyError> {
    if blob.is_empty() {
        return Err(VocabularyError::EmptyBlob);
    }
    if blob.len() < crate::BXV1_HEADER_BYTES {
        return Err(VocabularyError::BlobTooSmallForHeader);
    }
    if blob.len() > crate::BXV1_MAX_BLOB_BYTES {
        return Err(VocabularyError::BlobExceedsCeiling);
    }
    Ok(())
}

/// Checks `magic` and the two version halves. Exact equality on all three.
fn require_identity(blob: &[u8]) -> Result<(), VocabularyError> {
    let magic_end = MAGIC_OFFSET
        .checked_add(crate::BXV1_MAGIC.len())
        .ok_or(VocabularyError::ArithmeticOverflow)?;
    let magic = blob
        .get(MAGIC_OFFSET..magic_end)
        .ok_or(VocabularyError::BlobTooSmallForHeader)?;
    if magic != crate::BXV1_MAGIC {
        return Err(VocabularyError::BadMagic);
    }
    require_version(blob)
}

/// Checks `version_major` and `version_minor` against the only accepted pair.
fn require_version(blob: &[u8]) -> Result<(), VocabularyError> {
    let major =
        read_u16_le(blob, VERSION_MAJOR_OFFSET).ok_or(VocabularyError::BlobTooSmallForHeader)?;
    let minor =
        read_u16_le(blob, VERSION_MINOR_OFFSET).ok_or(VocabularyError::BlobTooSmallForHeader)?;
    if major != crate::BXV1_VERSION_MAJOR || minor != crate::BXV1_VERSION_MINOR {
        return Err(VocabularyError::UnsupportedVersion);
    }
    Ok(())
}

/// Checks `flags` and every byte of `reserved_tail`. A nonzero value in either
/// is a denial, not a forward-compatible unknown.
fn require_zeroed_fields(blob: &[u8]) -> Result<(), VocabularyError> {
    let flags = read_field(blob, FLAGS_OFFSET)?;
    if flags != 0 {
        return Err(VocabularyError::NonZeroReservedField);
    }
    let tail = blob
        .get(RESERVED_TAIL_OFFSET..crate::BXV1_HEADER_BYTES)
        .ok_or(VocabularyError::BlobTooSmallForHeader)?;
    if tail.iter().any(|byte| *byte != 0) {
        return Err(VocabularyError::NonZeroReservedField);
    }
    Ok(())
}

/// Applies the two count ceilings before either value is used in arithmetic or
/// to bound a read.
fn require_counts_in_range(token_count: u32, merge_count: u32) -> Result<(), VocabularyError> {
    if token_count < crate::BXV1_MIN_TOKENS {
        return Err(VocabularyError::TokenCountBelowMinimum);
    }
    if token_count > crate::BXV1_MAX_TOKENS {
        return Err(VocabularyError::TokenCountExceedsCeiling);
    }
    if merge_count > crate::BXV1_MAX_MERGES {
        return Err(VocabularyError::MergeCountExceedsCeiling);
    }
    Ok(())
}

/// Reads a `u32` header field at a compile-time offset.
fn read_field(blob: &[u8], offset: usize) -> Result<u32, VocabularyError> {
    read_u32_le(blob, offset).ok_or(VocabularyError::BlobTooSmallForHeader)
}

/// Reads the eight declared layout words verbatim. Nothing is checked here;
/// [`derive_sections`] is what compares them.
fn read_declared_offsets(blob: &[u8]) -> Result<DeclaredOffsets, VocabularyError> {
    Ok(DeclaredOffsets {
        byte_token_table: read_field(blob, BYTE_TOKEN_TABLE_OFFSET_OFFSET)?,
        token_table: read_field(blob, TOKEN_TABLE_OFFSET_OFFSET)?,
        token_index: read_field(blob, TOKEN_INDEX_OFFSET_OFFSET)?,
        merge_table: read_field(blob, MERGE_TABLE_OFFSET_OFFSET)?,
        merge_index: read_field(blob, MERGE_INDEX_OFFSET_OFFSET)?,
        token_bytes: read_field(blob, TOKEN_BYTES_OFFSET_OFFSET)?,
        token_bytes_length: read_field(blob, TOKEN_BYTES_LENGTH_OFFSET)?,
        total_size: read_field(blob, TOTAL_SIZE_OFFSET)?,
    })
}

/// Derives every section offset from the counts, compares each against the
/// declared value, and pins the token-bytes region to the end of the blob.
///
/// The blob's own numbers never size, extend, or index anything: they are
/// compared against values computed from `token_count` and `merge_count`, both
/// of which were bounded against a `const` first.
pub(crate) fn derive_sections(blob: &[u8], header: Header) -> Result<Sections, VocabularyError> {
    let sections = build_sections(blob, header)?;
    compare_declared(header.declared, sections)?;
    compare_lengths(blob, header.declared, sections)?;
    Ok(sections)
}

/// Lays the six sections out back to back with checked arithmetic.
fn build_sections(blob: &[u8], header: Header) -> Result<Sections, VocabularyError> {
    let token_table = advance(
        crate::BXV1_HEADER_BYTES,
        crate::BXV1_BYTE_TOKEN_TABLE_BYTES,
        1,
    )?;
    let token_index = advance(
        token_table,
        crate::BXV1_TOKEN_RECORD_BYTES,
        header.token_count,
    )?;
    let merge_table = advance(
        token_index,
        crate::BXV1_INDEX_ENTRY_BYTES,
        header.token_count,
    )?;
    let merge_index = advance(
        merge_table,
        crate::BXV1_MERGE_RECORD_BYTES,
        header.merge_count,
    )?;
    let token_bytes = advance(
        merge_index,
        crate::BXV1_INDEX_ENTRY_BYTES,
        header.merge_count,
    )?;
    Ok(Sections {
        byte_token_table: crate::BXV1_HEADER_BYTES,
        token_table,
        token_index,
        merge_table,
        merge_index,
        token_bytes,
        token_bytes_end: blob.len(),
    })
}

/// `base + stride × count`, checked at every step.
fn advance(base: usize, stride: usize, count: u32) -> Result<usize, VocabularyError> {
    let span = stride
        .checked_mul(count as usize)
        .ok_or(VocabularyError::ArithmeticOverflow)?;
    base.checked_add(span)
        .ok_or(VocabularyError::ArithmeticOverflow)
}

/// Compares each declared section offset against its derived value.
fn compare_declared(declared: DeclaredOffsets, sections: Sections) -> Result<(), VocabularyError> {
    let pairs = [
        (
            declared.byte_token_table as usize,
            sections.byte_token_table,
        ),
        (declared.token_table as usize, sections.token_table),
        (declared.token_index as usize, sections.token_index),
        (declared.merge_table as usize, sections.merge_table),
        (declared.merge_index as usize, sections.merge_index),
        (declared.token_bytes as usize, sections.token_bytes),
    ];
    if pairs.iter().any(|(stated, derived)| stated != derived) {
        return Err(VocabularyError::SectionOffsetMismatch);
    }
    Ok(())
}

/// Checks `total_size` against the object length and `token_bytes_length`
/// against the residual region.
fn compare_lengths(
    blob: &[u8],
    declared: DeclaredOffsets,
    sections: Sections,
) -> Result<(), VocabularyError> {
    if declared.total_size as usize != blob.len() {
        return Err(VocabularyError::TotalSizeMismatch);
    }
    let residual = sections
        .token_bytes_end
        .checked_sub(sections.token_bytes)
        .ok_or(VocabularyError::TokenBytesRegionMismatch)?;
    if declared.token_bytes_length as usize != residual {
        return Err(VocabularyError::TokenBytesRegionMismatch);
    }
    Ok(())
}
