//! Shared fixtures.
//!
//! A BXV1 blob builder that emits a **structurally well-formed** blob from a
//! token list and a merge list, computing both sort indices itself. It
//! deliberately does *not* validate what it is given: the adversarial suite
//! works by handing it a malformed vocabulary, or by patching a field of a
//! valid blob afterwards, and asserting which rule fires.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::cognitive_complexity
)]

use brainix_tokenizer::PRETOKENIZER_GPT2;

/// Offset of `magic`.
pub const MAGIC_OFFSET: usize = 0;
/// Offset of `version_major`.
pub const VERSION_MAJOR_OFFSET: usize = 4;
/// Offset of `version_minor`.
pub const VERSION_MINOR_OFFSET: usize = 6;
/// Offset of `flags`.
pub const FLAGS_OFFSET: usize = 8;
/// Offset of `token_count`.
pub const TOKEN_COUNT_OFFSET: usize = 12;
/// Offset of `merge_count`.
pub const MERGE_COUNT_OFFSET: usize = 16;
/// Offset of `byte_token_table_offset`.
pub const BYTE_TOKEN_TABLE_OFFSET_OFFSET: usize = 20;
/// Offset of `token_table_offset`.
pub const TOKEN_TABLE_OFFSET_OFFSET: usize = 24;
/// Offset of `token_index_offset`.
pub const TOKEN_INDEX_OFFSET_OFFSET: usize = 28;
/// Offset of `merge_table_offset`.
pub const MERGE_TABLE_OFFSET_OFFSET: usize = 32;
/// Offset of `merge_index_offset`.
pub const MERGE_INDEX_OFFSET_OFFSET: usize = 36;
/// Offset of `token_bytes_offset`.
pub const TOKEN_BYTES_OFFSET_OFFSET: usize = 40;
/// Offset of `token_bytes_length`.
pub const TOKEN_BYTES_LENGTH_OFFSET: usize = 44;
/// Offset of `total_size`.
pub const TOTAL_SIZE_OFFSET: usize = 48;
/// Offset of `pretokenizer`.
pub const PRETOKENIZER_OFFSET: usize = 52;
/// Offset of the first byte of `reserved_tail`.
pub const RESERVED_TAIL_OFFSET: usize = 56;

/// Bytes in the fixed header.
pub const HEADER_BYTES: usize = 64;
/// Bytes in the byte-token table.
pub const BYTE_TOKEN_TABLE_BYTES: usize = 1024;
/// Bytes in one token record.
pub const TOKEN_RECORD_BYTES: usize = 8;
/// Bytes in one merge record.
pub const MERGE_RECORD_BYTES: usize = 16;
/// Bytes in one sort-index entry.
pub const INDEX_ENTRY_BYTES: usize = 4;

/// A built blob together with the offsets of its sections, so a test can patch
/// a specific record without re-deriving the layout.
pub struct BuiltVocabulary {
    pub bytes: Vec<u8>,
    pub byte_token_table: usize,
    pub token_table: usize,
    pub token_index: usize,
    pub merge_table: usize,
    pub merge_index: usize,
    pub token_bytes: usize,
}

impl BuiltVocabulary {
    /// Offset of a token record's `byte_offset` word.
    pub fn token_record(&self, token_id: u32) -> usize {
        self.token_table + TOKEN_RECORD_BYTES * token_id as usize
    }

    /// Offset of a merge record's `left` word.
    pub fn merge_record(&self, merge_id: u32) -> usize {
        self.merge_table + MERGE_RECORD_BYTES * merge_id as usize
    }

    /// Offset of a token-index entry.
    pub fn token_index_entry(&self, position: u32) -> usize {
        self.token_index + INDEX_ENTRY_BYTES * position as usize
    }

    /// Offset of a merge-index entry.
    pub fn merge_index_entry(&self, position: u32) -> usize {
        self.merge_index + INDEX_ENTRY_BYTES * position as usize
    }

    /// Offset of a byte-token table entry.
    pub fn byte_token_entry(&self, byte: u8) -> usize {
        self.byte_token_table + INDEX_ENTRY_BYTES * byte as usize
    }
}

/// A vocabulary under construction.
pub struct VocabularyBuilder {
    pub tokens: Vec<Vec<u8>>,
    pub merges: Vec<(u32, u32, u32)>,
    pub pretokenizer: u32,
}

impl VocabularyBuilder {
    /// A vocabulary holding exactly the 256 byte tokens, in byte order, and no
    /// merges, declaring the GPT-2 pre-tokenizer. Token `i` spells byte `i`.
    pub fn new() -> Self {
        let mut tokens = Vec::new();
        for byte_value in 0..256usize {
            tokens.push(vec![byte_value as u8]);
        }
        Self {
            tokens,
            merges: Vec::new(),
            pretokenizer: PRETOKENIZER_GPT2,
        }
    }

    /// The same, declaring a specific pre-tokenizer code.
    pub fn with_pretokenizer(code: u32) -> Self {
        let mut builder = Self::new();
        builder.pretokenizer = code;
        builder
    }

    /// Appends a token and returns its identifier.
    pub fn add_token(&mut self, bytes: &[u8]) -> u32 {
        self.tokens.push(bytes.to_vec());
        (self.tokens.len() - 1) as u32
    }

    /// Identifier of the token spelling `bytes`, if one exists.
    pub fn token_id(&self, bytes: &[u8]) -> Option<u32> {
        let position = self.tokens.iter().position(|token| token == bytes)?;
        Some(position as u32)
    }

    /// Appends a merge record verbatim. No validation, on purpose.
    pub fn add_merge(&mut self, left: u32, right: u32, result: u32) {
        self.merges.push((left, right, result));
    }

    /// Appends the merge `left ++ right`, creating the result token if it does
    /// not exist yet. The merge's rank is its insertion order.
    pub fn merge_bytes(&mut self, left: &[u8], right: &[u8]) -> u32 {
        let left_id = self.token_id(left).expect("left token missing");
        let right_id = self.token_id(right).expect("right token missing");
        let mut joined = left.to_vec();
        joined.extend_from_slice(right);
        let result_id = match self.token_id(&joined) {
            Some(existing) => existing,
            None => self.add_token(&joined),
        };
        self.add_merge(left_id, right_id, result_id);
        result_id
    }

    /// Serializes the vocabulary to a BXV1 blob.
    pub fn build(&self) -> BuiltVocabulary {
        let layout = self.layout();
        let mut bytes = self.header(&layout);
        bytes.extend_from_slice(&self.byte_token_table());
        bytes.extend_from_slice(&self.token_table(layout.token_bytes));
        bytes.extend_from_slice(&self.token_index());
        bytes.extend_from_slice(&self.merge_table());
        bytes.extend_from_slice(&self.merge_index());
        bytes.extend_from_slice(&self.token_byte_region());
        BuiltVocabulary { bytes, ..layout }
    }

    fn layout(&self) -> BuiltVocabulary {
        let token_count = self.tokens.len();
        let merge_count = self.merges.len();
        let byte_token_table = HEADER_BYTES;
        let token_table = byte_token_table + BYTE_TOKEN_TABLE_BYTES;
        let token_index = token_table + TOKEN_RECORD_BYTES * token_count;
        let merge_table = token_index + INDEX_ENTRY_BYTES * token_count;
        let merge_index = merge_table + MERGE_RECORD_BYTES * merge_count;
        let token_bytes = merge_index + INDEX_ENTRY_BYTES * merge_count;
        BuiltVocabulary {
            bytes: Vec::new(),
            byte_token_table,
            token_table,
            token_index,
            merge_table,
            merge_index,
            token_bytes,
        }
    }

    fn header(&self, layout: &BuiltVocabulary) -> Vec<u8> {
        let region: usize = self.tokens.iter().map(|token| token.len()).sum();
        let total = layout.token_bytes + region;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BXV1");
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&(self.tokens.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(self.merges.len() as u32).to_le_bytes());
        for offset in [
            layout.byte_token_table,
            layout.token_table,
            layout.token_index,
            layout.merge_table,
            layout.merge_index,
            layout.token_bytes,
        ] {
            bytes.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        bytes.extend_from_slice(&(region as u32).to_le_bytes());
        bytes.extend_from_slice(&(total as u32).to_le_bytes());
        bytes.extend_from_slice(&self.pretokenizer.to_le_bytes());
        bytes.resize(HEADER_BYTES, 0);
        bytes
    }

    fn byte_token_table(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for byte_value in 0..256usize {
            let wanted = vec![byte_value as u8];
            let token_id = self.token_id(&wanted).unwrap_or(0);
            bytes.extend_from_slice(&token_id.to_le_bytes());
        }
        bytes
    }

    fn token_table(&self, region_start: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut cursor = region_start;
        for token in &self.tokens {
            bytes.extend_from_slice(&(cursor as u32).to_le_bytes());
            bytes.extend_from_slice(&(token.len() as u32).to_le_bytes());
            cursor += token.len();
        }
        bytes
    }

    fn token_index(&self) -> Vec<u8> {
        let mut order: Vec<u32> = (0..self.tokens.len() as u32).collect();
        order.sort_by(|left, right| self.tokens[*left as usize].cmp(&self.tokens[*right as usize]));
        let mut bytes = Vec::new();
        for entry in order {
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        bytes
    }

    fn merge_table(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for (rank, (left, right, result)) in self.merges.iter().enumerate() {
            bytes.extend_from_slice(&left.to_le_bytes());
            bytes.extend_from_slice(&right.to_le_bytes());
            bytes.extend_from_slice(&result.to_le_bytes());
            bytes.extend_from_slice(&(rank as u32).to_le_bytes());
        }
        bytes
    }

    fn merge_index(&self) -> Vec<u8> {
        let mut order: Vec<u32> = (0..self.merges.len() as u32).collect();
        order.sort_by_key(|entry| {
            let (left, right, _) = self.merges[*entry as usize];
            ((left as u64) << 32) | right as u64
        });
        let mut bytes = Vec::new();
        for entry in order {
            bytes.extend_from_slice(&entry.to_le_bytes());
        }
        bytes
    }

    fn token_byte_region(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for token in &self.tokens {
            bytes.extend_from_slice(token);
        }
        bytes
    }
}

/// Overwrites a little-endian `u32` at `offset` in a copy of `blob`.
pub fn patched_u32(blob: &[u8], offset: usize, value: u32) -> Vec<u8> {
    let mut out = blob.to_vec();
    out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    out
}

/// Overwrites a little-endian `u16` at `offset` in a copy of `blob`.
pub fn patched_u16(blob: &[u8], offset: usize, value: u16) -> Vec<u8> {
    let mut out = blob.to_vec();
    out[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    out
}

/// Overwrites a single byte at `offset` in a copy of `blob`.
pub fn patched_byte(blob: &[u8], offset: usize, value: u8) -> Vec<u8> {
    let mut out = blob.to_vec();
    out[offset] = value;
    out
}

/// Truncates a copy of `blob` to `length` bytes.
pub fn truncated(blob: &[u8], length: usize) -> Vec<u8> {
    blob[..length].to_vec()
}

/// A tiny vocabulary used by the round-trip and determinism suites: the 256
/// byte tokens plus a handful of merges over ASCII and over the UTF-8 bytes of
/// a couple of multi-byte characters.
pub fn sample_vocabulary() -> BuiltVocabulary {
    let mut builder = VocabularyBuilder::new();
    builder.merge_bytes(b"a", b"b");
    builder.merge_bytes(b"ab", b"c");
    builder.merge_bytes(b"h", b"e");
    builder.merge_bytes(b"l", b"l");
    builder.merge_bytes(b"he", b"ll");
    builder.merge_bytes(b" ", b"w");
    builder.merge_bytes(&[0xc3], &[0xa9]);
    builder.merge_bytes(&[0xf0], &[0x9f]);
    builder.build()
}
