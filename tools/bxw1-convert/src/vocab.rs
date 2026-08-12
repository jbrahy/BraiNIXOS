//! GPT-2 byte-level BPE files → a BXV1 vocabulary blob.
//!
//! `docs/architecture/BPE-vocabulary-format.md` is the specification; every
//! rule identifier below is its.
//!
//! # Why a GPT-2-family tokenizer converts cleanly and a SentencePiece one does
//! not
//!
//! BXV1 is **byte-level**: encoding seeds one byte token per input byte and
//! every token afterwards is reached by a merge rule (§5.1). A GPT-2 tokenizer
//! is byte-level in exactly the same sense — its alphabet is the 256 byte
//! values under the `bytes_to_unicode` bijection — so the seeding, the merge
//! graph and the byte-token table all transfer without approximation.
//!
//! A SentencePiece tokenizer's alphabet is *characters*, and a multi-byte
//! character is a single alphabet symbol reached by no merge. Converting one
//! would leave every non-ASCII character unreachable from the byte seeding,
//! which is a silent tokenization divergence rather than a refused load. That
//! is why this converter accepts `vocab.json` + `merges.txt` and refuses
//! anything else.

use std::collections::HashMap;
use std::path::Path;

use crate::json;

/// Pre-tokenizer code for GPT-2's rule (§5.4 mode 2).
pub const PRETOKENIZER_GPT2: u32 = 2;

/// A vocabulary ready to be written as BXV1.
pub struct Vocabulary {
    /// Every token's bytes, indexed by identifier.
    pub tokens: Vec<Vec<u8>>,
    /// `(left, right, result)` in rank order.
    pub merges: Vec<(u32, u32, u32)>,
    /// Which pre-tokenizer the vocabulary was trained behind.
    pub pretokenizer: u32,
    /// How many identifiers past the trained vocabulary were appended to reach
    /// the model's `vocab_size`.
    pub padding_tokens: usize,
}

/// GPT-2's `bytes_to_unicode` map, as a code point → byte inverse.
fn unicode_to_byte() -> HashMap<u32, u8> {
    let mut printable: Vec<u32> = Vec::new();
    printable.extend(0x21..=0x7E);
    printable.extend(0xA1..=0xAC);
    printable.extend(0xAE..=0xFF);
    let mut map = HashMap::new();
    for code in &printable {
        map.insert(*code, *code as u8);
    }
    let mut next = 0u32;
    for byte in 0u32..256 {
        if !printable.contains(&byte) {
            map.insert(256 + next, byte as u8);
            next += 1;
        }
    }
    map
}

fn decode(text: &str, map: &HashMap<u32, u8>) -> Result<Vec<u8>, String> {
    text.chars()
        .map(|character| {
            map.get(&(character as u32))
                .copied()
                .ok_or_else(|| format!("token contains {character:?}, not a GPT-2 alphabet symbol"))
        })
        .collect()
}

/// Reads `vocab.json` and `merges.txt` and builds the vocabulary.
///
/// `target_size` is the model's `vocab_size`. When the embedding matrix has
/// more rows than the tokenizer has tokens — the common practice of padding to
/// a hardware-friendly multiple — the surplus identifiers are filled with
/// unreachable tokens rather than the matrix being truncated, so the weights
/// stay bit-identical to the checkpoint. See the report for why the format
/// leaves no better option.
pub fn load(directory: &Path, target_size: usize) -> Result<Vocabulary, String> {
    let map = unicode_to_byte();

    let raw = std::fs::read(directory.join("vocab.json"))
        .map_err(|error| format!("vocab.json: {error}"))?;
    let document = json::parse(&raw).map_err(|error| format!("vocab.json: {error}"))?;
    let members = document
        .as_object()
        .ok_or("vocab.json is not an object")?;

    let mut tokens: Vec<Option<Vec<u8>>> = vec![None; members.len()];
    let mut by_bytes: HashMap<Vec<u8>, u32> = HashMap::new();
    for (text, value) in members {
        let id = value
            .as_usize()
            .ok_or_else(|| format!("vocab.json: {text:?} has a non-integer identifier"))?;
        let bytes = decode(text, &map)?;
        if id >= tokens.len() {
            return Err(format!("vocab.json: identifier {id} is out of range"));
        }
        if tokens[id].is_some() {
            return Err(format!("vocab.json: identifier {id} appears twice"));
        }
        if by_bytes.insert(bytes.clone(), id as u32).is_some() {
            return Err(format!(
                "vocab.json: two tokens spell the same bytes — BXV1 rule X4 refuses that"
            ));
        }
        tokens[id] = Some(bytes);
    }
    let mut tokens: Vec<Vec<u8>> = tokens
        .into_iter()
        .enumerate()
        .map(|(id, bytes)| bytes.ok_or(format!("vocab.json: identifier {id} is missing")))
        .collect::<Result<_, _>>()?;

    let merges_text = std::fs::read_to_string(directory.join("merges.txt"))
        .map_err(|error| format!("merges.txt: {error}"))?;
    let mut merges = Vec::new();
    for line in merges_text.lines() {
        if line.is_empty() || line.starts_with("#version") {
            continue;
        }
        let (left_text, right_text) = line
            .split_once(' ')
            .ok_or_else(|| format!("merges.txt: {line:?} is not a pair"))?;
        let left = decode(left_text, &map)?;
        let right = decode(right_text, &map)?;
        let mut result = left.clone();
        result.extend_from_slice(&right);
        let left_id = *by_bytes
            .get(&left)
            .ok_or_else(|| format!("merges.txt: {left_text:?} is not in the vocabulary"))?;
        let right_id = *by_bytes
            .get(&right)
            .ok_or_else(|| format!("merges.txt: {right_text:?} is not in the vocabulary"))?;
        let result_id = *by_bytes.get(&result).ok_or_else(|| {
            format!("merges.txt: {left_text:?}+{right_text:?} has no token — rule M6")
        })?;
        merges.push((left_id, right_id, result_id));
    }

    // Rule B3: every one of the 256 byte values must have a single-byte token.
    for byte in 0u16..256 {
        let single = vec![byte as u8];
        if !by_bytes.contains_key(&single) {
            return Err(format!(
                "no token spells the single byte 0x{byte:02x} — BXV1 cannot represent this \
                 vocabulary (§3.3)"
            ));
        }
    }

    let padding_tokens = target_size.saturating_sub(tokens.len());
    if tokens.len() > target_size {
        return Err(format!(
            "the tokenizer has {} tokens but the model's vocab_size is {target_size}; \
             truncating an embedding matrix is a model change, not a conversion",
            tokens.len()
        ));
    }
    for index in 0..padding_tokens {
        // Four bytes, so it can never be a byte token, and reached by no merge
        // rule, so the encoder can never emit it. Uniqueness is asserted below.
        let filler = vec![
            0x00,
            0xFF,
            (index >> 8) as u8,
            (index & 0xFF) as u8,
        ];
        if by_bytes.contains_key(&filler) {
            return Err("padding token collides with a real token".to_string());
        }
        tokens.push(filler);
    }

    Ok(Vocabulary {
        tokens,
        merges,
        pretokenizer: PRETOKENIZER_GPT2,
        padding_tokens,
    })
}

/// Emits the BXV1 blob.
pub fn emit(vocabulary: &Vocabulary) -> Result<Vec<u8>, String> {
    let token_count = vocabulary.tokens.len() as u32;
    let merge_count = vocabulary.merges.len() as u32;

    let byte_token_table_offset = 64u32;
    let token_table_offset = 1088u32;
    let token_index_offset = token_table_offset + 8 * token_count;
    let merge_table_offset = token_table_offset + 12 * token_count;
    let merge_index_offset = merge_table_offset + 16 * merge_count;
    let token_bytes_offset = merge_index_offset + 4 * merge_count;
    let token_bytes_length: u32 = vocabulary
        .tokens
        .iter()
        .map(|bytes| bytes.len() as u32)
        .sum();
    let total_size = token_bytes_offset + token_bytes_length;

    // Rule B3's table, and rule X4's uniqueness, both derived from the token
    // bytes themselves rather than from a claim the source file made.
    let mut byte_token = [u32::MAX; 256];
    let mut seen: HashMap<&[u8], u32> = HashMap::new();
    for (id, bytes) in vocabulary.tokens.iter().enumerate() {
        if bytes.is_empty() {
            return Err(format!("token {id} is empty — rule K2"));
        }
        if seen.insert(bytes.as_slice(), id as u32).is_some() {
            return Err(format!("token {id} duplicates another's bytes — rule X4"));
        }
        if bytes.len() == 1 {
            byte_token[bytes[0] as usize] = id as u32;
        }
    }
    if let Some(missing) = byte_token.iter().position(|id| *id == u32::MAX) {
        return Err(format!("byte 0x{missing:02x} has no token"));
    }

    let mut token_order: Vec<u32> = (0..token_count).collect();
    token_order.sort_by(|left, right| {
        vocabulary.tokens[*left as usize].cmp(&vocabulary.tokens[*right as usize])
    });
    let mut merge_order: Vec<u32> = (0..merge_count).collect();
    merge_order.sort_by_key(|index| {
        let (left, right, _) = vocabulary.merges[*index as usize];
        (u64::from(left) << 32) | u64::from(right)
    });
    for pair in merge_order.windows(2) {
        let first = vocabulary.merges[pair[0] as usize];
        let second = vocabulary.merges[pair[1] as usize];
        if (first.0, first.1) == (second.0, second.1) {
            return Err("two merge rules name the same pair — rule X5".to_string());
        }
    }

    let mut blob = Vec::with_capacity(total_size as usize);
    blob.extend_from_slice(b"BXV1");
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u32.to_le_bytes()); // flags
    blob.extend_from_slice(&token_count.to_le_bytes());
    blob.extend_from_slice(&merge_count.to_le_bytes());
    for field in [
        byte_token_table_offset,
        token_table_offset,
        token_index_offset,
        merge_table_offset,
        merge_index_offset,
        token_bytes_offset,
        token_bytes_length,
        total_size,
        vocabulary.pretokenizer,
    ] {
        blob.extend_from_slice(&field.to_le_bytes());
    }
    blob.resize(64, 0); // reserved_tail

    for id in byte_token {
        blob.extend_from_slice(&id.to_le_bytes());
    }

    let mut cursor = token_bytes_offset;
    for bytes in &vocabulary.tokens {
        blob.extend_from_slice(&cursor.to_le_bytes());
        blob.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        cursor += bytes.len() as u32;
    }
    for id in &token_order {
        blob.extend_from_slice(&id.to_le_bytes());
    }
    for (rank, (left, right, result)) in vocabulary.merges.iter().enumerate() {
        blob.extend_from_slice(&left.to_le_bytes());
        blob.extend_from_slice(&right.to_le_bytes());
        blob.extend_from_slice(&result.to_le_bytes());
        blob.extend_from_slice(&(rank as u32).to_le_bytes());
    }
    for index in &merge_order {
        blob.extend_from_slice(&index.to_le_bytes());
    }
    for bytes in &vocabulary.tokens {
        blob.extend_from_slice(bytes);
    }

    if blob.len() as u32 != total_size {
        return Err(format!(
            "internal: assembled {} bytes, declared {total_size}",
            blob.len()
        ));
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_byte_map_is_a_bijection_over_256_values() {
        let map = unicode_to_byte();
        assert_eq!(map.len(), 256);
        let mut seen = [false; 256];
        for byte in map.values() {
            assert!(!seen[*byte as usize]);
            seen[*byte as usize] = true;
        }
        assert!(seen.iter().all(|hit| *hit));
        // The two anchors every GPT-2 implementation agrees on.
        assert_eq!(map[&('Ġ' as u32)], b' ');
        assert_eq!(map[&('Ċ' as u32)], b'\n');
    }
}
