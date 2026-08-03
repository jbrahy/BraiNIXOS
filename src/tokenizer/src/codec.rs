//! Encode and decode.
//!
//! # The merge rule, stated exactly
//!
//! At every step, among all adjacent pairs of the current token sequence that
//! match a merge rule, the encoder applies **the rule with the lowest rank**;
//! if that rule matches at more than one position, it applies at the
//! **leftmost** of them. It repeats until no adjacent pair matches any rule.
//!
//! Rank priority is the whole of BPE and it is where implementations are
//! usually wrong. A greedy left-to-right pass — "walk the sequence and merge
//! the first mergeable pair you see" — produces different tokens whenever a
//! later position carries a higher-priority rule, and the difference is silent:
//! the output is a valid-looking token sequence that the model was not trained
//! on. `tests/merge_order.rs` builds a vocabulary where the two strategies
//! disagree and pins the rank-priority answer.
//!
//! Ranks are unique by construction — a merge record's rank must equal its
//! table index (`docs/architecture/BPE-vocabulary-format.md` §7.5) — so "the
//! lowest rank" never needs a tie-break between two different rules. The
//! leftmost tie-break is between two occurrences of the *same* rule.
//!
//! # The work bound
//!
//! Let `N` be the input length in bytes. The sequence starts at exactly `N`
//! tokens (one per byte), every iteration removes exactly one token, and the
//! loop stops at one token, so there are **at most `N − 1` merge iterations**.
//! Each iteration scans at most `N − 1` recorded ranks to find the minimum and
//! performs at most three merge-table lookups, each a binary search over at
//! most `BXV1_MAX_MERGES` records.
//!
//! Total: `≤ (N − 1)²` rank comparisons and `≤ 3N` binary searches, with `N`
//! bounded by [`MAX_ENCODE_INPUT_BYTES`](crate::MAX_ENCODE_INPUT_BYTES). The
//! quadratic term is what forces that ceiling to be a `const` — an unbounded
//! `N` here would be a denial-of-service hole, since the work an attacker buys
//! grows faster than the bytes they send.
//!
//! The bound is enforced, not merely argued: the loop carries a budget of `N`
//! iterations and denies with
//! [`VocabularyError::MergeBudgetExhausted`](crate::VocabularyError::MergeBudgetExhausted)
//! if it is ever exhausted. That path is unreachable given the argument above,
//! and it is checked anyway, because "unreachable" is an argument in a document
//! and the counter is a property of the program.

use core::cmp::Ordering;

use crate::error::VocabularyError;
use crate::{MergeRecord, Vocabulary, NO_MERGE_RANK};

/// Packs a merge's operands into the single key the merge index is sorted by.
pub(crate) fn merge_key(left: u32, right: u32) -> u64 {
    let high = (left as u64) << 32;
    high | (right as u64)
}

impl Vocabulary<'_> {
    /// Encodes `input` to token identifiers, returning how many were written.
    ///
    /// `input` is a byte string. It is not required to be UTF-8, is never
    /// validated as UTF-8, and no byte of it is ever replaced or dropped — see
    /// the crate documentation for why that rule is the deliberate one.
    ///
    /// Both `scratch` and `output` must hold at least `input.len()` entries.
    /// That is the honest requirement rather than a conservative one: the
    /// seeded sequence is one token per input byte, so a shorter output slice
    /// could not hold the starting state even though the finished sequence is
    /// usually far shorter. A slice that is too small is an error, never a
    /// truncated encode.
    ///
    /// On any error nothing is claimed: the returned length is the only thing
    /// that says how much of `output` is meaningful, and no error path returns
    /// one.
    pub fn encode(
        &self,
        input: &[u8],
        scratch: &mut [u32],
        output: &mut [u32],
    ) -> Result<usize, VocabularyError> {
        let outcome = self.encode_measured(input, scratch, output)?;
        Ok(outcome.token_count)
    }

    /// Encodes exactly as [`Vocabulary::encode`] does, and additionally reports
    /// how many merge iterations it took.
    ///
    /// The iteration count is the quantity the work bound in this module's
    /// documentation is stated over, so it is reported rather than inferred:
    /// a bound nothing can observe is a bound nothing can test, and this is
    /// the number an audit trail would want if a prompt ever became expensive.
    pub fn encode_measured(
        &self,
        input: &[u8],
        scratch: &mut [u32],
        output: &mut [u32],
    ) -> Result<EncodeOutcome, VocabularyError> {
        require_encode_capacity(input, scratch, output)?;
        seed_byte_tokens(self, input, output)?;
        seed_pair_ranks(self, input.len(), output, scratch)?;
        run_merges(self, input.len(), output, scratch)
    }

    /// Decodes token identifiers back to bytes, returning how many were
    /// written.
    ///
    /// Output is bytes, never `&str`: the vocabulary can spell any byte
    /// sequence, so a `&str` return would either have to fail on a valid
    /// vocabulary or lie about what the model produced.
    ///
    /// An identifier at or above `token_count` denies with
    /// [`VocabularyError::TokenIdOutOfRange`], and an output slice that cannot
    /// hold the result denies with
    /// [`VocabularyError::ByteOutputTooSmall`]. Neither writes a partial
    /// answer the caller could mistake for a whole one, because the returned
    /// length is the only thing that says how much of `output` is meaningful.
    pub fn decode(&self, tokens: &[u32], output: &mut [u8]) -> Result<usize, VocabularyError> {
        let mut written = 0usize;
        for token_id in tokens {
            written = self.append_token_bytes(*token_id, written, output)?;
        }
        Ok(written)
    }

    /// Copies one token's bytes into `output` at `written` and returns the new
    /// write position.
    fn append_token_bytes(
        &self,
        token_id: u32,
        written: usize,
        output: &mut [u8],
    ) -> Result<usize, VocabularyError> {
        let bytes = self.token_bytes(token_id)?;
        let end = written
            .checked_add(bytes.len())
            .ok_or(VocabularyError::ArithmeticOverflow)?;
        let slot = output
            .get_mut(written..end)
            .ok_or(VocabularyError::ByteOutputTooSmall)?;
        slot.copy_from_slice(bytes);
        Ok(end)
    }

    /// Finds the merge rule for an adjacent pair, or `None` if no rule applies.
    ///
    /// A binary search over the merge index, which
    /// [`crate::validate`] proved strictly ascending in `(left, right)` order.
    /// At most `log2(BXV1_MAX_MERGES) = 20` probes, each fully bounds-checked.
    pub fn find_merge(
        &self,
        left: u32,
        right: u32,
    ) -> Result<Option<MergeRecord>, VocabularyError> {
        let wanted = merge_key(left, right);
        let mut low = 0u32;
        let mut high = self.merge_count();
        while low < high {
            let middle = midpoint(low, high)?;
            match self.probe(middle, wanted)? {
                Probe::Found(record) => return Ok(Some(record)),
                Probe::Below => low = middle.checked_add(1).ok_or(overflow())?,
                Probe::Above => high = middle,
            }
        }
        Ok(None)
    }

    /// Reads the merge record the index points at and compares its key against
    /// the one being searched for.
    fn probe(&self, position: u32, wanted: u64) -> Result<Probe, VocabularyError> {
        let entry = self.merge_index_entry(position)?;
        let record = self.merge_record(entry)?;
        let key = merge_key(record.left, record.right);
        match key.cmp(&wanted) {
            Ordering::Equal => Ok(Probe::Found(record)),
            Ordering::Less => Ok(Probe::Below),
            Ordering::Greater => Ok(Probe::Above),
        }
    }
}

/// The three outcomes of one binary-search probe.
enum Probe {
    /// The probed record is the one being searched for.
    Found(MergeRecord),
    /// The probed key sorts before the wanted key.
    Below,
    /// The probed key sorts after the wanted key.
    Above,
}

/// `low + (high − low) / 2`, checked.
fn midpoint(low: u32, high: u32) -> Result<u32, VocabularyError> {
    let span = high.checked_sub(low).ok_or(overflow())?;
    let half = span.checked_div(2).ok_or(overflow())?;
    low.checked_add(half).ok_or(overflow())
}

/// The single arithmetic-denial reason, named once.
fn overflow() -> VocabularyError {
    VocabularyError::ArithmeticOverflow
}

/// Applies the three capacity rules before any work is done.
fn require_encode_capacity(
    input: &[u8],
    scratch: &[u32],
    output: &[u32],
) -> Result<(), VocabularyError> {
    if input.len() > crate::MAX_ENCODE_INPUT_BYTES {
        return Err(VocabularyError::PromptTooLong);
    }
    if output.len() < input.len() {
        return Err(VocabularyError::TokenOutputTooSmall);
    }
    if scratch.len() < input.len() {
        return Err(VocabularyError::ScratchTooSmall);
    }
    Ok(())
}

/// Writes one byte token per input byte. Cannot fail on a validated
/// vocabulary: the byte-token table covers all 256 values by construction.
fn seed_byte_tokens(
    vocabulary: &Vocabulary<'_>,
    input: &[u8],
    output: &mut [u32],
) -> Result<(), VocabularyError> {
    for (position, byte) in input.iter().enumerate() {
        let token_id = vocabulary.byte_token(*byte)?;
        let slot = output
            .get_mut(position)
            .ok_or(VocabularyError::TokenOutputTooSmall)?;
        *slot = token_id;
    }
    Ok(())
}

/// Records the applicable rank for every adjacent pair of the seeded sequence.
fn seed_pair_ranks(
    vocabulary: &Vocabulary<'_>,
    count: usize,
    tokens: &[u32],
    ranks: &mut [u32],
) -> Result<(), VocabularyError> {
    let pair_count = count.saturating_sub(1);
    for position in 0..pair_count {
        store_pair_rank(vocabulary, position, tokens, ranks)?;
    }
    Ok(())
}

/// Looks up the pair starting at `position` and records its rank, or the
/// no-merge sentinel.
fn store_pair_rank(
    vocabulary: &Vocabulary<'_>,
    position: usize,
    tokens: &[u32],
    ranks: &mut [u32],
) -> Result<(), VocabularyError> {
    let (left, right) = read_pair(tokens, position)?;
    let found = vocabulary.find_merge(left, right)?;
    let rank = match found {
        Some(record) => record.rank,
        None => NO_MERGE_RANK,
    };
    let slot = ranks
        .get_mut(position)
        .ok_or(VocabularyError::ScratchTooSmall)?;
    *slot = rank;
    Ok(())
}

/// Reads the adjacent pair starting at `position`.
fn read_pair(tokens: &[u32], position: usize) -> Result<(u32, u32), VocabularyError> {
    let next = position.checked_add(1).ok_or(overflow())?;
    let left = tokens
        .get(position)
        .ok_or(VocabularyError::TokenOutputTooSmall)?;
    let right = tokens
        .get(next)
        .ok_or(VocabularyError::TokenOutputTooSmall)?;
    Ok((*left, *right))
}

/// What one call to [`Vocabulary::encode_measured`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeOutcome {
    /// Number of token identifiers written to the output slice.
    pub token_count: usize,
    /// Number of merge iterations performed. Never more than
    /// `input.len() − 1`.
    pub merge_iterations: usize,
}

/// Runs the merge loop to a fixed point and reports what it did.
fn run_merges(
    vocabulary: &Vocabulary<'_>,
    initial: usize,
    tokens: &mut [u32],
    ranks: &mut [u32],
) -> Result<EncodeOutcome, VocabularyError> {
    let mut count = initial;
    let mut budget = initial;
    while count > 1 {
        budget = budget
            .checked_sub(1)
            .ok_or(VocabularyError::MergeBudgetExhausted)?;
        let pair_count = count.saturating_sub(1);
        match find_lowest_rank_pair(ranks, pair_count) {
            Some(position) => count = apply_merge(vocabulary, position, count, tokens, ranks)?,
            None => break,
        }
    }
    Ok(finish(initial, count))
}

/// Turns the starting and ending token counts into an outcome. Every iteration
/// removed exactly one token, so the difference *is* the iteration count.
fn finish(initial: usize, count: usize) -> EncodeOutcome {
    EncodeOutcome {
        token_count: count,
        merge_iterations: initial.saturating_sub(count),
    }
}

/// Returns the position of the lowest-ranked applicable pair, leftmost on a
/// tie, or `None` when no pair matches any rule.
fn find_lowest_rank_pair(ranks: &[u32], pair_count: usize) -> Option<usize> {
    let mut best_rank = NO_MERGE_RANK;
    let mut best_position = None;
    for position in 0..pair_count {
        let rank = *ranks.get(position)?;
        if rank < best_rank {
            best_rank = rank;
            best_position = Some(position);
        }
    }
    best_position
}

/// Collapses the pair at `position` and repairs the ranks around it, returning
/// the new token count.
fn apply_merge(
    vocabulary: &Vocabulary<'_>,
    position: usize,
    count: usize,
    tokens: &mut [u32],
    ranks: &mut [u32],
) -> Result<usize, VocabularyError> {
    let (left, right) = read_pair(tokens, position)?;
    let record = vocabulary
        .find_merge(left, right)?
        .ok_or(VocabularyError::MergeLookupInconsistent)?;
    write_token(tokens, position, record.result)?;
    let new_count = close_gap(position, count, tokens, ranks)?;
    refresh_neighbour_ranks(vocabulary, position, new_count, tokens, ranks)?;
    Ok(new_count)
}

/// Stores a token identifier at `position`.
fn write_token(tokens: &mut [u32], position: usize, token_id: u32) -> Result<(), VocabularyError> {
    let slot = tokens
        .get_mut(position)
        .ok_or(VocabularyError::TokenOutputTooSmall)?;
    *slot = token_id;
    Ok(())
}

/// Removes the now-absorbed right operand from the token sequence and its
/// entry from the rank array, returning the new token count.
fn close_gap(
    position: usize,
    count: usize,
    tokens: &mut [u32],
    ranks: &mut [u32],
) -> Result<usize, VocabularyError> {
    let removed = position.checked_add(1).ok_or(overflow())?;
    remove_element(tokens, removed, count)?;
    let pair_count = count.saturating_sub(1);
    if removed < pair_count {
        remove_element(ranks, removed, pair_count)?;
    }
    count.checked_sub(1).ok_or(overflow())
}

/// Deletes `values[removed]` from the prefix `values[..end]` by shifting the
/// tail down one place.
///
/// The two guards below are what make the shift total: `removed < end` gives a
/// non-empty, correctly ordered source range, and `end <= values.len()` keeps
/// both the source range and the destination inside the slice.
fn remove_element(values: &mut [u32], removed: usize, end: usize) -> Result<(), VocabularyError> {
    if removed >= end || end > values.len() {
        return Err(overflow());
    }
    let source = removed.checked_add(1).ok_or(overflow())?;
    values.copy_within(source..end, removed);
    Ok(())
}

/// Recomputes the two rank entries a merge at `position` can have invalidated:
/// the pair to its left and the pair it now forms with its new right
/// neighbour.
fn refresh_neighbour_ranks(
    vocabulary: &Vocabulary<'_>,
    position: usize,
    count: usize,
    tokens: &[u32],
    ranks: &mut [u32],
) -> Result<(), VocabularyError> {
    if let Some(previous) = position.checked_sub(1) {
        store_pair_rank(vocabulary, previous, tokens, ranks)?;
    }
    let pair_count = count.saturating_sub(1);
    if position < pair_count {
        store_pair_rank(vocabulary, position, tokens, ranks)?;
    }
    Ok(())
}
