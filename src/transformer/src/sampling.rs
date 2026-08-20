//! Turning a logit vector into a token, with the randomness supplied by the
//! caller.
//!
//! # This crate never reaches for entropy
//!
//! [`sample`] takes a `uniform` deviate in `[0, 1)` as an argument. It does not
//! own an RNG, does not seed one, does not keep sampling state between calls,
//! and cannot be made to. The kernel's CSPRNG is the eventual provider, and
//! routing the request through the caller is what keeps that true: an internal
//! generator would be a second, unaudited source of randomness inside the
//! serving path, and a deterministic one would be worse — it would look random
//! and be predictable to any client that could observe two generations.
//!
//! One deviate produces one token. A caller decoding `n` tokens asks its source
//! for `n` deviates.
//!
//! # Zero allocation
//!
//! [`sample`] needs `2 × vocab_size` floats of scratch — the
//! temperature-scaled logits and their softmax — and the caller supplies them,
//! sized with [`sampler_scratch_floats`]. Top-`k` selection additionally uses a
//! fixed [`MAXIMUM_TOP_K`]-entry array on the stack, which is why `k` has a
//! ceiling: the array is not a growable buffer and never will be.

use brainix_tensor::{is_positive_normal, softmax};

use crate::error::TransformerError;

/// The largest `top_k` this crate accepts.
///
/// Not a statistical judgement: it is the size of the fixed candidate array
/// [`sample`] keeps on the stack, `64 × 8 = 512` bytes, which is a size a
/// kernel stack can carry without thinking about it. A larger `k` is refused
/// rather than silently clamped, because clamping would mean a client's
/// sampling parameters and the engine's behaviour differ with nothing saying
/// so.
pub const MAXIMUM_TOP_K: usize = 64;

/// Floats a caller must reserve for [`sample`]: two vocabulary-wide rows.
///
/// # Errors
///
/// [`TransformerError::DimensionOverflow`].
pub const fn sampler_scratch_floats(vocabulary_size: usize) -> Result<usize, TransformerError> {
    match vocabulary_size.checked_mul(2) {
        Some(floats) => Ok(floats),
        None => Err(TransformerError::DimensionOverflow),
    }
}

/// How a token is chosen from a logit vector.
///
/// There is no `Default`. A serving path that did not say how it samples is a
/// serving path whose output distribution nobody chose.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Sampler {
    /// The highest logit, ties broken by the lower token identifier.
    ///
    /// Ignores the uniform deviate entirely and is bit-for-bit reproducible.
    Greedy,
    /// Sample from `softmax(logits / temperature)` over the whole vocabulary.
    Temperature {
        /// Positive, finite, normal. Zero is refused rather than redirected to
        /// [`Sampler::Greedy`].
        temperature: f32,
    },
    /// Sample from `softmax(logits / temperature)` restricted to the `top_k`
    /// most probable tokens and renormalized over them.
    ///
    /// The cumulative distribution is walked **most probable first**, because
    /// the selection step has already sorted the candidates and re-sorting them
    /// into token order would cost a second pass for no gain. A deviate of zero
    /// is therefore the argmax. [`Sampler::Temperature`] walks in token order,
    /// so the two agree on which tokens are reachable and with what mass, but
    /// not on which deviate lands where.
    TopK {
        /// Positive, finite, normal.
        temperature: f32,
        /// `1 ..= min(vocab_size, MAXIMUM_TOP_K)`.
        top_k: usize,
    },
}

/// The three things choosing a token needs beyond the logits themselves.
///
/// Bundled into one value rather than passed as three arguments so a decode
/// call takes a shape a caller cannot transpose, and so the scratch slice
/// travels with the sampler that sizes it.
#[derive(Debug)]
pub struct SamplingRequest<'a> {
    /// Exactly [`sampler_scratch_floats`] floats, caller-supplied.
    pub scratch: &'a mut [f32],
    /// How the token is chosen.
    pub sampler: Sampler,
    /// The caller's uniform deviate in `[0, 1)`. One per token.
    pub uniform: f32,
}

impl SamplingRequest<'_> {
    /// Chooses a token from `logits` under this request.
    ///
    /// # Errors
    ///
    /// Whatever [`sample`] refuses.
    pub fn choose(&mut self, logits: &[f32]) -> Result<u32, TransformerError> {
        sample(logits, self.scratch, self.sampler, self.uniform)
    }
}

/// One candidate token during top-`k` selection.
///
/// Ordering is `(probability descending, index ascending)`, which is total over
/// the finite values softmax produces and makes selection deterministic under
/// ties — two tokens with identical probability always resolve the same way.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    probability: f32,
    index: usize,
}

impl Candidate {
    /// Whether `self` outranks `other`.
    fn outranks(self, other: Self) -> bool {
        if self.probability > other.probability {
            return true;
        }
        self.probability == other.probability && self.index < other.index
    }
}

/// Chooses a token from `logits`.
///
/// `scratch` must be exactly [`sampler_scratch_floats`] long. `uniform` must be
/// in `[0, 1)` and comes from the caller's entropy source; [`Sampler::Greedy`]
/// ignores it but still requires it to be valid, so that switching samplers
/// cannot turn a latent bad deviate into a live one.
///
/// # Errors
///
/// [`TransformerError::LogitsLengthMismatch`],
/// [`TransformerError::SamplerScratchLengthMismatch`],
/// [`TransformerError::NonFiniteLogits`],
/// [`TransformerError::InvalidTemperature`],
/// [`TransformerError::InvalidTopK`],
/// [`TransformerError::InvalidUniformDeviate`], or
/// [`TransformerError::Kernel`].
pub fn sample(
    logits: &[f32],
    scratch: &mut [f32],
    sampler: Sampler,
    uniform: f32,
) -> Result<u32, TransformerError> {
    admit(logits, scratch, uniform)?;
    match sampler {
        Sampler::Greedy => greedy(logits),
        Sampler::Temperature { temperature } => {
            let probabilities = distribution(logits, scratch, temperature)?;
            walk_full(probabilities, uniform)
        }
        Sampler::TopK { temperature, top_k } => {
            admit_top_k(top_k, logits.len())?;
            let probabilities = distribution(logits, scratch, temperature)?;
            walk_top_k(probabilities, top_k, uniform)
        }
    }
}

/// Length and deviate agreement, before anything is computed.
fn admit(logits: &[f32], scratch: &[f32], uniform: f32) -> Result<(), TransformerError> {
    if logits.is_empty() {
        return Err(TransformerError::LogitsLengthMismatch);
    }
    if scratch.len() != sampler_scratch_floats(logits.len())? {
        return Err(TransformerError::SamplerScratchLengthMismatch);
    }
    // Finiteness first, so no float comparison is ever performed against a
    // possible NaN (BXW1 §4.7's rule, applied to a runtime input).
    if !uniform.is_finite() || !(0.0..1.0).contains(&uniform) {
        return Err(TransformerError::InvalidUniformDeviate);
    }
    Ok(())
}

fn admit_top_k(top_k: usize, vocabulary_size: usize) -> Result<(), TransformerError> {
    if top_k == 0 || top_k > vocabulary_size || top_k > MAXIMUM_TOP_K {
        return Err(TransformerError::InvalidTopK);
    }
    Ok(())
}

/// The highest logit, ties broken by the lower identifier.
fn greedy(logits: &[f32]) -> Result<u32, TransformerError> {
    let mut best = Candidate {
        probability: f32::NEG_INFINITY,
        index: 0,
    };
    for (index, logit) in logits.iter().enumerate() {
        if !logit.is_finite() {
            return Err(TransformerError::NonFiniteLogits);
        }
        let candidate = Candidate {
            probability: *logit,
            index,
        };
        if candidate.outranks(best) {
            best = candidate;
        }
    }
    identifier(best.index)
}

/// `softmax(logits / temperature)` into the second half of `scratch`.
fn distribution<'a>(
    logits: &[f32],
    scratch: &'a mut [f32],
    temperature: f32,
) -> Result<&'a [f32], TransformerError> {
    if !is_positive_normal(temperature) {
        return Err(TransformerError::InvalidTemperature);
    }
    let (scaled, probabilities) = scratch
        .split_at_mut_checked(logits.len())
        .ok_or(TransformerError::SamplerScratchLengthMismatch)?;
    scale_logits(logits, temperature, scaled)?;
    softmax(scaled, probabilities)?;
    Ok(probabilities)
}

/// `scaled[i] = logits[i] / temperature`, refusing a non-finite logit.
///
/// Refused here rather than left to softmax so the error names the model
/// failure — a NaN logit — rather than a kernel precondition.
fn scale_logits(
    logits: &[f32],
    temperature: f32,
    scaled: &mut [f32],
) -> Result<(), TransformerError> {
    let inverse = 1.0 / temperature;
    for (logit, slot) in logits.iter().zip(scaled.iter_mut()) {
        if !logit.is_finite() {
            return Err(TransformerError::NonFiniteLogits);
        }
        *slot = logit * inverse;
    }
    Ok(())
}

/// Inverse-transform sampling over the whole distribution.
///
/// The final fallback is the last index rather than a failure: softmax's output
/// sums to one only to within `f32` rounding, so `uniform` can exceed the
/// accumulated mass by an ulp or two, and the honest answer to "which bucket"
/// is then the last one rather than an error the caller cannot act on.
fn walk_full(probabilities: &[f32], uniform: f32) -> Result<u32, TransformerError> {
    let mut accumulated = 0.0_f32;
    let mut chosen = probabilities.len().checked_sub(1);
    for (index, probability) in probabilities.iter().enumerate() {
        accumulated += probability;
        if uniform < accumulated {
            chosen = Some(index);
            break;
        }
    }
    identifier(chosen.ok_or(TransformerError::LogitsLengthMismatch)?)
}

/// Inverse-transform sampling restricted to the `top_k` most probable tokens,
/// renormalized over exactly those.
fn walk_top_k(probabilities: &[f32], top_k: usize, uniform: f32) -> Result<u32, TransformerError> {
    let (candidates, filled) = select_top(probabilities, top_k)?;
    let selected = candidates
        .get(..filled)
        .ok_or(TransformerError::InvalidTopK)?;
    let mass = total_mass(selected);
    let target = uniform * mass;
    let mut accumulated = 0.0_f32;
    for candidate in selected {
        accumulated += candidate.probability;
        if target < accumulated {
            return identifier(candidate.index);
        }
    }
    // Reached at `uniform = 1.0`, where `target` equals the mass and the
    // comparison above is false at every step. Pinned by
    // `a_uniform_at_the_top_of_the_range_falls_through_to_the_residual`.
    identifier(last_index(selected)?)
}

/// The `top_k` highest-probability candidates, sorted descending.
///
/// Insertion into a fixed [`MAXIMUM_TOP_K`] array: each element costs one
/// comparison against the current worst survivor, and only a survivor pays for
/// the shift. No allocation, no sort of the full vocabulary, and no partial
/// order that could make the result depend on iteration order.
fn select_top(
    probabilities: &[f32],
    top_k: usize,
) -> Result<([Candidate; MAXIMUM_TOP_K], usize), TransformerError> {
    let mut candidates = [Candidate {
        probability: f32::NEG_INFINITY,
        index: 0,
    }; MAXIMUM_TOP_K];
    let mut filled = 0_usize;
    for (index, probability) in probabilities.iter().enumerate() {
        let candidate = Candidate {
            probability: *probability,
            index,
        };
        insert(&mut candidates, &mut filled, candidate, top_k)?;
    }
    Ok((candidates, filled))
}

/// Places `candidate` in the sorted prefix if it belongs there.
fn insert(
    candidates: &mut [Candidate],
    filled: &mut usize,
    candidate: Candidate,
    capacity: usize,
) -> Result<(), TransformerError> {
    let position = if *filled < capacity {
        let position = *filled;
        *filled = filled.checked_add(1).ok_or(TransformerError::InvalidTopK)?;
        position
    } else {
        let worst = capacity
            .checked_sub(1)
            .ok_or(TransformerError::InvalidTopK)?;
        if !candidate.outranks(*candidates.get(worst).ok_or(TransformerError::InvalidTopK)?) {
            return Ok(());
        }
        worst
    };
    *candidates
        .get_mut(position)
        .ok_or(TransformerError::InvalidTopK)? = candidate;
    bubble_up(candidates, position);
    Ok(())
}

/// Moves the entry at `position` forward while it outranks its predecessor.
fn bubble_up(candidates: &mut [Candidate], position: usize) {
    let mut current = position;
    while let Some(previous) = current.checked_sub(1) {
        let (Some(here), Some(before)) = (
            candidates.get(current).copied(),
            candidates.get(previous).copied(),
        ) else {
            // Unreachable from this crate, where every caller sifts an index it
            // just wrote, but not from the function: a position past the end
            // lands here and must return rather than index.
            return;
        };
        if !here.outranks(before) {
            return;
        }
        write(candidates, current, before);
        write(candidates, previous, here);
        current = previous;
    }
}

/// Stores `candidate` at `position`, doing nothing if the index is out of
/// range — which [`bubble_up`] has already excluded.
fn write(candidates: &mut [Candidate], position: usize, candidate: Candidate) {
    if let Some(slot) = candidates.get_mut(position) {
        *slot = candidate;
    }
}

/// The probability mass the selected candidates carry.
fn total_mass(selected: &[Candidate]) -> f32 {
    let mut mass = 0.0_f32;
    for candidate in selected {
        mass += candidate.probability;
    }
    mass
}

/// The last selected candidate's token identifier.
fn last_index(selected: &[Candidate]) -> Result<usize, TransformerError> {
    let last = selected.last().ok_or(TransformerError::InvalidTopK)?;
    Ok(last.index)
}

/// Narrows a vocabulary index to the `u32` a token identifier is.
fn identifier(index: usize) -> Result<u32, TransformerError> {
    u32::try_from(index).map_err(|_| TransformerError::TokenOutOfRange)
}

/// The sampler's residual paths, reached directly rather than through a draw.
///
/// # Why these were exempt
///
/// `last_index` is reached only when the accumulation loop falls through, and
/// that loop returns for any distribution with positive mass -- which the
/// caller guarantees. So it had never run, and neither had the error it
/// carries.
///
/// The guarantee is real and the function is still a function. It is private,
/// takes a plain slice, and returns an error for the empty case that the rest
/// of the file relies on never happening; presenting it that slice costs one
/// line and turns "cannot happen" into "does the right thing when it does".
#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{bubble_up, identifier, last_index, walk_top_k, Candidate};
    use crate::error::TransformerError;

    fn candidate(probability: f32, index: usize) -> Candidate {
        Candidate { probability, index }
    }

    /// The residual path is not a rounding curiosity, it is the top of the
    /// range.
    ///
    /// `target` is `uniform * mass`, and the loop returns only on
    /// `target < accumulated`. At `uniform = 1.0` the target IS the mass, so
    /// the comparison is false at every step including the last and the loop
    /// runs out. The marker on that line called this "floating-point mass that
    /// rounds below the target", which made it sound unreachable; a uniform
    /// draw of exactly 1.0 reaches it every time.
    #[test]
    fn a_uniform_at_the_top_of_the_range_falls_through_to_the_residual() {
        let probabilities = [0.25_f32, 0.25, 0.25, 0.25];
        let chosen = walk_top_k(&probabilities, 4, 1.0).expect("the residual choice");
        assert!(
            chosen < 4,
            "the residual must still be one of the candidates, got {chosen}"
        );
    }

    /// The sift's bound check, reached by the caller it exists for.
    ///
    /// Every real caller passes a position it just wrote to, which is why the
    /// arm is unreachable in the crate. It is not unreachable in the function:
    /// a position past the end makes the first `get` return `None`, and the
    /// sift must return rather than index.
    #[test]
    fn the_sift_returns_on_a_position_outside_the_array_rather_than_indexing() {
        let mut candidates = [candidate(0.25, 0), candidate(0.5, 1)];
        bubble_up(&mut candidates, 99);
        assert_eq!(
            candidates.first().map(|entry| entry.index),
            Some(0),
            "an out-of-range sift must leave the array alone"
        );
        assert_eq!(candidates.get(1).map(|entry| entry.index), Some(1));
    }

    #[test]
    fn the_last_candidate_is_the_residual_choice() {
        // The loop falls through only when floating-point mass rounds below
        // the target, and the honest answer then is the last survivor rather
        // than a panic or token 0. Token 0 is a real token in every vocabulary
        // this crate accepts, so silently returning it would be a sampler that
        // occasionally emits a specific wrong word.
        let selected = [candidate(0.5, 11), candidate(0.3, 22), candidate(0.2, 33)];
        assert_eq!(last_index(&selected), Ok(33));

        // One candidate is still the last one.
        assert_eq!(last_index(&[candidate(1.0, 7)]), Ok(7));
    }

    #[test]
    fn an_empty_selection_is_refused_as_a_top_k_error() {
        // `top_k` is validated to be at least 1, so this cannot arrive from
        // the public API. If it ever does, the error names the parameter that
        // would have to be wrong -- which is the difference between a bug
        // report that says InvalidTopK and one that says "it panicked".
        assert_eq!(last_index(&[]), Err(TransformerError::InvalidTopK));
    }

    #[test]
    fn an_index_past_u32_is_refused_rather_than_truncated() {
        // Token identifiers are u32 on the wire. On a 64-bit host a `usize`
        // index can exceed that, and truncating would name a different token
        // rather than fail.
        assert_eq!(identifier(0), Ok(0));
        assert_eq!(identifier(u32::MAX as usize), Ok(u32::MAX));
        #[cfg(target_pointer_width = "64")]
        assert_eq!(
            identifier(u32::MAX as usize + 1),
            Err(TransformerError::TokenOutOfRange)
        );
    }
}
