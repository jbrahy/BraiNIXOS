//! The required tensor-name set for `arch_id = 1` (§6.2) and the header/table
//! shape cross-checks (§5.3).
//!
//! A tensor name is an **opaque label matched against a compile-time set**
//! (`INV-MODEL-001`, `INV-MODEL-003`). It is compared, never interpreted: it
//! never names a file, a device, or an object, it is never used as an index,
//! and it is never emitted anywhere. The only thing this module does with a
//! name is decide which of a fixed set of slots it is, and refuse it if it is
//! none of them.
//!
//! **The set is exact in both directions.** A missing tensor denies (rule T7)
//! and an extra one denies (rule T6): there is no "unknown tensor, ignore it"
//! path, because a blob carrying tensors the engine will not read is a blob
//! whose bytes are unaccounted for at the semantic level even though they are
//! accounted for at the byte level.
//!
//! Membership doubles as the duplicate check (rule T5): a slot that is already
//! occupied is a duplicate, which is what makes duplicate detection a single
//! forward pass with a fixed 152-byte bitmap instead of a quadratic scan over
//! 64-byte names.

use crate::error::Bxw1Error;
use crate::header::Header;
use crate::table::Record;
use crate::{Dtype, BXW1_MAX_LAYERS};

/// Tensors in one transformer block (§6.2).
pub(crate) const TENSORS_PER_LAYER: u32 = 9;

/// Slots not attached to a layer: `tok_embeddings`, `norm`, `output`.
const GLOBAL_SLOTS: u32 = 3;

/// Bits the presence bitmap must hold: every global slot plus every slot of
/// every permitted layer.
const MAX_SLOTS: usize = (GLOBAL_SLOTS + BXW1_MAX_LAYERS * TENSORS_PER_LAYER) as usize;

/// Bits per bitmap word.
const WORD_BITS: usize = 64;

/// Words in the presence bitmap: `ceil(MAX_SLOTS / 64)`.
const BITMAP_WORDS: usize = MAX_SLOTS.div_ceil(WORD_BITS);

/// The name prefix of every per-layer tensor.
const LAYER_PREFIX: &[u8] = b"layers.";

/// Longest decimal layer index the ceiling admits: `127` is three digits.
const MAX_INDEX_DIGITS: usize = 3;

/// The nine per-layer tensors, in the order their slot bits are assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerTensor {
    AttentionNorm,
    Wq,
    Wk,
    Wv,
    Wo,
    FfnNorm,
    W1,
    W3,
    W2,
}

/// The per-layer name suffixes, paired with the tensor they name.
///
/// The canonical spelling is mandatory (§6.2), which is what makes "duplicate
/// name" a complete check: two spellings of one layer are impossible.
const LAYER_SUFFIXES: [(&[u8], LayerTensor); 9] = [
    (b"attention_norm.weight", LayerTensor::AttentionNorm),
    (b"attention.wq.weight", LayerTensor::Wq),
    (b"attention.wk.weight", LayerTensor::Wk),
    (b"attention.wv.weight", LayerTensor::Wv),
    (b"attention.wo.weight", LayerTensor::Wo),
    (b"ffn_norm.weight", LayerTensor::FfnNorm),
    (b"feed_forward.w1.weight", LayerTensor::W1),
    (b"feed_forward.w3.weight", LayerTensor::W3),
    (b"feed_forward.w2.weight", LayerTensor::W2),
];

/// One member of the required set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    TokEmbeddings,
    Norm,
    Output,
    Layer(u32, LayerTensor),
}

impl Slot {
    /// The slot's bit in the presence bitmap.
    fn bit(self) -> Result<usize, Bxw1Error> {
        let index = match self {
            Self::TokEmbeddings => 0,
            Self::Norm => 1,
            Self::Output => 2,
            Self::Layer(layer, tensor) => layer
                .checked_mul(TENSORS_PER_LAYER)
                .and_then(|base| base.checked_add(tensor as u32))
                .and_then(|offset| offset.checked_add(GLOBAL_SLOTS))
                .ok_or(Bxw1Error::UnknownTensorName)?,
        };
        usize::try_from(index).map_err(|_| Bxw1Error::UnknownTensorName)
    }

    /// Whether the slot's tensor may only be `F32` (rule D2).
    ///
    /// Norm weights are `F32`-only: they are `d_model` elements each and they
    /// multiply an entire activation vector, so quantizing them trades a
    /// rounding error across every element for a saving that does not appear
    /// in the bandwidth arithmetic at all (§6.2).
    fn f32_only(self) -> bool {
        matches!(
            self,
            Self::Norm | Self::Layer(_, LayerTensor::AttentionNorm | LayerTensor::FfnNorm)
        )
    }

    /// The shape the header requires this tensor to have (§5.3).
    ///
    /// Every product is checked, though rule H14's per-field bounds already
    /// make overflow unreachable.
    fn expected_dims(self, header: &Header) -> Result<([u64; 2], usize), Bxw1Error> {
        let d_model = u64::from(header.d_model);
        let d_ffn = u64::from(header.d_ffn);
        let vocab = u64::from(header.vocab_size);
        let q_width = u64::from(header.n_heads)
            .checked_mul(u64::from(header.d_head))
            .ok_or(Bxw1Error::HeadWidthProductOverflow)?;
        let kv_width = u64::from(header.n_kv_heads)
            .checked_mul(u64::from(header.d_head))
            .ok_or(Bxw1Error::HeadWidthProductOverflow)?;

        let shape = match self {
            Self::TokEmbeddings | Self::Output => ([vocab, d_model], 2),
            Self::Norm => ([d_model, 0], 1),
            Self::Layer(_, tensor) => match tensor {
                LayerTensor::AttentionNorm | LayerTensor::FfnNorm => ([d_model, 0], 1),
                LayerTensor::Wq => ([q_width, d_model], 2),
                LayerTensor::Wk | LayerTensor::Wv => ([kv_width, d_model], 2),
                LayerTensor::Wo => ([d_model, q_width], 2),
                LayerTensor::W1 | LayerTensor::W3 => ([d_ffn, d_model], 2),
                LayerTensor::W2 => ([d_model, d_ffn], 2),
            },
        };
        Ok(shape)
    }
}

/// The fixed-size presence bitmap over the required set.
///
/// 152 bytes on the stack, sized from `BXW1_MAX_LAYERS` at compile time. No
/// allocation, and no quantity from the blob sizes it.
pub(crate) struct SlotSet {
    words: [u64; BITMAP_WORDS],
}

impl SlotSet {
    /// An empty set.
    pub(crate) fn new() -> Self {
        Self {
            words: [0; BITMAP_WORDS],
        }
    }

    /// Marks a slot present, refusing a slot that is already occupied
    /// (rule T5).
    fn insert(&mut self, bit: usize) -> Result<(), Bxw1Error> {
        let (index, mask) = locate(bit)?;
        let word = self
            .words
            .get_mut(index)
            .ok_or(Bxw1Error::UnknownTensorName)?;
        if *word & mask != 0 {
            return Err(Bxw1Error::DuplicateTensorName);
        }
        *word |= mask;
        Ok(())
    }

    /// Whether a slot is present.
    fn contains(&self, bit: usize) -> Result<bool, Bxw1Error> {
        let (index, mask) = locate(bit)?;
        let word = self.words.get(index).ok_or(Bxw1Error::UnknownTensorName)?;
        Ok(*word & mask != 0)
    }

    /// Rule T7 and rule H21's second half: every required name is present.
    ///
    /// An untied model missing `output.weight` lands here rather than in a
    /// variant of its own, because "the blob does not carry a tensor the
    /// architecture requires" is exactly what happened.
    pub(crate) fn require_complete(&self, header: &Header) -> Result<(), Bxw1Error> {
        self.require(Slot::TokEmbeddings)?;
        self.require(Slot::Norm)?;
        if !header.tied_output {
            self.require(Slot::Output)?;
        }
        for layer in 0..header.n_layers {
            for (_, tensor) in LAYER_SUFFIXES {
                self.require(Slot::Layer(layer, tensor))?;
            }
        }
        Ok(())
    }

    fn require(&self, slot: Slot) -> Result<(), Bxw1Error> {
        if self.contains(slot.bit()?)? {
            Ok(())
        } else {
            Err(Bxw1Error::MissingRequiredTensor)
        }
    }
}

/// Word index and bit mask for a slot bit.
fn locate(bit: usize) -> Result<(usize, u64), Bxw1Error> {
    let index = bit
        .checked_div(WORD_BITS)
        .ok_or(Bxw1Error::UnknownTensorName)?;
    let shift = bit
        .checked_rem(WORD_BITS)
        .ok_or(Bxw1Error::UnknownTensorName)?;
    let mask = 1_u64
        .checked_shl(u32::try_from(shift).map_err(|_| Bxw1Error::UnknownTensorName)?)
        .ok_or(Bxw1Error::UnknownTensorName)?;
    Ok((index, mask))
}

/// Admits one record into the required set, applying rules T5, T6, D2, H21
/// and C8.
pub(crate) fn admit(
    record: &Record<'_>,
    header: &Header,
    seen: &mut SlotSet,
) -> Result<(), Bxw1Error> {
    let slot = classify(record.name, header.n_layers).ok_or(Bxw1Error::UnknownTensorName)?;

    // Rule H21: with the tied flag set, `output.weight` must be absent. The
    // format expresses weight tying with a flag rather than with two records
    // pointing at one extent, which is what preserves the disjoint-extent rule
    // (§6.3).
    if slot == Slot::Output && header.tied_output {
        return Err(Bxw1Error::TiedOutputWeightPresent);
    }
    seen.insert(slot.bit()?)?;

    if slot.f32_only() && record.dtype != Dtype::F32 {
        return Err(Bxw1Error::DtypeNotPermittedForName);
    }

    // Rule C8: header and table describe overlapping facts, so a disagreement
    // denies with no precedence rule (`INV-PARSE-004`). The loader does not
    // prefer the header over the shape or the reverse.
    let (expected, rank) = slot.expected_dims(header)?;
    if record.rank != rank {
        return Err(Bxw1Error::ShapeDisagreesWithHeader);
    }
    for (declared, wanted) in record.dims.iter().zip(expected.iter()).take(rank) {
        if declared != wanted {
            return Err(Bxw1Error::ShapeDisagreesWithHeader);
        }
    }
    Ok(())
}

/// Matches a name against the required set. `None` means "not a member".
fn classify(name: &[u8], n_layers: u32) -> Option<Slot> {
    match name {
        b"tok_embeddings.weight" => return Some(Slot::TokEmbeddings),
        b"norm.weight" => return Some(Slot::Norm),
        b"output.weight" => return Some(Slot::Output),
        _ => {}
    }

    let rest = name.strip_prefix(LAYER_PREFIX)?;
    let dot = rest.iter().position(|byte| *byte == b'.')?;
    let digits = rest.get(..dot)?;
    let suffix = rest.get(dot.checked_add(1)?..)?;
    let layer = parse_layer_index(digits)?;
    // A layer index at or above `n_layers` is not in the required set: §5.3
    // demands indices `0 .. n_layers` with no gap and no extra.
    if layer >= n_layers {
        return None;
    }
    LAYER_SUFFIXES
        .iter()
        .find(|(candidate, _)| *candidate == suffix)
        .map(|(_, tensor)| Slot::Layer(layer, *tensor))
}

/// Parses `{l}` as decimal with **no leading zeros** (§6.2).
///
/// The canonical spelling is mandatory: admitting `01` as well as `1` would
/// give one layer two names, and the duplicate check would no longer be
/// complete.
fn parse_layer_index(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > MAX_INDEX_DIGITS {
        return None;
    }
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return None;
    }
    let mut value: u32 = 0;
    for byte in digits {
        let digit = byte.checked_sub(b'0')?;
        if digit > 9 {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(digit))?;
    }
    Some(value)
}
