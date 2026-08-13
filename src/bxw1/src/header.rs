//! The 256-byte header (§3.1) and every rule of §7.2.
//!
//! The decoder is **total from the first byte**: it requires exactly 256
//! bytes, reads exactly 256 bytes, every field is at a compile-time offset,
//! and every deviation is a single denial. `tensor_count` is the only field
//! that governs how much is read afterwards, and it is bounds-checked against
//! a `const` before it is used for anything (rule H5).

use crate::error::Bxw1Error;
use crate::raw::{
    is_positive_finite, read_field, read_u16_le, read_u32_le, read_u64_le, DIGEST_LEN,
};
use crate::{
    RopePairing, BXW1_ALIGN_MASK, BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU, BXW1_FLAG_TIED_OUTPUT,
    BXW1_HEADER_BYTES, BXW1_MAGIC, BXW1_MAX_BLOB_BYTES, BXW1_MAX_D_FFN, BXW1_MAX_D_HEAD,
    BXW1_MAX_D_MODEL, BXW1_MAX_HEADS, BXW1_MAX_LAYERS, BXW1_MAX_SEQ_LEN, BXW1_MAX_TENSORS,
    BXW1_MAX_VOCAB, BXW1_MAX_VOCAB_BLOB_BYTES, BXW1_TENSOR_RECORD_BYTES, BXW1_VERSION_MAJOR,
    BXW1_VERSION_MINOR,
};

/// Field offsets, absolute from the first byte of the blob (§3.1).
mod offset {
    pub(super) const MAGIC: usize = 0;
    pub(super) const VERSION_MAJOR: usize = 4;
    pub(super) const VERSION_MINOR: usize = 6;
    pub(super) const FLAGS: usize = 8;
    pub(super) const TENSOR_COUNT: usize = 12;
    pub(super) const TOTAL_SIZE: usize = 16;
    pub(super) const TENSOR_TABLE_OFF: usize = 24;
    pub(super) const TENSOR_DATA_OFF: usize = 32;
    pub(super) const TENSOR_DATA_LEN: usize = 40;
    pub(super) const RESERVED_0: usize = 48;
    pub(super) const RESERVED_1: usize = 56;
    pub(super) const TENSOR_TABLE_DIGEST: usize = 64;
    pub(super) const ARCH_ID: usize = 96;
    pub(super) const N_LAYERS: usize = 100;
    pub(super) const D_MODEL: usize = 104;
    pub(super) const N_HEADS: usize = 108;
    pub(super) const N_KV_HEADS: usize = 112;
    pub(super) const D_HEAD: usize = 116;
    pub(super) const D_FFN: usize = 120;
    pub(super) const VOCAB_SIZE: usize = 124;
    pub(super) const MAX_SEQ_LEN: usize = 128;
    pub(super) const ROPE_THETA_BITS: usize = 132;
    pub(super) const NORM_EPS_BITS: usize = 136;
    pub(super) const ROPE_DIM: usize = 140;
    pub(super) const BOS_TOKEN_ID: usize = 144;
    pub(super) const EOS_TOKEN_ID: usize = 148;
    pub(super) const ROPE_PAIRING: usize = 152;
    pub(super) const RESERVED_3: usize = 156;
    pub(super) const VOCAB_DIGEST: usize = 160;
    pub(super) const VOCAB_LEN: usize = 192;
    pub(super) const RESERVED_TAIL: usize = 200;
    pub(super) const RESERVED_TAIL_LEN: usize = 56;
}

/// Lowest accepted `rope_theta`, §5.1.
const ROPE_THETA_MIN: f32 = 1.0e2;
/// Highest accepted `rope_theta`, §5.1.
const ROPE_THETA_MAX: f32 = 1.0e8;
/// Lowest accepted `norm_eps`, §5.1.
const NORM_EPS_MIN: f32 = 1.0e-8;
/// Highest accepted `norm_eps`, §5.1.
const NORM_EPS_MAX: f32 = 1.0e-1;

/// A fully validated BXW1 header.
///
/// Construction is the validation: holding one of these means every rule of
/// §7.2 passed. Every field is the value the blob declared, in the units §5.1
/// gives; nothing here has been defaulted, rounded, or inferred.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    /// `BXW1_FLAG_TIED_OUTPUT`: the output projection reuses
    /// `tok_embeddings.weight` and `output.weight` is absent (§6.3).
    pub tied_output: bool,
    /// Number of records in the tensor table.
    pub tensor_count: u32,
    /// Total blob bytes, header inclusive. Equal to the slice's length.
    pub total_size: u64,
    /// Byte offset of the first tensor extent. `BXW1_ALIGN`-aligned.
    pub tensor_data_off: u64,
    /// Total bytes of the tensor-data region, pads included.
    pub tensor_data_len: u64,
    /// SHA-256 over the `tensor_count × 160` table bytes at offset 256.
    pub tensor_table_digest: [u8; DIGEST_LEN],
    /// Enumerated architecture family. Always
    /// [`BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU`]: no other value is accepted, and
    /// the field is carried so a caller can log what it validated.
    pub arch_id: u32,
    /// Number of transformer blocks.
    pub n_layers: u32,
    /// Residual-stream width. Equal to `n_heads × d_head`.
    pub d_model: u32,
    /// Query heads.
    pub n_heads: u32,
    /// Key/value heads. Divides `n_heads` exactly.
    pub n_kv_heads: u32,
    /// Per-head width.
    pub d_head: u32,
    /// Feed-forward inner width.
    pub d_ffn: u32,
    /// Token count.
    pub vocab_size: u32,
    /// Maximum context length in tokens the weights support.
    pub max_seq_len: u32,
    /// RoPE base θ, in `θ_i = rope_theta^(−2i / rope_dim)`. A positive finite
    /// normal in `1.0e2 ..= 1.0e8`.
    pub rope_theta: f32,
    /// Normalization ε, added to the mean square **before** the reciprocal
    /// square root. A positive finite normal in `1.0e-8 ..= 1.0e-1`.
    pub norm_eps: f32,
    /// Leading per-head dimensions RoPE rotates. Even, and at most `d_head`;
    /// the remaining dimensions pass through **unrotated** (§5.1).
    pub rope_dim: u32,
    /// Which two components form a rotated pair. Decoded at the `u32`
    /// boundary, so an unrecognized pairing is unrepresentable past it.
    pub rope_pairing: RopePairing,
    /// Beginning-of-sequence token. Below `vocab_size`.
    pub bos_token_id: u32,
    /// End-of-sequence token. Below `vocab_size`.
    pub eos_token_id: u32,
    /// SHA-256 of the tokenizer vocabulary blob (§5.4). Carried, not verified:
    /// verifying it is stage S9 and needs the vocabulary, which this crate
    /// never sees.
    pub vocab_digest: [u8; DIGEST_LEN],
    /// The tokenizer vocabulary blob's exact byte length.
    pub vocab_len: u64,
}

impl Header {
    /// Parses and validates the header, applying rules H1-H22 in order.
    ///
    /// `length` is the authoritative object length -- the slice's own -- and
    /// `region_capacity` is the reserved `WEIGHTS_REGION` size in bytes. Both
    /// are the caller's, never the blob's (§8.3).
    pub(crate) fn parse(blob: &[u8], length: u64, region_capacity: u64) -> Result<Self, Bxw1Error> {
        let identity = Identity::read(blob)?;
        let layout = Layout::read(blob, length, region_capacity, identity.tensor_count)?;
        let meta = Metadata::read(blob)?;
        require_zero_field(blob, offset::RESERVED_TAIL, offset::RESERVED_TAIL_LEN)?;

        let tied_output = identity.flags & BXW1_FLAG_TIED_OUTPUT != 0;
        require_arch_tensor_count(identity.tensor_count, meta.n_layers, tied_output)?;

        Ok(Self {
            tied_output,
            tensor_count: identity.tensor_count,
            total_size: layout.total_size,
            tensor_data_off: layout.tensor_data_off,
            tensor_data_len: layout.tensor_data_len,
            tensor_table_digest: layout.tensor_table_digest,
            arch_id: meta.arch_id,
            n_layers: meta.n_layers,
            d_model: meta.d_model,
            n_heads: meta.n_heads,
            n_kv_heads: meta.n_kv_heads,
            d_head: meta.d_head,
            d_ffn: meta.d_ffn,
            vocab_size: meta.vocab_size,
            max_seq_len: meta.max_seq_len,
            rope_theta: meta.rope_theta,
            norm_eps: meta.norm_eps,
            rope_dim: meta.rope_dim,
            rope_pairing: meta.rope_pairing,
            bos_token_id: meta.bos_token_id,
            eos_token_id: meta.eos_token_id,
            vocab_digest: meta.vocab_digest,
            vocab_len: meta.vocab_len,
        })
    }

    /// Byte offset just past the last tensor-table record.
    ///
    /// Recomputed rather than stored: `tensor_count` is bounded by rule H5, so
    /// the multiply cannot overflow, and a stored copy would be a second source
    /// of the same fact.
    pub(crate) fn table_end(&self) -> Result<u64, Bxw1Error> {
        table_end(self.tensor_count)
    }
}

/// Format identity and the counts that govern later reads (rules H2-H5).
struct Identity {
    flags: u32,
    tensor_count: u32,
}

impl Identity {
    fn read(blob: &[u8]) -> Result<Self, Bxw1Error> {
        let magic =
            read_field(blob, offset::MAGIC, BXW1_MAGIC.len()).ok_or(Bxw1Error::TruncatedHeader)?;
        if magic != BXW1_MAGIC {
            return Err(Bxw1Error::BadMagic);
        }

        let major = read_u16_le(blob, offset::VERSION_MAJOR).ok_or(Bxw1Error::TruncatedHeader)?;
        let minor = read_u16_le(blob, offset::VERSION_MINOR).ok_or(Bxw1Error::TruncatedHeader)?;
        if major != BXW1_VERSION_MAJOR || minor != BXW1_VERSION_MINOR {
            return Err(Bxw1Error::UnsupportedVersion);
        }

        let flags = read_u32_le(blob, offset::FLAGS).ok_or(Bxw1Error::TruncatedHeader)?;
        if flags & !BXW1_FLAG_TIED_OUTPUT != 0 {
            return Err(Bxw1Error::ReservedFlagBitSet);
        }

        let tensor_count =
            read_u32_le(blob, offset::TENSOR_COUNT).ok_or(Bxw1Error::TruncatedHeader)?;
        if tensor_count == 0 {
            return Err(Bxw1Error::ZeroTensorCount);
        }
        if tensor_count > BXW1_MAX_TENSORS {
            return Err(Bxw1Error::TensorCountExceedsCeiling);
        }

        Ok(Self {
            flags,
            tensor_count,
        })
    }
}

/// Sizes and offsets, and the table digest (rules H6-H12).
struct Layout {
    total_size: u64,
    tensor_data_off: u64,
    tensor_data_len: u64,
    tensor_table_digest: [u8; DIGEST_LEN],
}

impl Layout {
    fn read(
        blob: &[u8],
        length: u64,
        region_capacity: u64,
        tensor_count: u32,
    ) -> Result<Self, Bxw1Error> {
        let total_size = read_u64_le(blob, offset::TOTAL_SIZE).ok_or(Bxw1Error::TruncatedHeader)?;
        if total_size < BXW1_HEADER_BYTES {
            return Err(Bxw1Error::TotalSizeBelowHeader);
        }
        if total_size > BXW1_MAX_BLOB_BYTES {
            return Err(Bxw1Error::TotalSizeExceedsMaxSize);
        }
        if total_size > region_capacity {
            return Err(Bxw1Error::TotalSizeExceedsRegionCapacity);
        }
        if total_size != length {
            return Err(Bxw1Error::TotalSizeMismatch);
        }

        let table_off =
            read_u64_le(blob, offset::TENSOR_TABLE_OFF).ok_or(Bxw1Error::TruncatedHeader)?;
        if table_off != BXW1_HEADER_BYTES {
            return Err(Bxw1Error::TensorTableOffsetNot256);
        }
        let table_end = table_end(tensor_count)?;
        if table_end > total_size {
            return Err(Bxw1Error::TensorTableExceedsBlob);
        }

        let data_off =
            read_u64_le(blob, offset::TENSOR_DATA_OFF).ok_or(Bxw1Error::TruncatedHeader)?;
        if data_off & BXW1_ALIGN_MASK != 0 {
            return Err(Bxw1Error::TensorDataOffsetMisaligned);
        }
        if data_off < table_end {
            return Err(Bxw1Error::TensorDataOffsetBeforeTable);
        }
        if data_off >= total_size {
            return Err(Bxw1Error::TensorDataOffsetPastBlob);
        }
        // Ordered by the check above, so the subtraction cannot underflow; it
        // is checked anyway because ordering is an argument and `checked_sub`
        // is a property of the program (§7.6).
        let gap = data_off
            .checked_sub(table_end)
            .ok_or(Bxw1Error::TensorDataOffsetBeforeTable)?;
        if gap > BXW1_ALIGN_MASK {
            return Err(Bxw1Error::TableToDataGapTooLarge);
        }

        let data_len =
            read_u64_le(blob, offset::TENSOR_DATA_LEN).ok_or(Bxw1Error::TruncatedHeader)?;
        let data_end = data_off
            .checked_add(data_len)
            .ok_or(Bxw1Error::TensorDataExtentOverflow)?;
        if data_end != total_size {
            return Err(Bxw1Error::TensorDataExtentNotBlobEnd);
        }

        require_zero_u64(blob, offset::RESERVED_0)?;
        require_zero_u64(blob, offset::RESERVED_1)?;

        let digest_field = read_field(blob, offset::TENSOR_TABLE_DIGEST, DIGEST_LEN)
            .ok_or(Bxw1Error::TruncatedHeader)?;
        Ok(Self {
            total_size,
            tensor_data_off: data_off,
            tensor_data_len: data_len,
            tensor_table_digest: copy_digest(digest_field)?,
        })
    }
}

/// Model metadata and the tokenizer binding (rules H13-H20).
struct Metadata {
    arch_id: u32,
    n_layers: u32,
    d_model: u32,
    n_heads: u32,
    n_kv_heads: u32,
    d_head: u32,
    d_ffn: u32,
    vocab_size: u32,
    max_seq_len: u32,
    rope_theta: f32,
    norm_eps: f32,
    rope_dim: u32,
    rope_pairing: RopePairing,
    bos_token_id: u32,
    eos_token_id: u32,
    vocab_digest: [u8; DIGEST_LEN],
    vocab_len: u64,
}

impl Metadata {
    fn read(blob: &[u8]) -> Result<Self, Bxw1Error> {
        let arch_id = read_u32_le(blob, offset::ARCH_ID).ok_or(Bxw1Error::TruncatedHeader)?;
        if arch_id != BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU {
            return Err(Bxw1Error::UnknownArchId);
        }

        let dims = Dimensions::read(blob)?;
        let (rope_theta, norm_eps) = read_floats(blob)?;
        let rope_dim = read_u32_le(blob, offset::ROPE_DIM).ok_or(Bxw1Error::TruncatedHeader)?;
        if rope_dim == 0 || rope_dim > dims.d_head {
            return Err(Bxw1Error::RopeDimOutOfRange);
        }
        if rope_dim & 1 != 0 {
            return Err(Bxw1Error::RopeDimOdd);
        }
        let rope_pairing = RopePairing::from_bxw1(
            read_u32_le(blob, offset::ROPE_PAIRING).ok_or(Bxw1Error::TruncatedHeader)?,
        )?;

        let bos_token_id =
            read_u32_le(blob, offset::BOS_TOKEN_ID).ok_or(Bxw1Error::TruncatedHeader)?;
        if bos_token_id >= dims.vocab_size {
            return Err(Bxw1Error::BosTokenOutOfRange);
        }
        let eos_token_id =
            read_u32_le(blob, offset::EOS_TOKEN_ID).ok_or(Bxw1Error::TruncatedHeader)?;
        if eos_token_id >= dims.vocab_size {
            return Err(Bxw1Error::EosTokenOutOfRange);
        }
        require_zero_u32(blob, offset::RESERVED_3)?;

        let vocab_digest = copy_digest(
            read_field(blob, offset::VOCAB_DIGEST, DIGEST_LEN).ok_or(Bxw1Error::TruncatedHeader)?,
            // COVERAGE-EXEMPT: copy_digest cannot fail here: read_field above already returned exactly DIGEST_LEN bytes or None.
        )?;
        let vocab_len = read_u64_le(blob, offset::VOCAB_LEN).ok_or(Bxw1Error::TruncatedHeader)?;
        if vocab_len == 0 {
            return Err(Bxw1Error::VocabLenZero);
        }
        if vocab_len > BXW1_MAX_VOCAB_BLOB_BYTES {
            return Err(Bxw1Error::VocabLenExceedsCeiling);
        }

        Ok(Self {
            arch_id,
            n_layers: dims.n_layers,
            d_model: dims.d_model,
            n_heads: dims.n_heads,
            n_kv_heads: dims.n_kv_heads,
            d_head: dims.d_head,
            d_ffn: dims.d_ffn,
            vocab_size: dims.vocab_size,
            max_seq_len: dims.max_seq_len,
            rope_theta,
            norm_eps,
            rope_dim,
            rope_pairing,
            bos_token_id,
            eos_token_id,
            vocab_digest,
            vocab_len,
        })
    }
}

/// The integer hyperparameters (rules H14-H16).
struct Dimensions {
    n_layers: u32,
    d_model: u32,
    n_heads: u32,
    n_kv_heads: u32,
    d_head: u32,
    d_ffn: u32,
    vocab_size: u32,
    max_seq_len: u32,
}

impl Dimensions {
    /// Every field is bounded **independently**, before any of them is
    /// multiplied by another (rule H14).
    fn read(blob: &[u8]) -> Result<Self, Bxw1Error> {
        let n_layers = bounded(
            blob,
            offset::N_LAYERS,
            BXW1_MAX_LAYERS,
            Bxw1Error::NLayersOutOfRange,
        )?;
        let d_model = bounded(
            blob,
            offset::D_MODEL,
            BXW1_MAX_D_MODEL,
            Bxw1Error::DModelOutOfRange,
        )?;
        let n_heads = bounded(
            blob,
            offset::N_HEADS,
            BXW1_MAX_HEADS,
            Bxw1Error::NHeadsOutOfRange,
        )?;
        let n_kv_heads = bounded(
            blob,
            offset::N_KV_HEADS,
            BXW1_MAX_HEADS,
            Bxw1Error::NKvHeadsOutOfRange,
        )?;
        let d_head = bounded(
            blob,
            offset::D_HEAD,
            BXW1_MAX_D_HEAD,
            Bxw1Error::DHeadOutOfRange,
        )?;
        let d_ffn = bounded(
            blob,
            offset::D_FFN,
            BXW1_MAX_D_FFN,
            Bxw1Error::DFfnOutOfRange,
        )?;
        let vocab_size = bounded(
            blob,
            offset::VOCAB_SIZE,
            BXW1_MAX_VOCAB,
            Bxw1Error::VocabSizeOutOfRange,
        )?;
        let max_seq_len = bounded(
            blob,
            offset::MAX_SEQ_LEN,
            BXW1_MAX_SEQ_LEN,
            Bxw1Error::MaxSeqLenOutOfRange,
        )?;

        if n_kv_heads > n_heads {
            return Err(Bxw1Error::KvHeadsExceedHeads);
        }
        if !n_heads.is_multiple_of(n_kv_heads) {
            return Err(Bxw1Error::HeadsNotDivisibleByKvHeads);
        }
        let head_width = n_heads
            .checked_mul(d_head)
            .ok_or(Bxw1Error::HeadWidthProductOverflow)?;
        if head_width != d_model {
            return Err(Bxw1Error::HeadWidthNotDModel);
        }

        Ok(Self {
            n_layers,
            d_model,
            n_heads,
            n_kv_heads,
            d_head,
            d_ffn,
            vocab_size,
            max_seq_len,
        })
    }
}

/// Reads a `u32` hyperparameter and bounds it to `1 ..= ceiling` (rule H14).
///
/// The caller supplies the field's own out-of-range variant, so every refused
/// hyperparameter is auditable by name rather than by a shared "bad metadata"
/// error.
fn bounded(
    blob: &[u8],
    at: usize,
    ceiling: u32,
    out_of_range: Bxw1Error,
) -> Result<u32, Bxw1Error> {
    let value = read_u32_le(blob, at).ok_or(Bxw1Error::TruncatedHeader)?;
    if value == 0 || value > ceiling {
        return Err(out_of_range);
    }
    Ok(value)
}

/// Reads `rope_theta` and `norm_eps` (rule H18).
///
/// The bit-pattern class check runs **first**, as integer comparisons, so no
/// float comparison is ever performed against a possible NaN. `+0.0` passes
/// the class check and is then refused by the range check, which is why the
/// range test is not redundant.
fn read_floats(blob: &[u8]) -> Result<(f32, f32), Bxw1Error> {
    let theta_bits =
        read_u32_le(blob, offset::ROPE_THETA_BITS).ok_or(Bxw1Error::TruncatedHeader)?;
    if !is_positive_finite(theta_bits) {
        return Err(Bxw1Error::InvalidRopeTheta);
    }
    let rope_theta = f32::from_bits(theta_bits);
    if !(ROPE_THETA_MIN..=ROPE_THETA_MAX).contains(&rope_theta) {
        return Err(Bxw1Error::RopeThetaOutOfRange);
    }

    let eps_bits = read_u32_le(blob, offset::NORM_EPS_BITS).ok_or(Bxw1Error::TruncatedHeader)?;
    if !is_positive_finite(eps_bits) {
        return Err(Bxw1Error::InvalidNormEps);
    }
    let norm_eps = f32::from_bits(eps_bits);
    if !(NORM_EPS_MIN..=NORM_EPS_MAX).contains(&norm_eps) {
        return Err(Bxw1Error::NormEpsOutOfRange);
    }

    Ok((rope_theta, norm_eps))
}

/// `256 + tensor_count × 160`, checked (rule H9).
fn table_end(tensor_count: u32) -> Result<u64, Bxw1Error> {
    let table_bytes = u64::from(tensor_count)
        .checked_mul(BXW1_TENSOR_RECORD_BYTES)
        .ok_or(Bxw1Error::TensorTableExtentOverflow)?;
    BXW1_HEADER_BYTES
        .checked_add(table_bytes)
        .ok_or(Bxw1Error::TensorTableExtentOverflow)
}

/// `tensor_count` must be exactly the arch's required set size (rule H22).
fn require_arch_tensor_count(
    tensor_count: u32,
    n_layers: u32,
    tied_output: bool,
) -> Result<(), Bxw1Error> {
    let global = if tied_output { 2 } else { 3 };
    let per_layer = n_layers
        .checked_mul(crate::names::TENSORS_PER_LAYER)
        .ok_or(Bxw1Error::TensorCountNotArchRequired)?;
    let required = per_layer
        .checked_add(global)
        .ok_or(Bxw1Error::TensorCountNotArchRequired)?;
    if tensor_count != required {
        return Err(Bxw1Error::TensorCountNotArchRequired);
    }
    Ok(())
}

/// Refuses a nonzero reserved `u32` (rule H12).
fn require_zero_u32(blob: &[u8], at: usize) -> Result<(), Bxw1Error> {
    if read_u32_le(blob, at).ok_or(Bxw1Error::TruncatedHeader)? != 0 {
        return Err(Bxw1Error::ReservedHeaderFieldNonZero);
    }
    Ok(())
}

/// Refuses a nonzero reserved `u64` (rule H12).
fn require_zero_u64(blob: &[u8], at: usize) -> Result<(), Bxw1Error> {
    if read_u64_le(blob, at).ok_or(Bxw1Error::TruncatedHeader)? != 0 {
        return Err(Bxw1Error::ReservedHeaderFieldNonZero);
    }
    Ok(())
}

/// Refuses a nonzero reserved fixed-size field (rule H12).
fn require_zero_field(blob: &[u8], at: usize, length: usize) -> Result<(), Bxw1Error> {
    let field = read_field(blob, at, length).ok_or(Bxw1Error::TruncatedHeader)?;
    if field.iter().any(|byte| *byte != 0) {
        return Err(Bxw1Error::ReservedHeaderFieldNonZero);
    }
    Ok(())
}

/// Copies a 32-byte digest field into an owned array without indexing.
fn copy_digest(field: &[u8]) -> Result<[u8; DIGEST_LEN], Bxw1Error> {
    if field.len() != DIGEST_LEN {
        // COVERAGE-EXEMPT: every caller passes a slice from read_field(.., DIGEST_LEN), which already guarantees the length. Kept so copy_digest is total for any slice.
        return Err(Bxw1Error::TruncatedHeader);
    }
    let mut digest = [0_u8; DIGEST_LEN];
    for (slot, byte) in digest.iter_mut().zip(field.iter()) {
        *slot = *byte;
    }
    Ok(digest)
}
