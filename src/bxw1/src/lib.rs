//! BXW1 model-weight loader — P3-T3.
//!
//! The gate every model weight passes before a tensor kernel sees a byte of
//! it. A BXW1 blob arrives **from disk**, which the project did not write and
//! cannot audit, and it is parsed with more authority than anything from the
//! network — the parse happens before `inferd` launches. It is hostile input
//! on the same footing as a packet (`INV-PARSE-001`), and this crate is the
//! Full-tier parser that treats it that way.
//!
//! The format is specified by
//! [`docs/architecture/BXW1-weight-format.md`](../../../docs/architecture/BXW1-weight-format.md).
//! Every rule identifier in this crate's documentation — `H7`, `D16`, `C2` —
//! is that document's, so a denial can be traced to a line of the
//! specification without reading the decoder.
//!
//! # What this crate guarantees
//!
//! - `#![no_std]`, the crate-level `forbid(unsafe_code)` below, and **no
//!   allocation of any kind** — no heap, no arena, no growable buffer, no
//!   owned copy of a tensor. Every working set is a fixed-size array or a
//!   borrowed slice (`INV-MEM`, `INV-PARSE-001`). The largest fixed structure
//!   is the 152-byte required-name bitmap, whose size comes from
//!   [`BXW1_MAX_LAYERS`] at compile time and from no quantity in the blob.
//! - **Total decoding.** Every malformed input returns a [`Bxw1Error`]. There
//!   is no panicking index, no unchecked `Option` access, and no arithmetic
//!   that can wrap: every operation on a blob-supplied value is checked `u64`
//!   arithmetic, and a value that does not fit **denies** — it never saturates
//!   and never wraps (§7.6).
//! - **Fail closed.** A violation ends the load. Nothing is skipped, nothing
//!   is clamped, no offset is rounded up to an alignment it failed, and no
//!   field is defaulted. Rounding a misaligned offset would shift every
//!   subsequent extent relative to the digests computed over the unshifted
//!   bytes and produce a model that loads, verifies, and computes wrong
//!   numbers (§4.4).
//! - **Validated before use.** Construction *is* the validation: holding a
//!   [`WeightBlob`] means every structural rule passed, the table digest
//!   matched, every per-tensor digest matched, every float bit pattern was
//!   classified as an integer, and every byte of the blob was accounted for.
//!   No accessor can hand out an unverified byte, because there is no way to
//!   build the type without the whole pass having succeeded.
//! - **Zero copy.** [`Tensor::data`] borrows the caller's slice. A tensor's
//!   payload is never copied, moved, or dequantized here — on a
//!   memory-bandwidth-bound machine a gratuitous copy of the weights is the
//!   single most expensive thing a loader could do (§4.5).
//!
//! # What this crate deliberately does not do
//!
//! It is the **decoder**, not `modeld` (§10.0). It does not read storage, does
//! not place bytes in `WEIGHTS_REGION`, does not seal anything, does not emit
//! an audit event, and holds no capability. Specifically:
//!
//! - **Stage S1's copy is the caller's.** This crate takes a `&[u8]` that is
//!   already resident and validates it in place, which is the ordering §10.1
//!   requires: parsing storage first and copying afterwards would leave a
//!   time-of-check/time-of-use gap.
//! - **Stage S8 is not here.** The whole-blob digest is computed and returned
//!   ([`WeightBlob::blob_digest`]); comparing it against the digest named by
//!   `LoadWeights` (rule C5) and verifying the detached Ed25519 signature over
//!   it (rule C9) belong to `modeld`, which has the key material this crate
//!   must not hold.
//! - **Stage S9 is not here.** `vocab_digest` and `vocab_len` are validated as
//!   *fields* and exposed on the [`Header`]; verifying them against an actual
//!   vocabulary blob needs the tokenizer (P3-T5), which does not exist.
//! - **Stage S10's seal is not here** and is P3-T2's. §9.3 item 5 states what
//!   this crate's integrity claim loses if that obligation is not discharged:
//!   verification is sound only because the region is exclusively owned while
//!   writable and read-only before anyone else sees it.
//!
//! # Region capacity is the caller's, never the blob's
//!
//! [`WeightBlob::parse`] takes `region_capacity` as an explicit argument and
//! has no default. `INV-MEM` admits no growing allocator for weights: no
//! quantity in a blob ever sizes, extends, or selects a region (§8.3). The
//! capacity is compared against, never derived from, the blob — and it is a
//! parameter rather than a `const` here because `WEIGHTS_REGION` is sized at
//! build time by P3-T2, which has not landed.
//!
//! # Example
//!
//! ```
//! use brainix_bxw1::{Bxw1Error, Dtype, WeightBlob};
//!
//! fn embedding_bytes(blob: &[u8], region_capacity: u64) -> Result<usize, Bxw1Error> {
//!     let weights = WeightBlob::parse(blob, region_capacity)?;
//!     let tensor = weights.tensor_by_name(b"tok_embeddings.weight")?;
//!     assert_eq!(tensor.dtype(), Dtype::Q8);
//!     Ok(tensor.data().len())
//! }
//! ```

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod header;
mod names;
mod payload;
mod raw;
mod table;

pub use crate::error::Bxw1Error;
pub use crate::header::Header;

use crate::names::SlotSet;
use crate::raw::{slice_at, DIGEST_LEN};
use crate::table::{require_no_trailing_bytes, walk_extent, Record};

/// The 4-byte format tag.
pub const BXW1_MAGIC: &[u8] = b"BXW1";

/// Accepted `version_major`. Exact match, not a negotiation: a v2 is a new
/// magic and a new document (§3.1).
pub const BXW1_VERSION_MAJOR: u16 = 1;

/// Accepted `version_minor`. Exact match.
pub const BXW1_VERSION_MINOR: u16 = 0;

/// Bytes in the fixed header. No variable-length field lives inside it, which
/// is what makes the header decoder total from the first byte.
pub const BXW1_HEADER_BYTES: u64 = 256;

/// Bytes in one fixed tensor-table record.
pub const BXW1_TENSOR_RECORD_BYTES: u64 = 160;

/// Table bound. At 160 bytes a record the table is at most 640 KiB.
pub const BXW1_MAX_TENSORS: u32 = 4096;

/// Dimension slots per record.
pub const BXW1_MAX_RANK: u16 = 4;

/// Per-dimension bound, checked before the product is formed (rule D6).
pub const BXW1_MAX_DIM: u64 = 1 << 28;

/// Running-product bound for the element fold (rule D7).
///
/// Chosen so that even at `Q8_0`'s 1.125 bytes per element the derived length
/// exceeds [`BXW1_MAX_BLOB_BYTES`] and is caught by the byte check. It bounds
/// the multiply loop; it is not the operative limit.
pub const BXW1_MAX_ELEMENTS: u64 = 1 << 35;

/// Tensor-data alignment: the reference machine's cache-line size, not its
/// page size. `16384 = 128 × 128`, so a 128-aligned blob offset yields a
/// 128-aligned virtual address once the blob sits at a page-aligned region
/// base (§4.4).
pub const BXW1_ALIGN: u64 = 128;

/// `BXW1_ALIGN - 1`, as its own constant so alignment tests need no division.
pub(crate) const BXW1_ALIGN_MASK: u64 = 127;

/// Elements per `Q8_0` block.
pub const BXW1_Q8_0_BLOCK: u64 = 32;

/// Elements per `Q4_0` block (§4.4). The same 32 as `Q8_0`, deliberately: one
/// block-alignment rule (D8) covers both, and a model can be requantized
/// between them without reshaping.
pub const BXW1_Q4_0_BLOCK: u64 = 32;

/// Hard maximum blob size: 22 GiB (§8.2).
///
/// A token-rate floor as much as a memory ceiling: at the reference machine's
/// 200 GB/s nameplate bandwidth a 22 GiB model is ~118 ms per token.
pub const BXW1_MAX_BLOB_BYTES: u64 = 23_622_320_128;

/// Bound on `n_layers`.
pub const BXW1_MAX_LAYERS: u32 = 128;

/// Bound on `d_model`.
pub const BXW1_MAX_D_MODEL: u32 = 16384;

/// Bound on `n_heads` and on `n_kv_heads`.
pub const BXW1_MAX_HEADS: u32 = 256;

/// Bound on `d_head`.
pub const BXW1_MAX_D_HEAD: u32 = 512;

/// Bound on `d_ffn`.
pub const BXW1_MAX_D_FFN: u32 = 65536;

/// Bound on `vocab_size`.
pub const BXW1_MAX_VOCAB: u32 = 1 << 20;

/// Bound on `max_seq_len`, the weights-supported context length.
pub const BXW1_MAX_SEQ_LEN: u32 = 1 << 17;

/// Bound on the tokenizer vocabulary blob's length: 64 MiB (§5.4).
pub const BXW1_MAX_VOCAB_BLOB_BYTES: u64 = 64 * 1024 * 1024;

/// Bit 0 of `flags`: the output projection reuses `tok_embeddings.weight`
/// and `output.weight` is absent (§6.3).
pub const BXW1_FLAG_TIED_OUTPUT: u32 = 1;

/// The only accepted `arch_id`: a decoder-only transformer with
/// pre-normalization RMSNorm, RoPE, grouped-query attention and SwiGLU (§5.2).
pub const BXW1_ARCH_DECODER_ROPE_GQA_SWIGLU: u32 = 1;

/// A tensor's element type (§4).
///
/// Three, and the cost of each is stated in §4: there is no `f16`, no `bf16`,
/// and no `Q5`/`Q6`. Adding a dtype is a format version bump, not a flag, and
/// the note under [`Dtype::Q4`] records how that was handled when `Q4_0` was
/// added on 2026-08-19.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dtype {
    /// IEEE-754 binary32, little-endian, one value per element (`0x0000`).
    F32,
    /// `Q8_0`: split-plane, 32-element blocks (`0x0001`).
    ///
    /// Named `Q8` rather than `Q8_0` only because a variant name may not carry
    /// an underscore-separated digit group; the format's name for it is
    /// `Q8_0` everywhere else.
    Q8,
    /// `Q4_0`: split-plane, 32-element blocks, two weights per byte (`0x0002`).
    ///
    /// **0.625 bytes per weight against `Q8_0`'s 1.125**, so 1.80x fewer bytes
    /// moved. `NORTH_STAR.md` ranks this first among in-bounds performance work
    /// — *"Q8 first, lower precision where quality permits"* — because it
    /// divides the bandwidth-bound ceiling directly, and the ceiling is where
    /// the matmul now sits: four workers reach 116.5 GB/s of a measured
    /// ~120 GB/s.
    ///
    /// # Why this did not bump the version, which needs saying
    ///
    /// The header's `version_major` and `version_minor` are matched **exactly**
    /// (§3.1), not negotiated. So a minor bump would make every existing v1.0
    /// blob unreadable by this loader — the opposite of what a compatible
    /// addition should cost.
    ///
    /// The `dtype` field is already the discriminator, and it already fails
    /// closed: [`Dtype::from_bxw1`] refuses an unrecognized value with
    /// [`Bxw1Error::UnknownDtype`]. So a reader built before `Q4_0` existed
    /// **rejects** a `Q4_0` blob rather than misreading it, which is exactly the
    /// property a version bump would have been protecting. Old readers refuse
    /// new files; new readers accept old files. That is the compatibility a
    /// minor version normally buys, obtained without breaking every blob in
    /// existence.
    ///
    /// Named `Q4` for the same reason `Q8` is.
    Q4,
}

impl Dtype {
    /// BXW1 `dtype` value for [`Dtype::F32`].
    pub const BXW1_F32: u16 = 0x0000;

    /// BXW1 `dtype` value for [`Dtype::Q8`].
    pub const BXW1_Q8_0: u16 = 0x0001;

    /// BXW1 `dtype` value for [`Dtype::Q4`].
    pub const BXW1_Q4_0: u16 = 0x0002;

    /// Decodes a record's `dtype` field (rule D1).
    ///
    /// This is the boundary where an unvalidated `u16` from a blob becomes a
    /// value the loader can act on. Past it the dtype is a Rust enum, so an
    /// unrecognized one is not merely refused — it is unrepresentable.
    pub const fn from_bxw1(value: u16) -> Result<Self, Bxw1Error> {
        match value {
            Self::BXW1_F32 => Ok(Self::F32),
            Self::BXW1_Q8_0 => Ok(Self::Q8),
            Self::BXW1_Q4_0 => Ok(Self::Q4),
            _ => Err(Bxw1Error::UnknownDtype),
        }
    }

    /// The BXW1 `dtype` value this element type is written as.
    #[must_use]
    pub const fn to_bxw1(self) -> u16 {
        match self {
            Self::F32 => Self::BXW1_F32,
            Self::Q8 => Self::BXW1_Q8_0,
            Self::Q4 => Self::BXW1_Q4_0,
        }
    }
}

/// Which two per-head components form a rotated pair (§5.5).
///
/// This is a property of **the weight file**, not of the engine: the two
/// conventions differ by a permutation of the Q and K projection rows, so a
/// runtime that hardcodes either one silently produces fluent, plausible
/// garbage on every model converted under the other. No unit test can detect
/// it — position 0 is the identity rotation under both, and both are
/// norm-preserving per pair.
///
/// Mirrors `brainix_tensor::RopePairing`, which is the consumer of the decoded
/// value. The two are deliberately separate types: this crate is a hostile-
/// input parser and does not depend on a compute crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RopePairing {
    /// Pair `i` is `(x[2i], x[2i+1])` — `rope_pairing == 1`.
    Interleaved,
    /// Pair `i` is `(x[i], x[i + rope_dim/2])` — `rope_pairing == 2`.
    HalfSplit,
}

impl RopePairing {
    /// BXW1 `rope_pairing` value for [`RopePairing::Interleaved`].
    pub const BXW1_INTERLEAVED: u32 = 1;

    /// BXW1 `rope_pairing` value for [`RopePairing::HalfSplit`].
    pub const BXW1_HALF_SPLIT: u32 = 2;

    /// Decodes the header's `rope_pairing` field (rule H17a).
    ///
    /// **Zero is not a default and not "unspecified".** It is the value a
    /// converter that never heard of the field writes, which is exactly the
    /// case the field exists to catch, so it denies with its own variant.
    /// There is no fallback, no "try both and pick the better perplexity", and
    /// no operator override.
    pub const fn from_bxw1(value: u32) -> Result<Self, Bxw1Error> {
        match value {
            0 => Err(Bxw1Error::RopePairingUnspecified),
            Self::BXW1_INTERLEAVED => Ok(Self::Interleaved),
            Self::BXW1_HALF_SPLIT => Ok(Self::HalfSplit),
            _ => Err(Bxw1Error::UnknownRopePairing),
        }
    }

    /// The BXW1 `rope_pairing` value this convention is written as.
    #[must_use]
    pub const fn to_bxw1(self) -> u32 {
        match self {
            Self::Interleaved => Self::BXW1_INTERLEAVED,
            Self::HalfSplit => Self::BXW1_HALF_SPLIT,
        }
    }
}

/// A fully validated BXW1 blob.
///
/// Construction is the validation. Holding one of these means the whole blob
/// passed every rule this crate enforces — structure, shapes, extents,
/// required-name set, table digest, per-tensor digests, float bit patterns,
/// and pad bytes — and that nothing was activated partially along the way.
#[derive(Debug, Clone, Copy)]
pub struct WeightBlob<'a> {
    blob: &'a [u8],
    table: &'a [u8],
    header: Header,
    blob_digest: [u8; DIGEST_LEN],
}

impl<'a> WeightBlob<'a> {
    /// Parses and fully validates a blob.
    ///
    /// `region_capacity` is the reserved `WEIGHTS_REGION` size in bytes. It is
    /// the caller's number, never the blob's: a blob whose declared sizes
    /// exceed it denies before anything is placed (§8.3, rules H6 and D14).
    ///
    /// The order of validation is the normative order of §10.1 stages S2-S7,
    /// and two placements are load bearing:
    ///
    /// 1. The **table digest** (rule C1) is verified before any record's
    ///    contents are used for anything beyond bounds checking, so a corrupt
    ///    table cannot silently relabel correct data.
    /// 2. The **whole structural pass completes before any payload byte is
    ///    hashed**, so no extent is read until it is known to be inside the
    ///    blob, inside the declared tensor-data region, inside the reserved
    ///    region, aligned, and disjoint from every other extent.
    ///
    /// The record walk is two passes over the table rather than one: pass one
    /// is stage S5 (per-record structure and extents), pass two is stage S6
    /// (the required-name set and the header/table shape cross-checks). The
    /// ordering is the specification's, and keeping them separate means a
    /// blob that violates both reports the structural rule — the earlier and
    /// more fundamental one — rather than whichever happened to be reached
    /// first.
    pub fn parse(blob: &'a [u8], region_capacity: u64) -> Result<Self, Bxw1Error> {
        if blob.is_empty() {
            return Err(Bxw1Error::EmptyBlob);
        }
        let length = u64::try_from(blob.len()).map_err(|_| Bxw1Error::BlobExceedsMaxSize)?;
        if length < BXW1_HEADER_BYTES {
            return Err(Bxw1Error::BlobTooSmallForHeader);
        }
        if length > BXW1_MAX_BLOB_BYTES {
            // COVERAGE-EXEMPT: BXW1_MAX_BLOB_BYTES is ~22 GiB; a test that allocates a blob past it would need 22 GiB of RAM. The adjacent u64::try_from guard covers the conversion half of the same check and IS tested.
            return Err(Bxw1Error::BlobExceedsMaxSize);
        }
        if length > region_capacity {
            return Err(Bxw1Error::BlobExceedsRegionCapacity);
        }

        let header = Header::parse(blob, length, region_capacity)?;
        let table = table_bytes(blob, &header)?;
        payload::verify_table_digest(table, &header)?;

        let mut cursor = header.tensor_data_off;
        for index in 0..header.tensor_count {
            let record = Record::decode(table, index)?;
            walk_extent(&record, &header, index, &mut cursor, region_capacity)?;
        }
        require_no_trailing_bytes(cursor, &header)?;

        let mut seen = SlotSet::new();
        for index in 0..header.tensor_count {
            let record = Record::decode(table, index)?;
            names::admit(&record, &header, &mut seen)?;
        }
        seen.require_complete(&header)?;

        let blob_digest = payload::verify(blob, table, &header)?;

        Ok(Self {
            blob,
            table,
            header,
            blob_digest,
        })
    }

    /// The validated header: layout, hyperparameters, and tokenizer binding.
    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Number of tensors in the table.
    #[must_use]
    pub fn tensor_count(&self) -> u32 {
        self.header.tensor_count
    }

    /// SHA-256 over every byte of the blob, header inclusive.
    ///
    /// Computed during the payload pass and **not compared against anything
    /// here**: the value it is compared against is named by `LoadWeights`
    /// (rule C5) and anchored by a detached Ed25519 signature (rule C9), both
    /// of which are `modeld`'s at stage S8. A verified digest proves the bytes
    /// are the bytes someone named; it proves nothing about whether the model
    /// is the intended one or a safe one (§9.3).
    #[must_use]
    pub fn blob_digest(&self) -> [u8; DIGEST_LEN] {
        self.blob_digest
    }

    /// The tensor at `index`, with its dtype, shape, and borrowed payload.
    pub fn tensor(&self, index: u32) -> Result<Tensor<'a>, Bxw1Error> {
        if index >= self.header.tensor_count {
            return Err(Bxw1Error::TensorIndexOutOfRange);
        }
        let record = Record::decode(self.table, index)?;
        let data = slice_at(self.blob, record.data_off, record.data_len)
            .ok_or(Bxw1Error::ExtentPastBlob)?;
        Ok(Tensor {
            name: record.name,
            dtype: record.dtype,
            rank: record.rank,
            dims: record.dims,
            elements: record.elements,
            offset: record.data_off,
            data,
        })
    }

    /// The tensor whose name is exactly `name`, without its NUL terminator.
    ///
    /// The name is **compared, never interpreted**. A linear scan is what the
    /// format admits: there is no string table and no index, and the required
    /// set is at most `3 + 9 × 128` entries.
    pub fn tensor_by_name(&self, name: &[u8]) -> Result<Tensor<'a>, Bxw1Error> {
        for index in 0..self.header.tensor_count {
            let tensor = self.tensor(index)?;
            if tensor.name == name {
                return Ok(tensor);
            }
        }
        Err(Bxw1Error::TensorNameNotFound)
    }
}

/// Borrows the `tensor_count × 160` table bytes at offset 256.
fn table_bytes<'a>(blob: &'a [u8], header: &Header) -> Result<&'a [u8], Bxw1Error> {
    let end = header.table_end()?;
    let length = end
        .checked_sub(BXW1_HEADER_BYTES)
        .ok_or(Bxw1Error::TensorTableExceedsBlob)?;
    slice_at(blob, BXW1_HEADER_BYTES, length).ok_or(Bxw1Error::TensorTableExceedsBlob)
}

/// A validated tensor: its name, dtype, shape, and a borrowed view of exactly
/// its payload bytes.
///
/// The payload is **borrowed, never copied**. For a `Q8_0` tensor it is the
/// two-plane layout of §4.2 — scale plane, zero pad to [`BXW1_ALIGN`], quant
/// plane — which is exactly what `brainix_tensor::Q8Weights` expects.
#[derive(Debug, Clone, Copy)]
pub struct Tensor<'a> {
    name: &'a [u8],
    dtype: Dtype,
    rank: usize,
    dims: [u64; BXW1_MAX_RANK as usize],
    elements: u64,
    offset: u64,
    data: &'a [u8],
}

impl<'a> Tensor<'a> {
    /// The tensor's name, without its NUL terminator. Printable ASCII.
    #[must_use]
    pub fn name(&self) -> &'a [u8] {
        self.name
    }

    /// The tensor's element type.
    #[must_use]
    pub fn dtype(&self) -> Dtype {
        self.dtype
    }

    /// Number of used dimensions, `1 ..= BXW1_MAX_RANK`.
    #[must_use]
    pub fn rank(&self) -> usize {
        self.rank
    }

    /// The used axis extents, outermost first (row-major, §6.1).
    #[must_use]
    pub fn dims(&self) -> &[u64] {
        match self.dims.get(..self.rank) {
            Some(dims) => dims,
            // COVERAGE-EXEMPT: rank is validated at parse time to be at most dims.len(), so the range is always in bounds. The arm avoids a panicking index on a struct a future constructor might build differently.
            None => &[],
        }
    }

    /// The product of the used dimensions.
    #[must_use]
    pub fn elements(&self) -> u64 {
        self.elements
    }

    /// The tensor's byte offset within the blob. `BXW1_ALIGN`-aligned, and so
    /// `BXW1_ALIGN`-aligned in memory once the blob sits at a page-aligned
    /// region base (§4.4).
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// The tensor's payload: exactly `data_len` bytes, borrowed from the blob.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }
}
