//! The single failure enum for the BXW1 loader.
//!
//! One variant per failure mode, so a rejected blob can be audited for *why*
//! it was rejected rather than merely *that* it was. Every variant names the
//! rule of `docs/architecture/BXW1-weight-format.md` §7 that produced it, so a
//! denial can be traced to a line of the specification without reading the
//! decoder. Deliberately not `#[non_exhaustive]`: callers inside BraiNIX are
//! meant to match exhaustively so that a newly added failure mode is a compile
//! error, not a silent wildcard arm. This mirrors
//! [`brainix_adt::AdtError`](../../adt/src/error.rs).

/// Every way a BXW1 weight blob can be refused.
///
/// There is no warning, no partial success, and no partial activation. Any
/// value of this type means the load denied and **nothing** was produced:
/// no tensor view, no digest, and no borrowed slice (BXW1 §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bxw1Error {
    // -----------------------------------------------------------------
    // Object-level bounds -- the S0 analogue, before a header byte is read
    // -----------------------------------------------------------------
    /// The supplied blob was zero bytes long.
    EmptyBlob,

    /// The blob is shorter than the fixed 256-byte header (rule H1).
    ///
    /// The header decoder requires exactly 256 bytes and never reads a partial
    /// header.
    BlobTooSmallForHeader,

    /// The blob is longer than
    /// [`BXW1_MAX_BLOB_BYTES`](crate::BXW1_MAX_BLOB_BYTES) (stage S0).
    BlobExceedsMaxSize,

    /// The blob is longer than the caller's reserved-region capacity
    /// (stage S0, §8.3). Refused before anything is placed.
    BlobExceedsRegionCapacity,

    /// A fixed-offset read inside the 256-byte header did not fit.
    ///
    /// Unreachable once [`Bxw1Error::BlobTooSmallForHeader`] has passed;
    /// retained because "unreachable" is an argument about the program and a
    /// checked read is a property of it.
    TruncatedHeader,

    // -----------------------------------------------------------------
    // Header: identity and layout (rules H2-H12)
    // -----------------------------------------------------------------
    /// `magic` is not ASCII `"BXW1"` (rule H2).
    BadMagic,

    /// `version_major` is not 1 or `version_minor` is not 0 (rule H3).
    ///
    /// Exact match. Not a negotiation and not a compatibility range: a v2 is a
    /// new magic and a new document (§3.1).
    UnsupportedVersion,

    /// A `flags` bit above bit 0 is set (rule H4).
    ///
    /// An undefined flag bit is an attack surface, not a forward-compatibility
    /// affordance.
    ReservedFlagBitSet,

    /// `tensor_count` is zero (rule H5).
    ZeroTensorCount,

    /// `tensor_count` is above [`BXW1_MAX_TENSORS`](crate::BXW1_MAX_TENSORS)
    /// (rule H5).
    ///
    /// Checked **before** `tensor_count` is used in any arithmetic or to bound
    /// any read.
    TensorCountExceedsCeiling,

    /// `total_size` is below the 256-byte header (rule H6).
    TotalSizeBelowHeader,

    /// `total_size` is above
    /// [`BXW1_MAX_BLOB_BYTES`](crate::BXW1_MAX_BLOB_BYTES) (rule H6).
    TotalSizeExceedsMaxSize,

    /// `total_size` is above the caller's reserved-region capacity
    /// (rule H6, §8.3).
    TotalSizeExceedsRegionCapacity,

    /// `total_size` disagrees with the actual byte count of the supplied slice,
    /// in either direction (rule H7).
    ///
    /// The slice length is the authority; `total_size` is only ever compared to
    /// it. A smaller `total_size` leaves trailing bytes nothing accounts for; a
    /// larger one is a read past the end.
    TotalSizeMismatch,

    /// `tensor_table_off` is not exactly 256 (rule H8).
    ///
    /// It is compared against the constant, never followed as a pointer.
    TensorTableOffsetNot256,

    /// `256 + tensor_count × 160` overflowed (rule H9).
    ///
    /// Unreachable while [`Bxw1Error::TensorCountExceedsCeiling`] precedes it
    /// -- `4096 × 160` cannot overflow a `u64` -- and the checked multiply is
    /// mandatory anyway (§7.6): "unreachable" is an argument in a document,
    /// `checked_mul` is a property of the program.
    TensorTableExtentOverflow,

    /// The tensor table runs past `total_size` (rule H9).
    TensorTableExceedsBlob,

    /// `tensor_data_off` is not [`BXW1_ALIGN`](crate::BXW1_ALIGN)-aligned
    /// (rule H10). Never rounded up (§4.4).
    TensorDataOffsetMisaligned,

    /// `tensor_data_off` is below the end of the tensor table (rule H10).
    TensorDataOffsetBeforeTable,

    /// `tensor_data_off` is at or past the end of the blob (rule H10).
    TensorDataOffsetPastBlob,

    /// The gap between the end of the table and `tensor_data_off` is
    /// [`BXW1_ALIGN`](crate::BXW1_ALIGN) bytes or more (rule H10).
    ///
    /// A larger gap is unaccounted space, exactly as rule D17 treats the gaps
    /// between extents.
    TableToDataGapTooLarge,

    /// `tensor_data_off + tensor_data_len` overflowed (rule H11).
    TensorDataExtentOverflow,

    /// `tensor_data_off + tensor_data_len` is not exactly `total_size`
    /// (rule H11). The tensor-data region must end exactly at the blob's end.
    TensorDataExtentNotBlobEnd,

    /// One of `reserved_0`, `reserved_1`, `reserved_3` or `reserved_tail` is
    /// nonzero (rule H12).
    ///
    /// A reserved field is not an extension point: nonzero is a denial, not a
    /// forward-compatible unknown.
    ReservedHeaderFieldNonZero,

    // -----------------------------------------------------------------
    // Header: model metadata (rules H13-H22)
    // -----------------------------------------------------------------
    /// `arch_id` is not in the enumerated set (rule H13).
    ///
    /// No default and no "unknown architecture, try anyway".
    UnknownArchId,

    /// `n_layers` is zero or above
    /// [`BXW1_MAX_LAYERS`](crate::BXW1_MAX_LAYERS) (rule H14).
    NLayersOutOfRange,

    /// `d_model` is zero or above
    /// [`BXW1_MAX_D_MODEL`](crate::BXW1_MAX_D_MODEL) (rule H14).
    DModelOutOfRange,

    /// `n_heads` is zero or above [`BXW1_MAX_HEADS`](crate::BXW1_MAX_HEADS)
    /// (rule H14).
    NHeadsOutOfRange,

    /// `n_kv_heads` is zero or above
    /// [`BXW1_MAX_HEADS`](crate::BXW1_MAX_HEADS) (rule H14).
    NKvHeadsOutOfRange,

    /// `d_head` is zero or above [`BXW1_MAX_D_HEAD`](crate::BXW1_MAX_D_HEAD)
    /// (rule H14).
    DHeadOutOfRange,

    /// `d_ffn` is zero or above [`BXW1_MAX_D_FFN`](crate::BXW1_MAX_D_FFN)
    /// (rule H14).
    DFfnOutOfRange,

    /// `vocab_size` is zero or above
    /// [`BXW1_MAX_VOCAB`](crate::BXW1_MAX_VOCAB) (rule H14).
    VocabSizeOutOfRange,

    /// `max_seq_len` is zero or above
    /// [`BXW1_MAX_SEQ_LEN`](crate::BXW1_MAX_SEQ_LEN) (rule H14).
    MaxSeqLenOutOfRange,

    /// `n_kv_heads` is greater than `n_heads` (rule H15).
    KvHeadsExceedHeads,

    /// `n_heads` is not a multiple of `n_kv_heads` (rule H15).
    ///
    /// Grouped-query attention's group size must be exact.
    HeadsNotDivisibleByKvHeads,

    /// `n_heads × d_head` overflowed (rule H16).
    HeadWidthProductOverflow,

    /// `n_heads × d_head` is not `d_model` (rule H16).
    HeadWidthNotDModel,

    /// `rope_dim` is zero or greater than `d_head` (rule H17).
    RopeDimOutOfRange,

    /// `rope_dim` is odd (rule H17).
    ///
    /// RoPE rotates dimension pairs; an odd count has no meaning.
    RopeDimOdd,

    /// `rope_pairing` is zero (rule H17a, §5.5).
    ///
    /// Kept distinct from [`Bxw1Error::UnknownRopePairing`] because zero has a
    /// specific meaning: it is the value a converter that never heard of the
    /// field writes, which is exactly the case the field exists to catch. It
    /// is **not** "unspecified, assume interleaved" -- there is no default, no
    /// fallback, and no operator override.
    RopePairingUnspecified,

    /// `rope_pairing` is neither 1 nor 2 and is not zero (rule H17a, §5.5).
    UnknownRopePairing,

    /// `rope_theta_bits` fails the §4.7 bit-pattern rule.
    ///
    /// Classified as a `u32` by integer comparison **before** any float
    /// comparison, because `NaN < x` and `NaN > x` are both false and a
    /// float-comparison range check accepts NaN silently (rule H18).
    InvalidRopeTheta,

    /// `rope_theta` is outside `1.0e2 ..= 1.0e8` (rule H18, §5.1).
    RopeThetaOutOfRange,

    /// `norm_eps_bits` fails the §4.7 bit-pattern rule (rule H18).
    InvalidNormEps,

    /// `norm_eps` is outside `1.0e-8 ..= 1.0e-1` (rule H18, §5.1).
    NormEpsOutOfRange,

    /// `bos_token_id` is at or above `vocab_size` (rule H19).
    BosTokenOutOfRange,

    /// `eos_token_id` is at or above `vocab_size` (rule H19).
    EosTokenOutOfRange,

    /// `vocab_len` is zero (rule H20).
    VocabLenZero,

    /// `vocab_len` is above
    /// [`BXW1_MAX_VOCAB_BLOB_BYTES`](crate::BXW1_MAX_VOCAB_BLOB_BYTES)
    /// (rule H20).
    VocabLenExceedsCeiling,

    /// `tensor_count` is not `3 + 9 × n_layers`, or `2 + 9 × n_layers` when
    /// [`BXW1_FLAG_TIED_OUTPUT`](crate::BXW1_FLAG_TIED_OUTPUT) is set
    /// (rule H22).
    TensorCountNotArchRequired,

    // -----------------------------------------------------------------
    // Tensor table: integrity and record decoding
    // -----------------------------------------------------------------
    /// The SHA-256 over the table bytes does not equal `tensor_table_digest`
    /// (rule C1).
    ///
    /// Checked **before** any record's contents are used for anything beyond
    /// bounds checking (stage S4).
    TensorTableDigestMismatch,

    /// A fixed-offset read inside a 160-byte tensor record did not fit.
    ///
    /// Unreachable once the table extent has been checked against the blob
    /// (rule H9); retained for the same reason as
    /// [`Bxw1Error::TruncatedHeader`].
    TruncatedTensorRecord,

    /// Byte 63 of a record's 64-byte `name` field is not NUL (rule T1).
    ///
    /// The terminator's presence is guaranteed by position, so no reader ever
    /// scans past the field looking for one.
    NameNotTerminated,

    /// A record's `name` field starts with NUL -- an empty name (rule T2).
    NameEmpty,

    /// A byte after the first NUL of a `name` field is nonzero (rule T3).
    ///
    /// Bytes past the terminator are unreachable by any reader and are
    /// therefore a covert channel; requiring zero removes it.
    NameNonZeroAfterTerminator,

    /// A byte before the first NUL of a `name` field is outside `0x21..=0x7E`
    /// (rule T4). No control bytes, no space, no non-ASCII.
    NameNotPrintableAscii,

    /// Two records carry the same name (rule T5).
    ///
    /// A resolver that takes the first match silently ignores the second's
    /// bytes.
    DuplicateTensorName,

    /// A record's name is not in the required set for `arch_id` (rule T6).
    ///
    /// Unknown tensors are refused, not skipped: there is no "unknown tensor,
    /// ignore it" path (§6.2).
    UnknownTensorName,

    /// A name the required set demands is absent from the table (rule T7).
    ///
    /// This is also what an untied model missing `output.weight` produces
    /// (rule H21, §6.3).
    MissingRequiredTensor,

    /// [`BXW1_FLAG_TIED_OUTPUT`](crate::BXW1_FLAG_TIED_OUTPUT) is set and
    /// `output.weight` is present (rule H21, §6.3).
    TiedOutputWeightPresent,

    /// `dtype` is neither `0x0000` (`F32`) nor `0x0001` (`Q8_0`) (rule D1).
    ///
    /// There is no "unknown dtype, skip this tensor".
    UnknownDtype,

    /// The record's `dtype` is not permitted for its name (rule D2).
    ///
    /// Norm weights are `F32`-only (§6.2).
    DtypeNotPermittedForName,

    /// `rank` is zero (rule D3).
    ZeroRank,

    /// `rank` is above [`BXW1_MAX_RANK`](crate::BXW1_MAX_RANK) (rule D3).
    RankExceedsCeiling,

    /// `dims[j] == 0` for some `j < rank` (rule D4).
    ///
    /// A zero extent makes the element product zero, which would pass a naive
    /// length check.
    ZeroDimension,

    /// `dims[j] != 0` for some `j >= rank` (rule D5).
    ///
    /// Unused dimension slots carry no data.
    UnusedDimensionNonZero,

    /// `dims[j] > `[`BXW1_MAX_DIM`](crate::BXW1_MAX_DIM) for some `j < rank`
    /// (rule D6). Checked per dimension, before the product is formed.
    DimensionExceedsCeiling,

    /// The element-product fold overflowed (rule D7).
    ///
    /// Unreachable given that rule D6 caps each dimension at 2^28 and the
    /// running product is capped at
    /// [`BXW1_MAX_ELEMENTS`](crate::BXW1_MAX_ELEMENTS) = 2^35 after *each*
    /// multiply, which bounds the next multiply by 2^63. The checked multiply
    /// is mandatory regardless (§7.6): only it survives a future edit to a
    /// bound.
    ElementProductOverflow,

    /// The running element product exceeded
    /// [`BXW1_MAX_ELEMENTS`](crate::BXW1_MAX_ELEMENTS) (rule D7).
    ElementCountExceedsCeiling,

    /// A `Q8_0` tensor's fastest-varying dimension is not a multiple of
    /// [`BXW1_Q8_0_BLOCK`](crate::BXW1_Q8_0_BLOCK) (rule D8).
    ///
    /// This is what stops a block straddling a row boundary (§4.2).
    LastDimensionNotBlockAligned,

    /// Deriving `data_len` from `dtype` and `dims` overflowed at some step
    /// (rule D9), including the round-up to
    /// [`BXW1_ALIGN`](crate::BXW1_ALIGN).
    DerivedLengthOverflow,

    /// The declared `data_len` differs from the derived one, in either
    /// direction (rule D10).
    ///
    /// A shorter declaration leaves payload bytes unaccounted for; a longer one
    /// claims bytes belonging to the next tensor or past the blob. The derived
    /// value is the one used; the declared value is only ever compared.
    DeclaredLengthMismatch,

    /// A record's `data_off` is not [`BXW1_ALIGN`](crate::BXW1_ALIGN)-aligned
    /// (rule D11). Never rounded up: rounding shifts every subsequent extent
    /// relative to the digests computed over the unshifted bytes (§4.4).
    DataOffsetMisaligned,

    /// `data_off + data_len` overflowed (rule D12).
    ExtentOverflow,

    /// An extent starts before `tensor_data_off` (rule D13).
    ExtentBeforeDataRegion,

    /// An extent ends past `total_size` (rule D13).
    ExtentPastBlob,

    /// An extent ends past `tensor_data_off + tensor_data_len` (rule D13).
    ///
    /// Checked in addition to [`Bxw1Error::ExtentPastBlob`], because either
    /// bound alone leaves a way to point inside the header or the table.
    ExtentPastDataRegion,

    /// An extent ends past the caller's reserved-region capacity (rule D14).
    ///
    /// Checked in addition to rule D13, because the blob's own accounting
    /// agreeing with itself says nothing about whether it fits in memory.
    ExtentExceedsRegionCapacity,

    /// Record 0's `data_off` is not `tensor_data_off` (rule D15).
    ///
    /// No unaccounted gap before the first extent.
    FirstExtentNotAtDataStart,

    /// An extent starts before the previous extent ended (rule D16).
    ///
    /// This is the overlap check. Because extents are required to be strictly
    /// ascending it costs one `u64` of carried state and no scratch
    /// proportional to `tensor_count`.
    OverlappingExtents,

    /// The gap between two extents is [`BXW1_ALIGN`](crate::BXW1_ALIGN) bytes
    /// or more (rule D17). A gap larger than the maximum alignment pad is
    /// unaccounted space.
    ExcessiveExtentGap,

    /// The final extent's end, rounded up to
    /// [`BXW1_ALIGN`](crate::BXW1_ALIGN), is not `total_size` (rule D18).
    ///
    /// No unaccounted trailing region.
    TrailingBytesAfterLastExtent,

    /// A pad byte -- between the table and the first extent, between two
    /// extents, inside a `Q8_0` tensor between its planes, or after the last
    /// extent -- is nonzero (rule D19).
    ///
    /// Together with rules D15-D18 this is what makes "every byte of the blob
    /// is accounted for" (§3) a checked property rather than a description.
    NonZeroPadByte,

    /// A record's `reserved_a` or `reserved_b` is nonzero (rule D20).
    ReservedRecordFieldNonZero,

    // -----------------------------------------------------------------
    // Content (rules C2-C4, C8)
    // -----------------------------------------------------------------
    /// A tensor's SHA-256 over its `data_len` bytes at `data_off` does not
    /// equal its `digest` (rule C2).
    ///
    /// Denies the **whole blob**, not the tensor: there is no partial
    /// activation.
    TensorDigestMismatch,

    /// A `Q8_0` scale fails the §4.7 bit-pattern rule (rule C3).
    ///
    /// The accepted set is exactly `+0.0` -- the canonical all-zero block --
    /// or a positive finite normal. NaN, ±Inf, subnormals, negatives and
    /// `-0.0` are refused by a pair of integer comparisons.
    InvalidQ8Scale,

    /// An `F32` element is NaN, ±Inf, or subnormal (rule C4).
    ///
    /// Sign is unconstrained for elements -- weights are legitimately
    /// negative. Subnormals are refused because their meaning depends on
    /// `FPCR.FZ`, a register this format does not fix (§4.7).
    NonFiniteF32Element,

    /// A tensor's shape disagrees with the header's hyperparameters (rule C8,
    /// §5.3).
    ///
    /// Denies with **no precedence rule**: the loader does not prefer the
    /// header over the shapes or the reverse, because picking a winner means
    /// trusting one unaudited source over another (`INV-PARSE-004`).
    ShapeDisagreesWithHeader,

    // -----------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------
    /// A tensor was requested by an index at or above `tensor_count`.
    TensorIndexOutOfRange,

    /// A tensor was requested by a name no record carries.
    TensorNameNotFound,
}
