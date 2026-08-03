//! The tensor table: one fixed 160-byte record per tensor (§3.2), and the
//! per-record rules of §7.3 and §7.4.
//!
//! Records are decoded **in index order** and the extents they describe are
//! required to be strictly ascending and disjoint. That requirement is what
//! reduces overlap detection from a quadratic scan needing
//! `BXW1_MAX_TENSORS` extents of scratch to a single forward pass carrying
//! **one `u64`** of state (§3.2).

use crate::error::Bxw1Error;
use crate::header::Header;
use crate::raw::{read_field, read_u16_le, read_u32_le, read_u64_le, DIGEST_LEN};
use crate::{
    Dtype, BXW1_ALIGN, BXW1_ALIGN_MASK, BXW1_MAX_DIM, BXW1_MAX_ELEMENTS, BXW1_MAX_RANK,
    BXW1_Q8_0_BLOCK, BXW1_TENSOR_RECORD_BYTES,
};

/// Field offsets within a record, relative to its first byte (§3.2).
mod offset {
    pub(super) const NAME: usize = 0;
    pub(super) const NAME_LEN: usize = 64;
    pub(super) const NAME_LAST: usize = 63;
    pub(super) const DTYPE: usize = 64;
    pub(super) const RANK: usize = 66;
    pub(super) const RESERVED_A: usize = 68;
    pub(super) const DIMS: usize = 72;
    pub(super) const DATA_OFF: usize = 104;
    pub(super) const DATA_LEN: usize = 112;
    pub(super) const DIGEST: usize = 120;
    pub(super) const RESERVED_B: usize = 152;
}

/// Bytes in one `dims` slot.
const DIM_STRIDE: usize = 8;

/// Bytes per `F32` element.
const F32_BYTES: u64 = 4;

/// Bytes per `Q8_0` scale.
const SCALE_BYTES: u64 = 4;

/// Bytes per `Q8_0` quant block, one `i8` per element.
const QUANT_BLOCK_BYTES: u64 = 32;

/// Lowest printable ASCII byte accepted in a name (rule T4).
const PRINTABLE_LOW: u8 = 0x21;

/// Highest printable ASCII byte accepted in a name (rule T4).
const PRINTABLE_HIGH: u8 = 0x7E;

/// A decoded and self-consistently validated tensor-table record.
///
/// Holding one means every rule of §7.3 and §7.4 that a record can be judged
/// against **in isolation** has passed. The rules that need context -- the
/// extent walk (D15-D18), the required-name set (T5-T7), and the shape
/// cross-checks (C8) -- are applied by the caller.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Record<'a> {
    /// The name's bytes up to, but excluding, its NUL terminator.
    pub(crate) name: &'a [u8],
    /// Element type.
    pub(crate) dtype: Dtype,
    /// Number of used `dims` slots, `1 ..= BXW1_MAX_RANK`.
    pub(crate) rank: usize,
    /// Axis extents, outermost first. Slots at or above `rank` are zero.
    pub(crate) dims: [u64; BXW1_MAX_RANK as usize],
    /// The product of `dims[0..rank]`, folded with checked multiplication and
    /// bounded after each step (rule D7).
    pub(crate) elements: u64,
    /// Absolute byte offset of this tensor's payload.
    pub(crate) data_off: u64,
    /// Payload byte length -- the value **derived** from `dtype` and `dims`,
    /// which rule D10 has already proven equal to the declared one.
    pub(crate) data_len: u64,
    /// SHA-256 over exactly `data_len` bytes at `data_off`.
    pub(crate) digest: &'a [u8],
}

impl<'a> Record<'a> {
    /// Decodes record `index` from the table bytes.
    pub(crate) fn decode(table: &'a [u8], index: u32) -> Result<Self, Bxw1Error> {
        let start = usize::try_from(
            u64::from(index)
                .checked_mul(BXW1_TENSOR_RECORD_BYTES)
                .ok_or(Bxw1Error::TruncatedTensorRecord)?,
        )
        .map_err(|_| Bxw1Error::TruncatedTensorRecord)?;
        let record = read_field(
            table,
            start,
            usize::try_from(BXW1_TENSOR_RECORD_BYTES)
                .map_err(|_| Bxw1Error::TruncatedTensorRecord)?,
        )
        .ok_or(Bxw1Error::TruncatedTensorRecord)?;

        let name = decode_name(record)?;
        let dtype = Dtype::from_bxw1(
            read_u16_le(record, offset::DTYPE).ok_or(Bxw1Error::TruncatedTensorRecord)?,
        )?;
        let shape = Shape::decode(record, dtype)?;

        if read_u32_le(record, offset::RESERVED_A).ok_or(Bxw1Error::TruncatedTensorRecord)? != 0 {
            return Err(Bxw1Error::ReservedRecordFieldNonZero);
        }
        if read_u64_le(record, offset::RESERVED_B).ok_or(Bxw1Error::TruncatedTensorRecord)? != 0 {
            return Err(Bxw1Error::ReservedRecordFieldNonZero);
        }

        let data_off =
            read_u64_le(record, offset::DATA_OFF).ok_or(Bxw1Error::TruncatedTensorRecord)?;
        if data_off & BXW1_ALIGN_MASK != 0 {
            return Err(Bxw1Error::DataOffsetMisaligned);
        }
        let declared_len =
            read_u64_le(record, offset::DATA_LEN).ok_or(Bxw1Error::TruncatedTensorRecord)?;
        let derived_len = derive_data_len(dtype, shape.elements)?;
        if declared_len != derived_len {
            return Err(Bxw1Error::DeclaredLengthMismatch);
        }

        let digest = read_field(record, offset::DIGEST, DIGEST_LEN)
            .ok_or(Bxw1Error::TruncatedTensorRecord)?;

        Ok(Self {
            name,
            dtype,
            rank: shape.rank,
            dims: shape.dims,
            elements: shape.elements,
            data_off,
            data_len: derived_len,
            digest,
        })
    }

    /// The byte just past this tensor's payload, checked (rule D12).
    pub(crate) fn extent_end(&self) -> Result<u64, Bxw1Error> {
        self.data_off
            .checked_add(self.data_len)
            .ok_or(Bxw1Error::ExtentOverflow)
    }
}

/// A record's shape: rank, dimensions, and their bounded product.
struct Shape {
    rank: usize,
    dims: [u64; BXW1_MAX_RANK as usize],
    elements: u64,
}

impl Shape {
    /// Applies rules D3-D8.
    fn decode(record: &[u8], dtype: Dtype) -> Result<Self, Bxw1Error> {
        let rank = read_u16_le(record, offset::RANK).ok_or(Bxw1Error::TruncatedTensorRecord)?;
        if rank == 0 {
            return Err(Bxw1Error::ZeroRank);
        }
        if rank > BXW1_MAX_RANK {
            return Err(Bxw1Error::RankExceedsCeiling);
        }
        let rank = usize::from(rank);

        let mut dims = [0_u64; BXW1_MAX_RANK as usize];
        let mut elements: u64 = 1;
        let mut last: u64 = 0;
        for (slot, dim) in dims.iter_mut().enumerate() {
            let at = offset::DIMS
                .checked_add(
                    slot.checked_mul(DIM_STRIDE)
                        .ok_or(Bxw1Error::ExtentOverflow)?,
                )
                .ok_or(Bxw1Error::ExtentOverflow)?;
            let value = read_u64_le(record, at).ok_or(Bxw1Error::TruncatedTensorRecord)?;
            if slot >= rank {
                // Rule D5: unused dimension slots carry no data.
                if value != 0 {
                    return Err(Bxw1Error::UnusedDimensionNonZero);
                }
                continue;
            }
            if value == 0 {
                return Err(Bxw1Error::ZeroDimension);
            }
            if value > BXW1_MAX_DIM {
                return Err(Bxw1Error::DimensionExceedsCeiling);
            }
            // Rule D7: checked multiply, and the running product is bounded
            // after *each* step. That ordering is what bounds the next
            // multiply; a per-dimension bound alone does not make the product
            // safe.
            elements = elements
                .checked_mul(value)
                .ok_or(Bxw1Error::ElementProductOverflow)?;
            if elements > BXW1_MAX_ELEMENTS {
                return Err(Bxw1Error::ElementCountExceedsCeiling);
            }
            *dim = value;
            last = value;
        }

        // Rule D8: no `Q8_0` block ever straddles a row boundary. The rule is
        // on the last dimension rather than on the element count because that
        // is what lets a per-row dot product decompose into whole blocks.
        if dtype == Dtype::Q8 && !last.is_multiple_of(BXW1_Q8_0_BLOCK) {
            return Err(Bxw1Error::LastDimensionNotBlockAligned);
        }

        Ok(Self {
            rank,
            dims,
            elements,
        })
    }
}

/// Applies the name rules T1-T4 and returns the name without its terminator.
fn decode_name(record: &[u8]) -> Result<&[u8], Bxw1Error> {
    let field = read_field(record, offset::NAME, offset::NAME_LEN)
        .ok_or(Bxw1Error::TruncatedTensorRecord)?;

    // Rule T1 first: the terminator's presence is guaranteed by position, so
    // no reader ever scans past the field looking for one.
    let last = field
        .get(offset::NAME_LAST)
        .ok_or(Bxw1Error::TruncatedTensorRecord)?;
    if *last != 0 {
        return Err(Bxw1Error::NameNotTerminated);
    }
    let first = field.first().ok_or(Bxw1Error::TruncatedTensorRecord)?;
    if *first == 0 {
        return Err(Bxw1Error::NameEmpty);
    }

    let terminator = field
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(Bxw1Error::NameNotTerminated)?;
    let name = field
        .get(..terminator)
        .ok_or(Bxw1Error::NameNotTerminated)?;
    if name
        .iter()
        .any(|byte| !(PRINTABLE_LOW..=PRINTABLE_HIGH).contains(byte))
    {
        return Err(Bxw1Error::NameNotPrintableAscii);
    }

    let after = terminator
        .checked_add(1)
        .ok_or(Bxw1Error::TruncatedTensorRecord)?;
    let tail = field.get(after..).ok_or(Bxw1Error::TruncatedTensorRecord)?;
    if tail.iter().any(|byte| *byte != 0) {
        return Err(Bxw1Error::NameNonZeroAfterTerminator);
    }

    Ok(name)
}

/// Derives `data_len` from `dtype` and the element count (§4.3, rule D9).
///
/// Every step is checked `u64` arithmetic, including the round-up to
/// `BXW1_ALIGN`.
fn derive_data_len(dtype: Dtype, elements: u64) -> Result<u64, Bxw1Error> {
    match dtype {
        Dtype::F32 => elements
            .checked_mul(F32_BYTES)
            .ok_or(Bxw1Error::DerivedLengthOverflow),
        Dtype::Q8 => {
            let blocks = elements
                .checked_div(BXW1_Q8_0_BLOCK)
                .ok_or(Bxw1Error::DerivedLengthOverflow)?;
            let scale_len = blocks
                .checked_mul(SCALE_BYTES)
                .ok_or(Bxw1Error::DerivedLengthOverflow)?;
            let quant_len = blocks
                .checked_mul(QUANT_BLOCK_BYTES)
                .ok_or(Bxw1Error::DerivedLengthOverflow)?;
            round_up_to_align(scale_len)?
                .checked_add(quant_len)
                .ok_or(Bxw1Error::DerivedLengthOverflow)
        }
    }
}

/// Rounds up to a multiple of [`BXW1_ALIGN`], refusing rather than wrapping.
pub(crate) fn round_up_to_align(value: u64) -> Result<u64, Bxw1Error> {
    let raised = value
        .checked_add(BXW1_ALIGN_MASK)
        .ok_or(Bxw1Error::DerivedLengthOverflow)?;
    Ok(raised & !BXW1_ALIGN_MASK)
}

/// The byte offset of a `Q8_0` tensor's quant plane within its payload, and
/// the length of its scale plane (§4.2).
pub(crate) fn q8_planes(elements: u64) -> Result<(u64, u64), Bxw1Error> {
    let blocks = elements
        .checked_div(BXW1_Q8_0_BLOCK)
        .ok_or(Bxw1Error::DerivedLengthOverflow)?;
    let scale_len = blocks
        .checked_mul(SCALE_BYTES)
        .ok_or(Bxw1Error::DerivedLengthOverflow)?;
    Ok((scale_len, round_up_to_align(scale_len)?))
}

/// The single forward pass over extents: rules D13-D18, carrying one `u64`.
///
/// `cursor` is the end of the previous extent on entry and the end of this one
/// on exit. `index` is only used to distinguish record 0, whose rule (D15) is
/// different in kind: there is no previous extent, and the first one must
/// begin exactly at `tensor_data_off`.
pub(crate) fn walk_extent(
    record: &Record<'_>,
    header: &Header,
    index: u32,
    cursor: &mut u64,
    region_capacity: u64,
) -> Result<(), Bxw1Error> {
    let end = record.extent_end()?;
    if record.data_off < header.tensor_data_off {
        return Err(Bxw1Error::ExtentBeforeDataRegion);
    }
    if end > header.total_size {
        return Err(Bxw1Error::ExtentPastBlob);
    }
    let region_end = header
        .tensor_data_off
        .checked_add(header.tensor_data_len)
        .ok_or(Bxw1Error::TensorDataExtentOverflow)?;
    if end > region_end {
        return Err(Bxw1Error::ExtentPastDataRegion);
    }
    // Rule D14, checked in addition to D13: the blob's own accounting agreeing
    // with itself says nothing about whether it fits in memory.
    if end > region_capacity {
        return Err(Bxw1Error::ExtentExceedsRegionCapacity);
    }

    if index == 0 {
        if record.data_off != header.tensor_data_off {
            return Err(Bxw1Error::FirstExtentNotAtDataStart);
        }
    } else {
        if record.data_off < *cursor {
            return Err(Bxw1Error::OverlappingExtents);
        }
        let gap = record
            .data_off
            .checked_sub(*cursor)
            .ok_or(Bxw1Error::OverlappingExtents)?;
        if gap >= BXW1_ALIGN {
            return Err(Bxw1Error::ExcessiveExtentGap);
        }
    }

    *cursor = end;
    Ok(())
}

/// Rule D18: the final extent's end, rounded up to `BXW1_ALIGN`, must be
/// exactly `total_size`. No unaccounted trailing region.
pub(crate) fn require_no_trailing_bytes(cursor: u64, header: &Header) -> Result<(), Bxw1Error> {
    if round_up_to_align(cursor)? != header.total_size {
        return Err(Bxw1Error::TrailingBytesAfterLastExtent);
    }
    Ok(())
}
