//! Bounds-checked primitive reads and the structural walk.
//!
//! Everything in this module works in **buffer-relative offsets**. The decoder
//! never sees a physical address; converting `boot_args.devtree` to a physical
//! address, checking `devtree_size`, and producing the `&[u8]` are the
//! caller's obligations (spec §3, §9.1) and belong to the boot-args parser.
//!
//! Two kinds of offset are distinguished, because they obey different rules:
//!
//! - a **read** offset must be strictly inside the buffer and the whole record
//!   starting there must fit;
//! - an **extent** offset — the end of a node, or the "first child" offset of a
//!   node with no children — may legitimately equal the buffer length. The
//!   worked fixture in the specification ends exactly this way.

use crate::error::AdtError;

/// Bytes in a node header: two little-endian `u32` counts.
pub(crate) const NODE_HEADER_LEN: usize = 8;

/// Bytes in a property's fixed name field.
pub(crate) const PROPERTY_NAME_LEN: usize = 32;

/// Offset of the last byte of a property name field, which must be NUL.
pub(crate) const PROPERTY_NAME_LAST: usize = 31;

/// Bytes in a property header: 32-byte name plus the 4-byte length word.
pub(crate) const PROPERTY_HEADER_LEN: usize = 36;

/// Bytes in a little-endian `u32`.
pub(crate) const U32_LEN: usize = 4;

/// Bytes in a little-endian `u64`.
pub(crate) const U64_LEN: usize = 8;

/// Every record in the format is aligned to, and padded to, 4 bytes.
pub(crate) const ALIGN_MASK: usize = 3;

/// Bit 31 of a property length word: the unresolved-template flag.
pub(crate) const PLACEHOLDER_FLAG: u32 = 0x8000_0000;

/// Bits 30..0 of a property length word: the value length in bytes.
pub(crate) const LENGTH_MASK: u32 = 0x7fff_ffff;

/// Fill value for the fixed-size traversal stack.
const EMPTY_FRAME: u32 = 0;

/// Reads a little-endian `u32` at `offset`, or `None` if it does not fit.
pub(crate) fn read_u32_le(blob: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(U32_LEN)?;
    let bytes = blob.get(offset..end)?;
    let array: [u8; U32_LEN] = bytes.try_into().ok()?;
    Some(u32::from_le_bytes(array))
}

/// Reads a little-endian `u64` at `offset`, or `None` if it does not fit.
///
/// The format guarantees only 4-byte alignment even for 64-bit values
/// (spec §4.3), which is why this goes through a byte copy rather than a
/// typed load.
pub(crate) fn read_u64_le(blob: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(U64_LEN)?;
    let bytes = blob.get(offset..end)?;
    let array: [u8; U64_LEN] = bytes.try_into().ok()?;
    Some(u64::from_le_bytes(array))
}

/// Rejects any read offset that is not 4-byte aligned.
pub(crate) fn require_alignment(offset: usize) -> Result<(), AdtError> {
    if offset & ALIGN_MASK == 0 {
        Ok(())
    } else {
        Err(AdtError::MisalignedRecord)
    }
}

/// Rounds a value length up to the next multiple of 4.
///
/// The addition is done with a checked operation so that a length near
/// `usize::MAX` denies rather than wrapping to a small padded length. The
/// grouping is `((len + 3) & !3)` — rounding **up** — which is the reading the
/// specification parenthesises correctly in §4.3.
pub(crate) fn padded_length(value_len: usize) -> Result<usize, AdtError> {
    let raised = value_len
        .checked_add(ALIGN_MASK)
        .ok_or(AdtError::OffsetOverflow)?;
    Ok(raised & !ALIGN_MASK)
}

/// A decoded and validated node header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NodeHeader {
    /// Number of property records following the header.
    pub(crate) property_count: u32,
    /// Number of child subtrees following the last property.
    pub(crate) child_count: u32,
}

/// Decodes the node header at `offset`, applying every check of spec §9.2.
///
/// The space tests run *before* the policy ceilings, so that an absurd count
/// such as `0xFFFF_FFFF` is refused by the test that is correct for small
/// buffers rather than merely by the ceiling.
pub(crate) fn decode_node_header(blob: &[u8], offset: usize) -> Result<NodeHeader, AdtError> {
    require_alignment(offset)?;

    let remaining = blob
        .len()
        .checked_sub(offset)
        .ok_or(AdtError::TruncatedNodeHeader)?;
    if remaining < NODE_HEADER_LEN {
        return Err(AdtError::TruncatedNodeHeader);
    }

    let property_count = read_u32_le(blob, offset).ok_or(AdtError::TruncatedNodeHeader)?;
    let child_count_offset = offset
        .checked_add(U32_LEN)
        .ok_or(AdtError::OffsetOverflow)?;
    let child_count = read_u32_le(blob, child_count_offset).ok_or(AdtError::TruncatedNodeHeader)?;

    if property_count == 0 {
        return Err(AdtError::ZeroPropertyCount);
    }

    // Minimum bytes the properties alone consume: every property record is at
    // least its 36-byte header.
    let properties_minimum = (property_count as usize)
        .checked_mul(PROPERTY_HEADER_LEN)
        .ok_or(AdtError::PropertyCountExceedsBuffer)?;
    let through_properties = NODE_HEADER_LEN
        .checked_add(properties_minimum)
        .ok_or(AdtError::PropertyCountExceedsBuffer)?;
    if through_properties > remaining {
        return Err(AdtError::PropertyCountExceedsBuffer);
    }
    if property_count > crate::MAX_PROPERTY_COUNT {
        return Err(AdtError::PropertyCountExceedsCeiling);
    }

    // Header-time *pre-check* on the child count. This is an early reject
    // only: it measures against the bytes remaining from the node's own
    // offset, which counts the node's properties as space available to its
    // children, so it can accept a count that cannot possibly fit. It does
    // **not** discharge the real test, which needs the first-child offset and
    // therefore the whole property walk — see `first_child_offset`.
    let children_minimum = (child_count as usize)
        .checked_mul(NODE_HEADER_LEN)
        .ok_or(AdtError::ChildCountExceedsBuffer)?;
    let through_children = through_properties
        .checked_add(children_minimum)
        .ok_or(AdtError::ChildCountExceedsBuffer)?;
    if through_children > remaining {
        return Err(AdtError::ChildCountExceedsBuffer);
    }
    if child_count > crate::MAX_CHILD_COUNT {
        return Err(AdtError::ChildCountExceedsCeiling);
    }

    Ok(NodeHeader {
        property_count,
        child_count,
    })
}

/// A decoded property record: borrowed name field, borrowed value, and the
/// offset at which the next record begins.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RawProperty<'a> {
    /// The full fixed 32-byte name field.
    pub(crate) name: &'a [u8],
    /// The value, exactly `value_len` bytes, padding excluded.
    pub(crate) value: &'a [u8],
    /// Offset just past this record's padding. May equal `blob.len()`.
    pub(crate) end: usize,
}

/// Decodes the property record at `offset`, applying spec §9.3 and §9.5.
pub(crate) fn decode_property(blob: &[u8], offset: usize) -> Result<RawProperty<'_>, AdtError> {
    require_alignment(offset)?;

    let header_end = offset
        .checked_add(PROPERTY_HEADER_LEN)
        .ok_or(AdtError::OffsetOverflow)?;
    if header_end > blob.len() {
        return Err(AdtError::TruncatedPropertyHeader);
    }
    let name_end = offset
        .checked_add(PROPERTY_NAME_LEN)
        .ok_or(AdtError::OffsetOverflow)?;
    let name = blob
        .get(offset..name_end)
        .ok_or(AdtError::TruncatedPropertyHeader)?;

    // Termination is checked before anything else touches the name.
    let terminator = name
        .get(PROPERTY_NAME_LAST)
        .ok_or(AdtError::TruncatedPropertyHeader)?;
    if *terminator != 0 {
        return Err(AdtError::PropertyNameNotTerminated);
    }

    let length_word = read_u32_le(blob, name_end).ok_or(AdtError::TruncatedPropertyHeader)?;
    if length_word & PLACEHOLDER_FLAG != 0 {
        return Err(AdtError::PlaceholderFlagSet);
    }
    let value_len = (length_word & LENGTH_MASK) as usize;
    if value_len > crate::MAX_VALUE_LEN {
        return Err(AdtError::ValueLengthExceedsCeiling);
    }

    // The padded test is strictly stronger than the unpadded one and is the
    // one that matters, because the padded size is what the next-record
    // arithmetic consumes.
    let padded = padded_length(value_len)?;
    let end = header_end
        .checked_add(padded)
        .ok_or(AdtError::OffsetOverflow)?;
    if end > blob.len() {
        return Err(AdtError::TruncatedPropertyValue);
    }

    let value_end = header_end
        .checked_add(value_len)
        .ok_or(AdtError::OffsetOverflow)?;
    let value = blob
        .get(header_end..value_end)
        .ok_or(AdtError::TruncatedPropertyValue)?;

    Ok(RawProperty { name, value, end })
}

/// Walks every property of the node whose header is at `offset` and returns
/// the offset just past the last one — which is both the node's "first child"
/// offset and, when the node has no children, the node's own extent end.
pub(crate) fn end_of_properties(
    blob: &[u8],
    offset: usize,
    property_count: u32,
) -> Result<usize, AdtError> {
    let mut cursor = offset
        .checked_add(NODE_HEADER_LEN)
        .ok_or(AdtError::OffsetOverflow)?;
    let mut walked: u32 = 0;
    while walked < property_count {
        let property = decode_property(blob, cursor)?;
        cursor = property.end;
        walked = walked.checked_add(1).ok_or(AdtError::OffsetOverflow)?;
    }
    Ok(cursor)
}

/// Walks the node's properties and returns its first-child offset `F`, after
/// applying the **real** child-count minimum-space test.
///
/// This is the test the header-time pre-check does not discharge. Each child
/// needs at least its own 8-byte header, and the space actually available to
/// the children starts at `F` — not at the node's offset, which would count
/// the node's own properties as room for its children.
///
/// `F` is an *extent* offset: it may legitimately equal the buffer length,
/// which is exactly the case when `child_count` is zero and the node is the
/// last in the blob. It becomes a read offset only when the count says a child
/// record exists there, and the full read-offset test is applied then.
pub(crate) fn first_child_offset(
    blob: &[u8],
    offset: usize,
    header: NodeHeader,
) -> Result<usize, AdtError> {
    let first = end_of_properties(blob, offset, header.property_count)?;
    let available = blob
        .len()
        .checked_sub(first)
        .ok_or(AdtError::ChildCountExceedsBuffer)?;
    let children_minimum = (header.child_count as usize)
        .checked_mul(NODE_HEADER_LEN)
        .ok_or(AdtError::ChildCountExceedsBuffer)?;
    if children_minimum > available {
        return Err(AdtError::ChildCountExceedsBuffer);
    }
    Ok(first)
}

/// Fully validates the subtree rooted at `start` and returns its extent end.
///
/// The walk is iterative over an explicit fixed-size stack, so the depth limit
/// is a property of the data structure rather than of programmer discipline
/// (spec §9.6). No recursion, no allocation.
///
/// `depth_budget` is how many further levels below `start` may be descended;
/// it is clamped to [`MAX_TREE_DEPTH`](crate::MAX_TREE_DEPTH), which is the
/// stack's capacity.
///
/// **Termination.** Each iteration of the outer loop begins at a strictly
/// greater offset than the previous one, because every node consumes at least
/// its 8-byte header and every advance is to an offset past a decoded record.
/// A visit budget of `blob.len() / 8` makes that guarantee structural rather
/// than argued: an input that somehow failed to advance denies with
/// [`AdtError::WalkBudgetExhausted`] instead of looping.
pub(crate) fn walk_node_end(
    blob: &[u8],
    start: usize,
    depth_budget: usize,
) -> Result<usize, AdtError> {
    let limit = core::cmp::min(depth_budget, crate::MAX_TREE_DEPTH);
    let mut pending_siblings = [EMPTY_FRAME; crate::MAX_TREE_DEPTH];
    let mut depth: usize = 0;
    let mut offset = start;

    let mut budget = blob
        .len()
        .checked_div(NODE_HEADER_LEN)
        .ok_or(AdtError::OffsetOverflow)?
        .checked_add(1)
        .ok_or(AdtError::OffsetOverflow)?;

    loop {
        budget = budget.checked_sub(1).ok_or(AdtError::WalkBudgetExhausted)?;

        let header = decode_node_header(blob, offset)?;
        let cursor = first_child_offset(blob, offset, header)?;

        if header.child_count > 0 {
            if depth >= limit {
                return Err(AdtError::DepthLimitExceeded);
            }
            let frame = pending_siblings
                .get_mut(depth)
                .ok_or(AdtError::DepthLimitExceeded)?;
            *frame = header
                .child_count
                .checked_sub(1)
                .ok_or(AdtError::OffsetOverflow)?;
            depth = depth.checked_add(1).ok_or(AdtError::DepthLimitExceeded)?;
            offset = cursor;
            continue;
        }

        // A node with no children ends where its properties end. Unwind to the
        // nearest ancestor that still owes a sibling; the end of a parent is
        // the end of its last child, so `cursor` carries upward unchanged.
        loop {
            if depth == 0 {
                return Ok(cursor);
            }
            let index = depth.checked_sub(1).ok_or(AdtError::OffsetOverflow)?;
            let frame = pending_siblings
                .get_mut(index)
                .ok_or(AdtError::DepthLimitExceeded)?;
            if *frame > 0 {
                *frame = frame.checked_sub(1).ok_or(AdtError::OffsetOverflow)?;
                offset = cursor;
                break;
            }
            depth = index;
        }
    }
}
