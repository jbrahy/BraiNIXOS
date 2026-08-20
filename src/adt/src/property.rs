//! Properties and the typed accessors AS-1 needs.
//!
//! A property value is **untyped bytes**. Nothing in the format says whether
//! four bytes are an integer or four characters, so every accessor here states
//! the shape it requires and denies a value that does not have it. Nothing is
//! coerced, truncated or zero-extended to fit.

use crate::error::AdtError;
use crate::raw::{read_u32_le, read_u64_le, PROPERTY_NAME_LEN, U32_LEN, U64_LEN};

/// Bytes in an `(address, size)` record: two little-endian `u64`.
pub const ADDRESS_SIZE_RECORD_LEN: usize = 16;

/// The longest node name accepted, in characters, excluding the terminator.
///
/// Apple's own declaration allows 63. BraiNIX policy per spec §9.0, reported
/// through [`AdtError::NodeNameTooLong`].
pub const MAX_NODE_NAME_LEN: usize = 63;

/// The longest `name` property *value* accepted: 63 characters plus the NUL.
///
/// A node name lives inside a property value, which the format bounds only by
/// `0x7FFFFFFF`, so this is the bound that actually caps the work a crafted
/// tree can impose on path resolution. BraiNIX policy per spec §9.0 and §9.5,
/// reported through [`AdtError::NodeNameValueTooLong`] — a distinct reason
/// from the bound on the decoded string.
pub const MAX_NODE_VALUE_LEN: usize = 64;

/// A borrowed property: its fixed 32-byte name field and its untyped value.
///
/// Both slices point into the caller's blob. Nothing is copied.
#[derive(Debug, Clone, Copy)]
pub struct Property<'a> {
    name_field: &'a [u8],
    value: &'a [u8],
}

impl<'a> Property<'a> {
    pub(crate) fn new(name_field: &'a [u8], value: &'a [u8]) -> Self {
        Self { name_field, value }
    }

    /// The full fixed 32-byte name field, NUL padding included.
    pub fn name_field(&self) -> &'a [u8] {
        self.name_field
    }

    /// The property name: the bytes of the name field before its first NUL.
    ///
    /// The decoder has already refused any property whose byte 31 is not NUL,
    /// so a NUL is always present; if one somehow is not, the whole 32-byte
    /// field is returned rather than reading past it.
    pub fn name(&self) -> &'a [u8] {
        match self.name_field.iter().position(|byte| *byte == 0) {
            Some(index) => match self.name_field.get(..index) {
                Some(slice) => slice,
                // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
                // than by validation of the tree. `ranges` refuses a parent count outside
                // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
                // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
                // unless a whole `entry_len` is present, so each read lands inside the
                // entry. Kept because both of those facts live in other functions.
                None => self.name_field,
            },
            None => self.name_field,
        }
    }

    /// Whether this property is named `wanted`.
    ///
    /// The comparison is bounded to the 32-byte field regardless of the
    /// termination check already performed — defence in depth (spec §9.5).
    pub fn is_named(&self, wanted: &[u8]) -> bool {
        if wanted.len() > PROPERTY_NAME_LEN {
            return false;
        }
        self.name() == wanted
    }

    /// The untyped value, exactly `value_len` bytes. Padding is excluded.
    pub fn value(&self) -> &'a [u8] {
        self.value
    }

    /// The value as a little-endian `u32`. The value must be exactly 4 bytes.
    pub fn as_u32(&self) -> Result<u32, AdtError> {
        if self.value.len() != U32_LEN {
            return Err(AdtError::PropertyLengthMismatch);
        }
        read_u32_le(self.value, 0).ok_or(AdtError::PropertyLengthMismatch)
    }

    /// The value as a little-endian `u64`. The value must be exactly 8 bytes.
    pub fn as_u64(&self) -> Result<u64, AdtError> {
        if self.value.len() != U64_LEN {
            return Err(AdtError::PropertyLengthMismatch);
        }
        read_u64_le(self.value, 0).ok_or(AdtError::PropertyLengthMismatch)
    }

    /// The value as a single NUL-terminated string, without its terminator.
    ///
    /// The search for the terminator is bounded by the declared value length.
    /// A value with no NUL in it is refused; the whole value is never adopted
    /// as the string (spec §9.5).
    pub fn as_c_str(&self) -> Result<&'a [u8], AdtError> {
        let index = self
            .value
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(AdtError::UnterminatedStringValue)?;
        self.value
            .get(..index)
            .ok_or(AdtError::UnterminatedStringValue)
    }

    /// Iterates the NUL-terminated strings packed into the value, as
    /// `compatible` and similar list-valued properties carry them.
    ///
    /// Iteration stops at the end of the value or at the first byte range that
    /// contains no NUL. Empty strings are the 4-byte zero padding of §4.3, not
    /// entries, and are skipped rather than yielded (spec §8.1).
    pub fn strings(&self) -> StringIter<'a> {
        StringIter {
            value: self.value,
            position: 0,
            done: false,
        }
    }

    /// Whether any string in the value equals `wanted` exactly.
    pub fn has_string(&self, wanted: &[u8]) -> bool {
        self.strings().any(|entry| entry == wanted)
    }

    /// The value as one `(address, size)` record of two little-endian `u64`.
    ///
    /// The value must be **exactly** 16 bytes. This is the shape of
    /// `cpu-impl-reg`, `cpu-uttdbg-reg`, and every `/chosen/memory-map` and
    /// `/chosen/carveout-memory-map` entry (spec §8.2, §8.3, §9.9).
    pub fn as_address_size(&self) -> Result<AddressRange, AdtError> {
        if self.value.len() != ADDRESS_SIZE_RECORD_LEN {
            return Err(AdtError::PropertyLengthMismatch);
        }
        let address = read_u64_le(self.value, 0).ok_or(AdtError::PropertyLengthMismatch)?;
        let size = read_u64_le(self.value, U64_LEN).ok_or(AdtError::PropertyLengthMismatch)?;
        Ok(AddressRange { address, size })
    }

    /// Container `index` of a `reg` property, decoded with the cell counts
    /// declared by the node's **parent** (spec §8.5).
    ///
    /// A value need not be an exact multiple of the container size, but a
    /// partial trailing container is never read.
    pub fn reg_container(&self, cells: CellCounts, index: usize) -> Result<AddressRange, AdtError> {
        let stride = cells.container_len()?;
        let start = index
            .checked_mul(stride)
            .ok_or(AdtError::RegContainerOutOfRange)?;
        let end = start
            .checked_add(stride)
            .ok_or(AdtError::RegContainerOutOfRange)?;
        if end > self.value.len() {
            return Err(AdtError::RegContainerOutOfRange);
        }
        let address = read_cells(self.value, start, cells.address_cells)?;
        let size_offset = start
            .checked_add(cells.address_bytes()?)
            .ok_or(AdtError::RegContainerOutOfRange)?;
        let size = read_cells(self.value, size_offset, cells.size_cells)?;
        Ok(AddressRange { address, size })
    }

    /// How many whole `reg` containers the value holds.
    pub fn reg_container_count(&self, cells: CellCounts) -> Result<usize, AdtError> {
        let stride = cells.container_len()?;
        self.value
            .len()
            .checked_div(stride)
            .ok_or(AdtError::MalformedRangesEntry)
    }

    /// Iterates the entries of a `ranges` property.
    ///
    /// `child` is the cell-count pair declared by the node that owns the
    /// `ranges` property; `parent_address_cells` is that node's parent's
    /// `#address-cells`. Only whole entries are visited; a trailing partial
    /// entry is ignored rather than read (spec §9.8).
    pub fn ranges(
        &self,
        child: CellCounts,
        parent_address_cells: u32,
    ) -> Result<RangesIter<'a>, AdtError> {
        if parent_address_cells == 0 || parent_address_cells > 2 {
            return Err(AdtError::InvalidAddressCells);
        }
        let child_address_bytes = child.address_bytes()?;
        let size_bytes = child.size_bytes()?;
        let parent_address_bytes = (parent_address_cells as usize)
            .checked_mul(U32_LEN)
            .ok_or(AdtError::MalformedRangesEntry)?;
        let entry_len = child_address_bytes
            .checked_add(parent_address_bytes)
            .ok_or(AdtError::MalformedRangesEntry)?
            .checked_add(size_bytes)
            .ok_or(AdtError::MalformedRangesEntry)?;
        if entry_len == 0 || entry_len > self.value.len() {
            return Err(AdtError::MalformedRangesEntry);
        }
        Ok(RangesIter {
            value: self.value,
            position: 0,
            entry_len,
            child_address_cells: child.address_cells,
            parent_address_cells,
            size_cells: child.size_cells,
        })
    }
}

/// A physical `(address, size)` pair decoded from the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    /// Base address, as the tree states it. Never translated implicitly.
    pub address: u64,
    /// Length in bytes. Zero when the governing `#size-cells` is zero.
    pub size: u64,
}

/// A validated `#address-cells` / `#size-cells` pair.
///
/// Constructed only through [`CellCounts::new`], which enforces the bounds of
/// spec §8.5 and §9.8. There is no default: a missing declaration denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellCounts {
    /// Cells in an address. Always 1 or 2.
    address_cells: u32,
    /// Cells in a size. 0, 1 or 2.
    size_cells: u32,
}

impl CellCounts {
    /// Validates and constructs a cell-count pair.
    pub fn new(address_cells: u32, size_cells: u32) -> Result<Self, AdtError> {
        if address_cells == 0 || address_cells > 2 {
            return Err(AdtError::InvalidAddressCells);
        }
        if size_cells > 2 {
            return Err(AdtError::InvalidSizeCells);
        }
        Ok(Self {
            address_cells,
            size_cells,
        })
    }

    fn address_bytes(&self) -> Result<usize, AdtError> {
        (self.address_cells as usize)
            .checked_mul(U32_LEN)
            .ok_or(AdtError::RegContainerOutOfRange)
    }

    fn size_bytes(&self) -> Result<usize, AdtError> {
        (self.size_cells as usize)
            .checked_mul(U32_LEN)
            .ok_or(AdtError::RegContainerOutOfRange)
    }

    /// Bytes in one `reg` container: `(address_cells + size_cells) × 4`.
    pub fn container_len(&self) -> Result<usize, AdtError> {
        let total = self
            .address_bytes()?
            .checked_add(self.size_bytes()?)
            .ok_or(AdtError::RegContainerOutOfRange)?;
        if total == 0 {
            // COVERAGE-EXEMPT: `new` rejects `address_cells == 0` and the
            // fields are private, so `address_bytes` is at least 4 and the
            // total cannot be zero. Kept because the floor lives in `new`
            // rather than in the arithmetic here, so a change to `new` should
            // meet a denial and not a zero-length container.
            return Err(AdtError::InvalidAddressCells);
        }
        Ok(total)
    }
}

/// Reads `count` cells at `offset`, least-significant cell first.
///
/// This ordering is the opposite of an FDT's, and each cell is itself
/// little-endian (spec §8.5, §4.4).
fn read_cells(bytes: &[u8], offset: usize, count: u32) -> Result<u64, AdtError> {
    match count {
        0 => Ok(0),
        1 => {
            let low = read_u32_le(bytes, offset).ok_or(AdtError::RegContainerOutOfRange)?;
            Ok(u64::from(low))
        }
        2 => {
            let low = read_u32_le(bytes, offset).ok_or(AdtError::RegContainerOutOfRange)?;
            let high_offset = offset
                .checked_add(U32_LEN)
                .ok_or(AdtError::RegContainerOutOfRange)?;
            let high = read_u32_le(bytes, high_offset).ok_or(AdtError::RegContainerOutOfRange)?;
            let shifted = u64::from(high)
                .checked_shl(32)
                .ok_or(AdtError::RegContainerOutOfRange)?;
            Ok(u64::from(low) | shifted)
        }
        // COVERAGE-EXEMPT: `count` is always a `CellCounts` field, whose
        // constructor rejects anything above 2 and whose fields are private,
        // so no caller can reach this arm. Kept fail-closed rather than
        // deleted: an unrecognised cell count must deny, not decode.
        _ => Err(AdtError::InvalidAddressCells),
    }
}

/// Iterator over the NUL-terminated strings packed into a property value.
///
/// Terminates because `position` strictly increases on every iteration and is
/// bounded by the value length.
#[derive(Debug, Clone)]
pub struct StringIter<'a> {
    value: &'a [u8],
    position: usize,
    done: bool,
}

impl<'a> Iterator for StringIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.done {
                // Reached on a LATER call, after the value ran out and set
                // the flag. Pinned by
                // `an_exhausted_string_iterator_keeps_returning_none`.
                return None;
            }
            let rest = match self.value.get(self.position..) {
                Some(rest) => rest,
                None => {
                    // COVERAGE-EXEMPT: `position` only ever becomes
                    // `terminator + 1`, and `terminator` indexes inside `rest`,
                    // so it tops out at exactly `value.len()`, where
                    // `get(len..)` is `Some("")` and the emptiness check below
                    // handles it. A fact about this loop, not about the tree.
                    self.done = true;
                    return None;
                }
            };
            if rest.is_empty() {
                self.done = true;
                return None;
            }
            let terminator = match rest.iter().position(|byte| *byte == 0) {
                Some(index) => index,
                None => {
                    // A tail with no NUL is not an entry (spec §8.1).
                    self.done = true;
                    return None;
                }
            };
            let entry = match rest.get(..terminator) {
                Some(entry) => entry,
                None => {
                    // COVERAGE-EXEMPT: `terminator` is the index `position`
                    // just found inside `rest`, so it is strictly less than
                    // `rest.len()` and the cut is always present. Kept because
                    // the search and the cut are separate statements: an edit
                    // to what is searched must meet a denial.
                    self.done = true;
                    return None;
                }
            };
            let advanced = self
                .position
                .checked_add(terminator)
                .and_then(|next| next.checked_add(1));
            self.position = match advanced {
                Some(next) => next,
                None => {
                    // COVERAGE-EXEMPT: `position + terminator + 1` overflows
                    // only near `usize::MAX`, and both are offsets into a slice
                    // that exists, so their sum is bounded by its length.
                    // `checked_add` because this value advances the cursor, and
                    // a wrap here is an iterator that restarts instead of
                    // ending.
                    self.done = true;
                    return None;
                }
            };
            if entry.is_empty() {
                // Zero padding, not an entry. Ordinary data: spec section 8.1
                // pads values to a 4-byte boundary, so two NULs in a row is the
                // common case and this is the normal path. Pinned by
                // `empty_entries_between_terminators_are_skipped_rather_than_yielded`.
                continue;
            }
            return Some(entry);
        }
    }
}

/// One decoded `ranges` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RangesEntry {
    /// Base of the window in the child address space.
    pub child_address: u64,
    /// Base of the same window in the parent address space.
    pub parent_address: u64,
    /// Length of the window.
    pub child_size: u64,
}

impl RangesEntry {
    /// Translates `(address, size)` through this entry, or `None` if the
    /// window does not wholly contain it.
    ///
    /// Both containment sums are attacker-controlled, so both are computed
    /// with checked arithmetic; an overflow denies rather than wrapping into
    /// an apparent match.
    pub fn translate(&self, range: AddressRange) -> Result<Option<u64>, AdtError> {
        let request_end = range
            .address
            .checked_add(range.size)
            .ok_or(AdtError::TranslationOverflow)?;
        let window_end = self
            .child_address
            .checked_add(self.child_size)
            .ok_or(AdtError::TranslationOverflow)?;
        if range.address < self.child_address || request_end > window_end {
            return Ok(None);
        }
        let offset_in_window = range
            .address
            .checked_sub(self.child_address)
            .ok_or(AdtError::TranslationOverflow)?;
        let translated = offset_in_window
            .checked_add(self.parent_address)
            .ok_or(AdtError::TranslationOverflow)?;
        Ok(Some(translated))
    }
}

/// Iterator over the entries of a `ranges` property.
///
/// Yields only whole entries; a trailing partial entry is ignored. Terminates
/// because `position` advances by a non-zero `entry_len` each step.
#[derive(Debug, Clone)]
pub struct RangesIter<'a> {
    value: &'a [u8],
    position: usize,
    entry_len: usize,
    child_address_cells: u32,
    parent_address_cells: u32,
    size_cells: u32,
}

impl Iterator for RangesIter<'_> {
    type Item = Result<RangesEntry, AdtError>;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.position.checked_add(self.entry_len)?;
        if end > self.value.len() {
            return None;
        }
        let start = self.position;
        self.position = end;

        let child_address = match read_cells(self.value, start, self.child_address_cells) {
            Ok(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            Err(error) => return Some(Err(error)),
        };
        let child_address_bytes = match (self.child_address_cells as usize).checked_mul(U32_LEN) {
            Some(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let parent_offset = match start.checked_add(child_address_bytes) {
            Some(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let parent_address = match read_cells(self.value, parent_offset, self.parent_address_cells)
        {
            Ok(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            Err(error) => return Some(Err(error)),
        };
        let parent_address_bytes = match (self.parent_address_cells as usize).checked_mul(U32_LEN) {
            Some(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let size_offset = match parent_offset.checked_add(parent_address_bytes) {
            Some(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let child_size = match read_cells(self.value, size_offset, self.size_cells) {
            Ok(value) => value,
            // COVERAGE-EXEMPT: unreachable by construction of this iterator rather
            // than by validation of the tree. `ranges` refuses a parent count outside
            // 1..=2 and `CellCounts::new` bounds the child pair, so every `count` here
            // is at most 2 and every `x U32_LEN` fits; and `next` returns `None`
            // unless a whole `entry_len` is present, so each read lands inside the
            // entry. Kept because both of those facts live in other functions.
            Err(error) => return Some(Err(error)),
        };

        Some(Ok(RangesEntry {
            child_address,
            parent_address,
            child_size,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 32-byte name field holding `name`, NUL-padded, as the wire format has it.
    fn field(name: &[u8]) -> [u8; PROPERTY_NAME_LEN] {
        let mut bytes = [0u8; PROPERTY_NAME_LEN];
        for (slot, byte) in bytes.iter_mut().zip(name.iter()) {
            *slot = *byte;
        }
        bytes
    }

    /// `Property::new` is `pub(crate)`, which is what makes these reachable.
    ///
    /// Every guard below was exempt from the coverage gate on the grounds that
    /// `DeviceTree::parse` validates the tree before any cursor exists, so a
    /// malformed record cannot reach an accessor. That is true of the public
    /// API -- `DeviceTree`'s fields are private and `parse` is its only
    /// constructor -- and it is exactly why these paths were never executed.
    ///
    /// It also made "fails closed" an assertion rather than a fact. From inside
    /// the crate the constructor is reachable, so the malformed record can be
    /// built directly and the guards can be made to run. No public surface is
    /// added and no encapsulation is weakened; the tests simply stand where a
    /// future constructor that skips validation would stand.
    #[test]
    fn a_name_field_with_no_terminator_yields_the_whole_field() {
        // Every byte non-NUL: the decoder refuses this at parse time, so only
        // a constructor that skipped validation could produce it.
        let unterminated = [b'x'; PROPERTY_NAME_LEN];
        let property = Property::new(&unterminated, &[]);

        // The whole field, and not one byte more. Reading past it is the bug
        // this guard exists to prevent.
        assert_eq!(property.name(), &unterminated[..]);
        assert_eq!(property.name().len(), PROPERTY_NAME_LEN);
    }

    #[test]
    fn a_name_longer_than_the_field_matches_nothing() {
        let named = field(b"compatible");
        let property = Property::new(&named, &[]);

        assert!(property.is_named(b"compatible"));

        // Longer than the field can hold, so it cannot be this property's name
        // whatever the field contains. The comparison is refused before the
        // name is even decoded.
        let too_long = [b'a'; PROPERTY_NAME_LEN + 1];
        assert!(!property.is_named(&too_long));

        // And the boundary itself is not refused: exactly 32 bytes is a legal
        // question to ask, it simply does not match here.
        let exactly_full = [b'a'; PROPERTY_NAME_LEN];
        assert!(!property.is_named(&exactly_full));
    }

    #[test]
    fn a_u64_value_decodes_little_endian_and_a_wrong_length_is_refused() {
        let named = field(b"reg");
        let value = 0x0123_4567_89ab_cdef_u64.to_le_bytes();
        let property = Property::new(&named, &value);
        assert_eq!(property.as_u64(), Ok(0x0123_4567_89ab_cdef));

        // Seven bytes is not eight, and the refusal is by length rather than
        // by reading what happens to be there.
        let short = Property::new(&named, &value[..7]);
        assert_eq!(short.as_u64(), Err(AdtError::PropertyLengthMismatch));

        // Nine is equally wrong. A parser that accepted "at least eight" would
        // silently ignore a trailing byte the producer meant to be read.
        let mut long = [0u8; U64_LEN + 1];
        for (slot, byte) in long.iter_mut().zip(value.iter()) {
            *slot = *byte;
        }
        let over = Property::new(&named, &long);
        assert_eq!(over.as_u64(), Err(AdtError::PropertyLengthMismatch));
    }

    /// Empty entries between NULs are padding, which is normal data.
    ///
    /// The `continue` that skips them carried a marker saying a parsed tree
    /// "cannot meet a malformed record". Padding is not malformed -- spec
    /// section 8.1 has values NUL-padded to a 4-byte boundary, so a run of two
    /// NULs in a row is the ordinary case, and the branch that skips it is on
    /// the normal path rather than a defensive one.
    #[test]
    fn empty_entries_between_terminators_are_skipped_rather_than_yielded() {
        let name = field(b"compatible");
        let property = Property::new(&name, b"first\0\0second\0\0\0");
        let mut strings = property.strings();
        assert_eq!(strings.next(), Some(&b"first"[..]));
        assert_eq!(
            strings.next(),
            Some(&b"second"[..]),
            "the empty entry between them is padding, not a third string"
        );
        assert_eq!(strings.next(), None);
    }

    /// An exhausted iterator stays exhausted.
    ///
    /// `done` is set when the value runs out, and the check for it at the top
    /// of the loop only runs on a LATER call. Nothing reached it because every
    /// test collects, and `collect` stops at the first `None` and never asks
    /// again. A caller that does ask again must get `None`, not a re-read of
    /// the tail.
    #[test]
    fn an_exhausted_string_iterator_keeps_returning_none() {
        let name = field(b"compatible");
        let property = Property::new(&name, b"only\0");
        let mut strings = property.strings();
        assert_eq!(strings.next(), Some(&b"only"[..]));
        assert_eq!(strings.next(), None, "the value is spent");
        assert_eq!(strings.next(), None, "and asking again changes nothing");
        assert_eq!(strings.next(), None);
    }

    /// The same for a value whose tail has no terminator at all.
    #[test]
    fn an_unterminated_tail_ends_the_iterator_and_keeps_it_ended() {
        let name = field(b"compatible");
        let property = Property::new(&name, b"good\0trailing");
        let mut strings = property.strings();
        assert_eq!(strings.next(), Some(&b"good"[..]));
        assert_eq!(strings.next(), None, "a tail with no NUL is not an entry");
        assert_eq!(strings.next(), None);
    }
}
