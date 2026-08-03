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
    pub address_cells: u32,
    /// Cells in a size. 0, 1 or 2.
    pub size_cells: u32,
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
                return None;
            }
            let rest = match self.value.get(self.position..) {
                Some(rest) => rest,
                None => {
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
                    self.done = true;
                    return None;
                }
            };
            if entry.is_empty() {
                // Zero padding, not an entry.
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
            Err(error) => return Some(Err(error)),
        };
        let child_address_bytes = match (self.child_address_cells as usize).checked_mul(U32_LEN) {
            Some(value) => value,
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let parent_offset = match start.checked_add(child_address_bytes) {
            Some(value) => value,
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let parent_address = match read_cells(self.value, parent_offset, self.parent_address_cells)
        {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };
        let parent_address_bytes = match (self.parent_address_cells as usize).checked_mul(U32_LEN) {
            Some(value) => value,
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let size_offset = match parent_offset.checked_add(parent_address_bytes) {
            Some(value) => value,
            None => return Some(Err(AdtError::MalformedRangesEntry)),
        };
        let child_size = match read_cells(self.value, size_offset, self.size_cells) {
            Ok(value) => value,
            Err(error) => return Some(Err(error)),
        };

        Some(Ok(RangesEntry {
            child_address,
            parent_address,
            child_size,
        }))
    }
}
