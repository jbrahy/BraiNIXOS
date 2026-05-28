//! Fixed-capacity command history for the shell line editor.
//!
//! Two types make up the history feature:
//!
//! * [`HistoryRing`] — a ring buffer of 16 entries, each up to 256 bytes
//!   (`LINE_CAPACITY_IN_BYTES`). Committed non-empty lines are pushed in;
//!   the oldest entry is overwritten when the ring is full.
//! * [`HistoryNavigationCursor`] — the user's position within the ring
//!   while pressing `↑` / `↓`. The cursor knows whether the user is on
//!   the working line they were typing or on a specific past entry.
//!
//! The REPL also keeps a "working-line snapshot" — the bytes the user
//! had typed before pressing `↑` for the first time — so pressing `↓`
//! past the newest entry can restore them. That snapshot lives in the
//! REPL, not here: this module is purely about the ring and the cursor.
//!
//! No alloc, no unsafe.

use crate::line_buffer::LINE_CAPACITY_IN_BYTES;

/// Maximum number of distinct lines retained in history.
pub const HISTORY_ENTRY_CAPACITY: usize = 16;

/// Bitmask for `% HISTORY_ENTRY_CAPACITY`. `HISTORY_ENTRY_CAPACITY` must
/// remain a power of two for this to hold; the `const` assertion below
/// guards against an accidental change.
const HISTORY_ENTRY_INDEX_MASK: usize = 0xF;
const _: () = assert!(
    HISTORY_ENTRY_INDEX_MASK + 1 == HISTORY_ENTRY_CAPACITY,
    "HISTORY_ENTRY_INDEX_MASK must equal HISTORY_ENTRY_CAPACITY - 1",
);

/// One stored command line.
#[derive(Copy, Clone)]
pub struct HistoryEntry {
    bytes: [u8; LINE_CAPACITY_IN_BYTES],
    length: usize,
}

impl HistoryEntry {
    /// Empty entry; used as the initial value for every slot in the ring.
    pub const fn new() -> Self {
        Self {
            bytes: [0; LINE_CAPACITY_IN_BYTES],
            length: 0,
        }
    }

    /// Borrows the populated prefix for copying into the current-line
    /// buffer or for display.
    pub fn as_byte_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Number of populated bytes in this entry.
    pub fn length(&self) -> usize {
        self.length
    }

    /// Overwrites this entry with `source`, truncating to capacity.
    pub fn replace_with_byte_slice(&mut self, source: &[u8]) {
        let copy_length = source.len().min(LINE_CAPACITY_IN_BYTES);
        self.bytes[..copy_length].copy_from_slice(&source[..copy_length]);
        self.length = copy_length;
    }
}

impl Default for HistoryEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Ring buffer of committed command lines.
///
/// Entries are stored in physical insertion order; `entry_at_offset_from_newest`
/// translates the "how far back from now" view used by the cursor into
/// the underlying physical index using wrapping arithmetic on a power-of-
/// two ring.
pub struct HistoryRing {
    entries: [HistoryEntry; HISTORY_ENTRY_CAPACITY],
    next_write_index: usize,
    entry_count: usize,
}

impl HistoryRing {
    /// Empty history.
    pub const fn new() -> Self {
        Self {
            entries: [const { HistoryEntry::new() }; HISTORY_ENTRY_CAPACITY],
            next_write_index: 0,
            entry_count: 0,
        }
    }

    /// Number of populated entries in the ring (saturates at capacity).
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Stores `bytes` as the newest entry, overwriting the oldest if the
    /// ring is full. Empty input is silently dropped — pressing Enter on
    /// a blank line does not pollute history. Returns `true` if a write
    /// actually occurred.
    pub fn record_committed_line(&mut self, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        self.entries[self.next_write_index].replace_with_byte_slice(bytes);
        self.advance_write_index();
        self.bump_entry_count_up_to_capacity();
        true
    }

    /// Returns the entry that is `offset_from_newest` positions back from
    /// the most recent (0 = newest). `None` if the offset exceeds the
    /// number of stored entries.
    pub fn entry_at_offset_from_newest(
        &self,
        offset_from_newest: usize,
    ) -> Option<&HistoryEntry> {
        if offset_from_newest >= self.entry_count {
            return None;
        }
        let entry_index = self.compute_entry_index_for_offset(offset_from_newest);
        Some(&self.entries[entry_index])
    }

    fn advance_write_index(&mut self) {
        self.next_write_index =
            self.next_write_index.saturating_add(1) & HISTORY_ENTRY_INDEX_MASK;
    }

    fn bump_entry_count_up_to_capacity(&mut self) {
        if self.entry_count < HISTORY_ENTRY_CAPACITY {
            self.entry_count = self.entry_count.saturating_add(1);
        }
    }

    /// Wrapping subtraction on the ring: `newest_index = next_write_index - 1`
    /// (mod capacity), and `entry_at_offset(n) = newest_index - n` (mod
    /// capacity). Implemented with `wrapping_sub` + bitmask to satisfy
    /// the workspace `clippy::arithmetic_side_effects` lint.
    fn compute_entry_index_for_offset(&self, offset_from_newest: usize) -> usize {
        self.next_write_index
            .wrapping_sub(1)
            .wrapping_sub(offset_from_newest)
            & HISTORY_ENTRY_INDEX_MASK
    }
}

impl Default for HistoryRing {
    fn default() -> Self {
        Self::new()
    }
}

/// The user's `↑` / `↓` position within the history ring.
///
/// `None` means the user is editing the working line (whatever they
/// were typing before any `↑` press). `Some(n)` means they are viewing
/// entry `n` positions back from the newest.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct HistoryNavigationCursor {
    selected_offset_from_newest: Option<usize>,
}

impl HistoryNavigationCursor {
    /// Cursor anchored on the working line (no history entry selected).
    pub const fn new() -> Self {
        Self {
            selected_offset_from_newest: None,
        }
    }

    /// Returns `true` when the cursor is on the working line (i.e. no
    /// history entry is currently selected).
    pub fn is_on_working_line(&self) -> bool {
        self.selected_offset_from_newest.is_none()
    }

    /// Current history offset, or `None` when on the working line.
    pub fn current_offset_from_newest(&self) -> Option<usize> {
        self.selected_offset_from_newest
    }

    /// Moves the cursor one step into the past. From the working line
    /// this lands on the newest entry; from entry `n` it lands on
    /// entry `n + 1`. Returns `true` if the cursor moved, `false` if it
    /// was already at the oldest entry (or the ring is empty).
    pub fn navigate_to_previous_entry(&mut self, ring: &HistoryRing) -> bool {
        let candidate_offset = self.compute_next_previous_offset();
        if candidate_offset >= ring.entry_count() {
            return false;
        }
        self.selected_offset_from_newest = Some(candidate_offset);
        true
    }

    /// Moves the cursor one step toward the present. From entry 0 this
    /// lands back on the working line. Returns `true` if the cursor
    /// moved, `false` if it was already on the working line.
    pub fn navigate_to_next_entry(&mut self) -> bool {
        let current_offset = match self.selected_offset_from_newest {
            None => return false,
            Some(offset) => offset,
        };
        self.selected_offset_from_newest = compute_next_state_for_navigate_next(current_offset);
        true
    }

    /// Resets the cursor to the working line. Called by the REPL after
    /// committing a line so the next `↑` starts from the present again.
    pub fn reset_to_working_line(&mut self) {
        self.selected_offset_from_newest = None;
    }

    fn compute_next_previous_offset(&self) -> usize {
        match self.selected_offset_from_newest {
            None => 0,
            Some(current) => current.saturating_add(1),
        }
    }
}

impl Default for HistoryNavigationCursor {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_next_state_for_navigate_next(current_offset: usize) -> Option<usize> {
    if current_offset == 0 {
        return None;
    }
    Some(current_offset.saturating_sub(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_ring_is_empty() {
        let ring = HistoryRing::new();
        assert_eq!(ring.entry_count(), 0);
        assert!(ring.entry_at_offset_from_newest(0).is_none());
    }

    #[test]
    fn default_ring_is_empty() {
        let ring = HistoryRing::default();
        assert_eq!(ring.entry_count(), 0);
    }

    #[test]
    fn recording_non_empty_line_increases_entry_count() {
        let mut ring = HistoryRing::new();
        assert!(ring.record_committed_line(b"ls"));
        assert_eq!(ring.entry_count(), 1);
    }

    #[test]
    fn recording_empty_line_does_not_change_ring() {
        let mut ring = HistoryRing::new();
        assert!(!ring.record_committed_line(b""));
        assert_eq!(ring.entry_count(), 0);
    }

    #[test]
    fn newest_entry_is_reported_at_offset_zero() {
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"first");
        ring.record_committed_line(b"second");
        let newest = ring.entry_at_offset_from_newest(0).unwrap();
        assert_eq!(newest.as_byte_slice(), b"second");
    }

    #[test]
    fn second_newest_entry_is_at_offset_one() {
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"first");
        ring.record_committed_line(b"second");
        let second_newest = ring.entry_at_offset_from_newest(1).unwrap();
        assert_eq!(second_newest.as_byte_slice(), b"first");
    }

    #[test]
    fn ring_at_capacity_overwrites_oldest_entry() {
        let mut ring = HistoryRing::new();
        for index in 0..HISTORY_ENTRY_CAPACITY {
            let label = [b'a', b'0'.wrapping_add(index as u8)];
            ring.record_committed_line(&label);
        }
        assert_eq!(ring.entry_count(), HISTORY_ENTRY_CAPACITY);
        ring.record_committed_line(b"overflow");
        assert_eq!(ring.entry_count(), HISTORY_ENTRY_CAPACITY);
        assert_eq!(
            ring.entry_at_offset_from_newest(0).unwrap().as_byte_slice(),
            b"overflow"
        );
    }

    #[test]
    fn entry_at_offset_beyond_count_returns_none() {
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"only");
        assert!(ring.entry_at_offset_from_newest(1).is_none());
    }

    #[test]
    fn entry_at_offset_on_empty_ring_returns_none() {
        let ring = HistoryRing::new();
        assert!(ring.entry_at_offset_from_newest(0).is_none());
    }

    #[test]
    fn entry_length_is_reported() {
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"abcd");
        let entry = ring.entry_at_offset_from_newest(0).unwrap();
        assert_eq!(entry.length(), 4);
    }

    #[test]
    fn replace_with_oversized_slice_truncates_to_capacity() {
        let oversized = [b'q'; LINE_CAPACITY_IN_BYTES + 10];
        let mut entry = HistoryEntry::new();
        entry.replace_with_byte_slice(&oversized);
        assert_eq!(entry.length(), LINE_CAPACITY_IN_BYTES);
    }

    #[test]
    fn new_cursor_is_on_working_line() {
        let cursor = HistoryNavigationCursor::new();
        assert!(cursor.is_on_working_line());
        assert!(cursor.current_offset_from_newest().is_none());
    }

    #[test]
    fn default_cursor_is_on_working_line() {
        let cursor = HistoryNavigationCursor::default();
        assert!(cursor.is_on_working_line());
    }

    #[test]
    fn navigate_up_from_working_line_with_empty_ring_does_not_move() {
        let mut cursor = HistoryNavigationCursor::new();
        let ring = HistoryRing::new();
        assert!(!cursor.navigate_to_previous_entry(&ring));
        assert!(cursor.is_on_working_line());
    }

    #[test]
    fn navigate_up_from_working_line_to_newest_entry() {
        let mut cursor = HistoryNavigationCursor::new();
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"only");
        assert!(cursor.navigate_to_previous_entry(&ring));
        assert_eq!(cursor.current_offset_from_newest(), Some(0));
    }

    #[test]
    fn navigate_up_stops_at_oldest_entry() {
        let mut cursor = HistoryNavigationCursor::new();
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"a");
        ring.record_committed_line(b"b");
        assert!(cursor.navigate_to_previous_entry(&ring));
        assert!(cursor.navigate_to_previous_entry(&ring));
        assert!(!cursor.navigate_to_previous_entry(&ring));
        assert_eq!(cursor.current_offset_from_newest(), Some(1));
    }

    #[test]
    fn navigate_down_from_newest_entry_returns_to_working_line() {
        let mut cursor = HistoryNavigationCursor::new();
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"a");
        cursor.navigate_to_previous_entry(&ring);
        assert!(cursor.navigate_to_next_entry());
        assert!(cursor.is_on_working_line());
    }

    #[test]
    fn navigate_down_from_working_line_does_not_move() {
        let mut cursor = HistoryNavigationCursor::new();
        assert!(!cursor.navigate_to_next_entry());
        assert!(cursor.is_on_working_line());
    }

    #[test]
    fn navigate_down_walks_toward_present_through_multiple_entries() {
        let mut cursor = HistoryNavigationCursor::new();
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"a");
        ring.record_committed_line(b"b");
        cursor.navigate_to_previous_entry(&ring);
        cursor.navigate_to_previous_entry(&ring);
        assert_eq!(cursor.current_offset_from_newest(), Some(1));
        assert!(cursor.navigate_to_next_entry());
        assert_eq!(cursor.current_offset_from_newest(), Some(0));
        assert!(cursor.navigate_to_next_entry());
        assert!(cursor.is_on_working_line());
    }

    #[test]
    fn reset_returns_cursor_to_working_line() {
        let mut cursor = HistoryNavigationCursor::new();
        let mut ring = HistoryRing::new();
        ring.record_committed_line(b"x");
        cursor.navigate_to_previous_entry(&ring);
        cursor.reset_to_working_line();
        assert!(cursor.is_on_working_line());
    }
}
