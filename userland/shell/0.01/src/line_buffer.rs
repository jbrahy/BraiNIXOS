//! Fixed-capacity buffer holding the line the user is currently typing.
//!
//! The shell has no allocator, so the working line lives in a single
//! BSS-backed `[u8; LINE_CAPACITY_IN_BYTES]` array. Edits performed by the
//! REPL — append a printable byte, erase the last byte, erase the last
//! whitespace-delimited word, erase the entire line, or replace the
//! contents with a history entry — flow through this type's small API.
//!
//! Erase-word semantics match readline's `unix-word-rubout`: strip
//! trailing whitespace, then strip trailing non-whitespace. Whitespace is
//! ASCII space (0x20) or tab (0x09).
//!
//! No unsafe, no panics, no allocations.

/// Maximum number of bytes a single shell line can hold.
///
/// 256 bytes covers every realistic command on a serial console while
/// keeping the BSS footprint negligible compared to the 4 MiB userland
/// region. Re-exported here so the history module can match the line
/// width without independently picking a constant.
pub const LINE_CAPACITY_IN_BYTES: usize = 256;

/// ASCII space byte.
const SPACE_BYTE: u8 = 0x20;

/// ASCII horizontal tab byte.
const HORIZONTAL_TAB_BYTE: u8 = 0x09;

/// The line currently being typed.
///
/// Holds a fixed-size byte array plus a populated-prefix length. The bytes
/// beyond `length` are not part of the user's input.
pub struct CurrentLineBuffer {
    bytes: [u8; LINE_CAPACITY_IN_BYTES],
    length: usize,
}

impl CurrentLineBuffer {
    /// Returns a freshly-emptied buffer (length 0, contents zero).
    pub const fn new() -> Self {
        Self {
            bytes: [0; LINE_CAPACITY_IN_BYTES],
            length: 0,
        }
    }

    /// Number of populated bytes (everything to the left of the cursor).
    pub fn length(&self) -> usize {
        self.length
    }

    /// Returns true when no further append would succeed without an erase.
    pub fn is_at_capacity(&self) -> bool {
        self.length >= LINE_CAPACITY_IN_BYTES
    }

    /// Borrows the populated prefix of the buffer for inspection or echo.
    pub fn as_byte_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }

    /// Appends one byte. Returns `true` if the byte fit, `false` if the
    /// buffer was already at capacity (and therefore unchanged).
    pub fn append_printable_byte(&mut self, byte: u8) -> bool {
        if self.is_at_capacity() {
            return false;
        }
        self.bytes[self.length] = byte;
        self.length = self.length.saturating_add(1);
        true
    }

    /// Removes the last byte. Returns `true` if a byte was removed,
    /// `false` if the buffer was already empty.
    pub fn erase_last_character(&mut self) -> bool {
        if self.length == 0 {
            return false;
        }
        self.length = self.length.saturating_sub(1);
        true
    }

    /// Strips trailing whitespace, then trailing non-whitespace. Returns
    /// the number of bytes that were removed (zero if the buffer was
    /// empty).
    pub fn erase_last_word(&mut self) -> usize {
        let original_length = self.length;
        self.length = strip_trailing_run(&self.bytes, self.length, is_whitespace_byte);
        self.length = strip_trailing_run(&self.bytes, self.length, is_non_whitespace_byte);
        original_length.saturating_sub(self.length)
    }

    /// Resets the buffer to empty. Returns the number of bytes that were
    /// in the buffer prior to the call.
    pub fn erase_entire_line(&mut self) -> usize {
        let previous_length = self.length;
        self.length = 0;
        previous_length
    }

    /// Replaces the buffer contents with `source`, truncating to capacity
    /// if `source` is too long.
    pub fn replace_with_byte_slice(&mut self, source: &[u8]) {
        let copy_length = source.len().min(LINE_CAPACITY_IN_BYTES);
        self.bytes[..copy_length].copy_from_slice(&source[..copy_length]);
        self.length = copy_length;
    }
}

impl Default for CurrentLineBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Walks back from `current_length` while the predicate matches, returning
/// the resulting length. Used to peel off trailing whitespace runs and
/// trailing non-whitespace runs during `erase_last_word`.
fn strip_trailing_run(bytes: &[u8], current_length: usize, predicate: fn(u8) -> bool) -> usize {
    let mut length = current_length;
    while length > 0 && predicate(bytes[length.saturating_sub(1)]) {
        length = length.saturating_sub(1);
    }
    length
}

fn is_whitespace_byte(byte: u8) -> bool {
    byte == SPACE_BYTE || byte == HORIZONTAL_TAB_BYTE
}

fn is_non_whitespace_byte(byte: u8) -> bool {
    !is_whitespace_byte(byte)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_buffer_is_empty() {
        let buffer = CurrentLineBuffer::new();
        assert_eq!(buffer.length(), 0);
        assert_eq!(buffer.as_byte_slice(), b"");
        assert!(!buffer.is_at_capacity());
    }

    #[test]
    fn default_buffer_is_empty() {
        let buffer = CurrentLineBuffer::default();
        assert_eq!(buffer.length(), 0);
    }

    #[test]
    fn appending_within_capacity_grows_length_and_returns_true() {
        let mut buffer = CurrentLineBuffer::new();
        assert!(buffer.append_printable_byte(b'a'));
        assert!(buffer.append_printable_byte(b'b'));
        assert_eq!(buffer.length(), 2);
        assert_eq!(buffer.as_byte_slice(), b"ab");
    }

    #[test]
    fn appending_at_capacity_returns_false_and_leaves_buffer_unchanged() {
        let mut buffer = CurrentLineBuffer::new();
        for _ in 0..LINE_CAPACITY_IN_BYTES {
            assert!(buffer.append_printable_byte(b'x'));
        }
        assert!(buffer.is_at_capacity());
        assert!(!buffer.append_printable_byte(b'y'));
        assert_eq!(buffer.length(), LINE_CAPACITY_IN_BYTES);
        assert_eq!(buffer.as_byte_slice()[LINE_CAPACITY_IN_BYTES - 1], b'x');
    }

    #[test]
    fn erase_last_character_on_empty_buffer_returns_false() {
        let mut buffer = CurrentLineBuffer::new();
        assert!(!buffer.erase_last_character());
        assert_eq!(buffer.length(), 0);
    }

    #[test]
    fn erase_last_character_removes_one_byte_and_returns_true() {
        let mut buffer = CurrentLineBuffer::new();
        let _ = buffer.append_printable_byte(b'a');
        let _ = buffer.append_printable_byte(b'b');
        assert!(buffer.erase_last_character());
        assert_eq!(buffer.as_byte_slice(), b"a");
    }

    #[test]
    fn erase_last_word_on_empty_buffer_returns_zero() {
        let mut buffer = CurrentLineBuffer::new();
        assert_eq!(buffer.erase_last_word(), 0);
    }

    #[test]
    fn erase_last_word_strips_trailing_word_with_no_trailing_whitespace() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"hello world" {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_last_word(), 5);
        assert_eq!(buffer.as_byte_slice(), b"hello ");
    }

    #[test]
    fn erase_last_word_strips_trailing_whitespace_first_then_word() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"hello   world   " {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_last_word(), 8);
        assert_eq!(buffer.as_byte_slice(), b"hello   ");
    }

    #[test]
    fn erase_last_word_strips_only_whitespace_when_buffer_is_all_whitespace() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"   " {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_last_word(), 3);
        assert_eq!(buffer.length(), 0);
    }

    #[test]
    fn erase_last_word_strips_only_the_single_token_when_no_whitespace_present() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"hello" {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_last_word(), 5);
        assert_eq!(buffer.length(), 0);
    }

    #[test]
    fn erase_last_word_treats_horizontal_tab_as_whitespace() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"hello\tworld" {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_last_word(), 5);
        assert_eq!(buffer.as_byte_slice(), b"hello\t");
    }

    #[test]
    fn erase_entire_line_returns_previous_length_and_clears_buffer() {
        let mut buffer = CurrentLineBuffer::new();
        for byte in b"abcd" {
            assert!(buffer.append_printable_byte(*byte));
        }
        assert_eq!(buffer.erase_entire_line(), 4);
        assert_eq!(buffer.length(), 0);
    }

    #[test]
    fn replace_with_byte_slice_copies_and_resets_length() {
        let mut buffer = CurrentLineBuffer::new();
        let _ = buffer.append_printable_byte(b'x');
        buffer.replace_with_byte_slice(b"ls -la");
        assert_eq!(buffer.as_byte_slice(), b"ls -la");
    }

    #[test]
    fn replace_with_oversized_slice_truncates_to_capacity() {
        let mut buffer = CurrentLineBuffer::new();
        let oversized = [b'q'; LINE_CAPACITY_IN_BYTES + 32];
        buffer.replace_with_byte_slice(&oversized);
        assert_eq!(buffer.length(), LINE_CAPACITY_IN_BYTES);
        assert!(buffer.is_at_capacity());
    }

    #[test]
    fn replace_with_empty_slice_yields_empty_buffer() {
        let mut buffer = CurrentLineBuffer::new();
        let _ = buffer.append_printable_byte(b'x');
        buffer.replace_with_byte_slice(b"");
        assert_eq!(buffer.length(), 0);
    }
}
