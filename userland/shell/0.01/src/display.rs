//! Serial-side display helpers for the shell line editor.
//!
//! The shell needs a small set of write primitives — echo one printable
//! byte, emit the `0x08 0x20 0x08` erase-last sequence, redraw the prompt
//! and current line after a history swap — and the bare-metal binary
//! ultimately calls `syscall_serial_write_byte` for each byte that goes
//! out. To make this layer unit-testable on the host without poking at
//! the COM1 syscall, the actual write target is abstracted behind the
//! [`ByteSink`] trait. Production code uses [`SerialByteSink`], which
//! forwards into `brainix_libsyscall::syscall_serial_write_byte`; tests
//! inject a `Vec<u8>`-backed sink and assert on the captured stream.
//!
//! No unsafe. No alloc in production paths. Tests use `alloc::vec::Vec`
//! solely to capture output for assertions.

use brainix_libsyscall::syscall_serial_write_byte;

/// The shell prompt, written immediately after `\r\x1b[K` or `\r\n`.
pub const PROMPT_BYTES: &[u8] = b"$ ";

/// `Backspace, Space, Backspace` — the canonical ASCII way to erase the
/// last character visually on a serial terminal that has no cursor
/// addressing beyond `\b`.
const ERASE_LAST_CHARACTER_SEQUENCE: &[u8] = b"\x08 \x08";

/// `\r ESC [ K` — carriage return, then ANSI "clear to end of line".
/// Used to wipe the current physical line before redrawing the prompt
/// and a new buffer (history recall, Ctrl-U).
const CARRIAGE_RETURN_AND_CLEAR_TO_END_OF_LINE: &[u8] = b"\r\x1b[K";

/// `\r\n` — newline pair emitted on Enter and on shell exit.
const CARRIAGE_RETURN_LINE_FEED: &[u8] = b"\r\n";

/// Abstract one-byte sink. Production code uses [`SerialByteSink`];
/// tests inject a `Vec<u8>`-backed capturing implementation.
pub trait ByteSink {
    fn write_byte(&mut self, value: u8);
}

/// Production [`ByteSink`] that forwards each byte to
/// `syscall_serial_write_byte`. Zero-sized; instantiate freely.
pub struct SerialByteSink;

impl ByteSink for SerialByteSink {
    fn write_byte(&mut self, value: u8) {
        let _ = syscall_serial_write_byte(value);
    }
}

/// Writes every byte in `bytes` to `sink` in order. Used internally by
/// the helpers below.
pub fn write_byte_slice<S: ByteSink>(sink: &mut S, bytes: &[u8]) {
    for byte in bytes {
        sink.write_byte(*byte);
    }
}

/// Echoes a single printable byte. Equivalent to `sink.write_byte(byte)`;
/// kept as a named helper so the REPL reads as a stream of intent-named
/// calls rather than raw trait invocations.
pub fn echo_printable_byte<S: ByteSink>(sink: &mut S, byte: u8) {
    sink.write_byte(byte);
}

/// Emits one `Backspace, Space, Backspace` sequence — one visual erase.
pub fn emit_erase_last_character<S: ByteSink>(sink: &mut S) {
    write_byte_slice(sink, ERASE_LAST_CHARACTER_SEQUENCE);
}

/// Emits the erase-last-character sequence `count` times. Used for
/// Ctrl-W (kill last word) where the line-buffer reports how many bytes
/// it removed so the display can emit exactly that many erases — much
/// cheaper than a full redraw on the common single-word case.
pub fn emit_erase_last_character_repeated<S: ByteSink>(sink: &mut S, count: usize) {
    for _ in 0..count {
        emit_erase_last_character(sink);
    }
}

/// Writes the canonical `\r\n`.
pub fn write_carriage_return_line_feed<S: ByteSink>(sink: &mut S) {
    write_byte_slice(sink, CARRIAGE_RETURN_LINE_FEED);
}

/// Writes the shell prompt (`PROMPT_BYTES`).
pub fn write_prompt<S: ByteSink>(sink: &mut S) {
    write_byte_slice(sink, PROMPT_BYTES);
}

/// Erases the current physical line and redraws it as
/// `<prompt><current_line>`. Used for Ctrl-U (line was zeroed) and for
/// `↑` / `↓` history navigation (line was replaced with an entry).
pub fn redraw_prompt_and_current_line<S: ByteSink>(sink: &mut S, current_line: &[u8]) {
    write_byte_slice(sink, CARRIAGE_RETURN_AND_CLEAR_TO_END_OF_LINE);
    write_prompt(sink);
    write_byte_slice(sink, current_line);
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    struct CapturingByteSink {
        captured_bytes: Vec<u8>,
    }

    impl CapturingByteSink {
        fn new() -> Self {
            Self {
                captured_bytes: Vec::new(),
            }
        }

        fn captured_bytes(&self) -> &[u8] {
            &self.captured_bytes
        }
    }

    impl ByteSink for CapturingByteSink {
        fn write_byte(&mut self, value: u8) {
            self.captured_bytes.push(value);
        }
    }

    #[test]
    fn echo_printable_byte_writes_exactly_that_byte() {
        let mut sink = CapturingByteSink::new();
        echo_printable_byte(&mut sink, b'q');
        assert_eq!(sink.captured_bytes(), &[b'q']);
    }

    #[test]
    fn emit_erase_last_character_writes_backspace_space_backspace() {
        let mut sink = CapturingByteSink::new();
        emit_erase_last_character(&mut sink);
        assert_eq!(sink.captured_bytes(), &[0x08, 0x20, 0x08]);
    }

    #[test]
    fn emit_erase_repeated_zero_count_writes_nothing() {
        let mut sink = CapturingByteSink::new();
        emit_erase_last_character_repeated(&mut sink, 0);
        assert_eq!(sink.captured_bytes(), &[]);
    }

    #[test]
    fn emit_erase_repeated_three_writes_nine_bytes() {
        let mut sink = CapturingByteSink::new();
        emit_erase_last_character_repeated(&mut sink, 3);
        let expected = [0x08, 0x20, 0x08, 0x08, 0x20, 0x08, 0x08, 0x20, 0x08];
        assert_eq!(sink.captured_bytes(), &expected);
    }

    #[test]
    fn write_carriage_return_line_feed_writes_crlf() {
        let mut sink = CapturingByteSink::new();
        write_carriage_return_line_feed(&mut sink);
        assert_eq!(sink.captured_bytes(), b"\r\n");
    }

    #[test]
    fn write_prompt_writes_dollar_space() {
        let mut sink = CapturingByteSink::new();
        write_prompt(&mut sink);
        assert_eq!(sink.captured_bytes(), b"$ ");
    }

    #[test]
    fn redraw_prompt_and_current_line_emits_clear_prompt_and_line() {
        let mut sink = CapturingByteSink::new();
        redraw_prompt_and_current_line(&mut sink, b"ls -la");
        assert_eq!(sink.captured_bytes(), b"\r\x1b[K$ ls -la");
    }

    #[test]
    fn redraw_with_empty_line_only_clears_and_writes_prompt() {
        let mut sink = CapturingByteSink::new();
        redraw_prompt_and_current_line(&mut sink, b"");
        assert_eq!(sink.captured_bytes(), b"\r\x1b[K$ ");
    }

    #[test]
    fn write_byte_slice_preserves_order() {
        let mut sink = CapturingByteSink::new();
        write_byte_slice(&mut sink, b"abc");
        assert_eq!(sink.captured_bytes(), b"abc");
    }
}
