//! Committed-line → argument-vector tokenizer for the shell.
//!
//! When the user presses Enter, the committed bytes must be split into the
//! command name plus its arguments before any builtin can run. This module
//! owns that split. It mirrors zsh word-splitting closely enough for an
//! interactive console:
//!
//!   * Unquoted ASCII space (0x20) and tab (0x09) separate tokens; runs of
//!     whitespace collapse and never produce empty tokens.
//!   * `'single quotes'` group bytes literally — no escape is recognized
//!     inside them (a backslash is an ordinary byte).
//!   * `"double quotes"` group bytes, but `\"` and `\\` are escapes; any
//!     other `\x` keeps the backslash as a literal byte (there is no
//!     parameter or command expansion in this shell).
//!   * Outside quotes, `\x` takes `x` literally — so `a\ b` is one token.
//!   * Quotes abut neighboring word characters: `a"b c"d` is the single
//!     token `ab cd`; `''` is a single empty token.
//!
//! No allocation: bytes are unescaped into a fixed BSS scratch buffer and
//! each token is recorded as an `(offset, length)` span into that scratch.
//! No unsafe, no panics; every function body stays within the shell's
//! six-executable-line budget.

use crate::line_buffer::LINE_CAPACITY_IN_BYTES;

/// Maximum number of argument-vector tokens a single line can yield.
///
/// 32 covers any realistic interactive command; tokens beyond this are
/// dropped rather than allocated.
pub const MAXIMUM_TOKEN_COUNT: usize = 32;

/// ASCII space byte.
const SPACE_BYTE: u8 = 0x20;
/// ASCII horizontal tab byte.
const HORIZONTAL_TAB_BYTE: u8 = 0x09;
/// ASCII single-quote byte.
const SINGLE_QUOTE_BYTE: u8 = b'\'';
/// ASCII double-quote byte.
const DOUBLE_QUOTE_BYTE: u8 = b'"';
/// ASCII backslash byte.
const BACKSLASH_BYTE: u8 = b'\\';

/// Position of the parser within the line.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ParseState {
    /// Between tokens: whitespace is skipped; any other byte opens a token.
    Separator,
    /// Inside an unquoted run of a token.
    Unquoted,
    /// Just saw `\` while unquoted; the next byte is taken literally.
    UnquotedEscape,
    /// Inside a `'…'` single-quoted run.
    SingleQuoted,
    /// Inside a `"…"` double-quoted run.
    DoubleQuoted,
    /// Just saw `\` inside double quotes; the next byte may be an escape.
    DoubleQuotedEscape,
}

/// A line split into argument-vector tokens.
///
/// Holds the unescaped token bytes contiguously in `scratch`, plus one
/// `(offset, length)` span per token. Re-`parse` overwrites all prior state.
pub struct ParsedCommandLine {
    scratch: [u8; LINE_CAPACITY_IN_BYTES],
    scratch_length: usize,
    token_offsets: [usize; MAXIMUM_TOKEN_COUNT],
    token_lengths: [usize; MAXIMUM_TOKEN_COUNT],
    token_count: usize,
    current_token_offset: usize,
}

impl ParsedCommandLine {
    /// An empty parse result (no tokens).
    pub const fn new() -> Self {
        Self {
            scratch: [0; LINE_CAPACITY_IN_BYTES],
            scratch_length: 0,
            token_offsets: [0; MAXIMUM_TOKEN_COUNT],
            token_lengths: [0; MAXIMUM_TOKEN_COUNT],
            token_count: 0,
            current_token_offset: 0,
        }
    }

    /// Number of tokens produced by the most recent [`parse`](Self::parse).
    pub fn token_count(&self) -> usize {
        self.token_count
    }

    /// Borrows token `index` (0 = command name), or `None` if out of range.
    pub fn token(&self, index: usize) -> Option<&[u8]> {
        if index >= self.token_count {
            return None;
        }
        let offset = self.token_offsets[index];
        Some(&self.scratch[offset..offset.saturating_add(self.token_lengths[index])])
    }

    /// Splits `line` into tokens, discarding any prior result.
    pub fn parse(&mut self, line: &[u8]) {
        self.reset();
        let mut state = ParseState::Separator;
        for byte in line {
            state = self.consume_byte(state, *byte);
        }
        self.finalize_trailing_token(state);
    }

    fn reset(&mut self) {
        self.scratch_length = 0;
        self.token_count = 0;
        self.current_token_offset = 0;
    }

    fn consume_byte(&mut self, state: ParseState, byte: u8) -> ParseState {
        match state {
            ParseState::Separator => self.consume_in_separator(byte),
            ParseState::Unquoted => self.consume_in_unquoted(byte),
            ParseState::UnquotedEscape => self.consume_in_unquoted_escape(byte),
            ParseState::SingleQuoted => self.consume_in_single_quoted(byte),
            ParseState::DoubleQuoted => self.consume_in_double_quoted(byte),
            ParseState::DoubleQuotedEscape => self.consume_in_double_quoted_escape(byte),
        }
    }

    fn consume_in_separator(&mut self, byte: u8) -> ParseState {
        if is_whitespace_byte(byte) {
            return ParseState::Separator;
        }
        self.begin_token();
        self.enter_word_byte(byte)
    }

    fn consume_in_unquoted(&mut self, byte: u8) -> ParseState {
        if is_whitespace_byte(byte) {
            self.finalize_current_token();
            return ParseState::Separator;
        }
        self.enter_word_byte(byte)
    }

    fn enter_word_byte(&mut self, byte: u8) -> ParseState {
        match byte {
            SINGLE_QUOTE_BYTE => ParseState::SingleQuoted,
            DOUBLE_QUOTE_BYTE => ParseState::DoubleQuoted,
            BACKSLASH_BYTE => ParseState::UnquotedEscape,
            _ => self.push_then_unquoted(byte),
        }
    }

    fn push_then_unquoted(&mut self, byte: u8) -> ParseState {
        self.push_scratch_byte(byte);
        ParseState::Unquoted
    }

    fn consume_in_unquoted_escape(&mut self, byte: u8) -> ParseState {
        self.push_scratch_byte(byte);
        ParseState::Unquoted
    }

    fn consume_in_single_quoted(&mut self, byte: u8) -> ParseState {
        if byte == SINGLE_QUOTE_BYTE {
            return ParseState::Unquoted;
        }
        self.push_scratch_byte(byte);
        ParseState::SingleQuoted
    }

    fn consume_in_double_quoted(&mut self, byte: u8) -> ParseState {
        match byte {
            DOUBLE_QUOTE_BYTE => ParseState::Unquoted,
            BACKSLASH_BYTE => ParseState::DoubleQuotedEscape,
            _ => self.push_then_double_quoted(byte),
        }
    }

    fn push_then_double_quoted(&mut self, byte: u8) -> ParseState {
        self.push_scratch_byte(byte);
        ParseState::DoubleQuoted
    }

    fn consume_in_double_quoted_escape(&mut self, byte: u8) -> ParseState {
        if byte != DOUBLE_QUOTE_BYTE && byte != BACKSLASH_BYTE {
            self.push_scratch_byte(BACKSLASH_BYTE);
        }
        self.push_scratch_byte(byte);
        ParseState::DoubleQuoted
    }

    fn begin_token(&mut self) {
        self.current_token_offset = self.scratch_length;
    }

    fn finalize_current_token(&mut self) {
        if self.token_count >= MAXIMUM_TOKEN_COUNT {
            return;
        }
        self.token_offsets[self.token_count] = self.current_token_offset;
        self.token_lengths[self.token_count] = self
            .scratch_length
            .saturating_sub(self.current_token_offset);
        self.token_count = self.token_count.saturating_add(1);
    }

    fn finalize_trailing_token(&mut self, state: ParseState) {
        if state != ParseState::Separator {
            self.finalize_current_token();
        }
    }

    fn push_scratch_byte(&mut self, byte: u8) {
        if self.scratch_length >= LINE_CAPACITY_IN_BYTES {
            return;
        }
        self.scratch[self.scratch_length] = byte;
        self.scratch_length = self.scratch_length.saturating_add(1);
    }
}

impl Default for ParsedCommandLine {
    fn default() -> Self {
        Self::new()
    }
}

fn is_whitespace_byte(byte: u8) -> bool {
    byte == SPACE_BYTE || byte == HORIZONTAL_TAB_BYTE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(line: &[u8]) -> ParsedCommandLine {
        let mut parsed = ParsedCommandLine::new();
        parsed.parse(line);
        parsed
    }

    #[test]
    fn empty_line_yields_no_tokens() {
        let parsed = parse(b"");
        assert_eq!(parsed.token_count(), 0);
        assert!(parsed.token(0).is_none());
    }

    #[test]
    fn whitespace_only_line_yields_no_tokens() {
        let parsed = parse(b"   \t  ");
        assert_eq!(parsed.token_count(), 0);
    }

    #[test]
    fn single_word_yields_one_token() {
        let parsed = parse(b"ls");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"ls"[..]));
    }

    #[test]
    fn two_words_split_on_space() {
        let parsed = parse(b"ls -la");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(0), Some(&b"ls"[..]));
        assert_eq!(parsed.token(1), Some(&b"-la"[..]));
    }

    #[test]
    fn leading_and_trailing_whitespace_is_ignored() {
        let parsed = parse(b"   echo   hi   ");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(0), Some(&b"echo"[..]));
        assert_eq!(parsed.token(1), Some(&b"hi"[..]));
    }

    #[test]
    fn tabs_separate_tokens() {
        let parsed = parse(b"echo\thi");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(1), Some(&b"hi"[..]));
    }

    #[test]
    fn single_quotes_group_bytes_including_spaces() {
        let parsed = parse(b"echo 'a b c'");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(1), Some(&b"a b c"[..]));
    }

    #[test]
    fn double_quotes_group_bytes_including_spaces() {
        let parsed = parse(b"echo \"a b c\"");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(1), Some(&b"a b c"[..]));
    }

    #[test]
    fn empty_single_quotes_yield_one_empty_token() {
        let parsed = parse(b"echo ''");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(1), Some(&b""[..]));
    }

    #[test]
    fn quotes_abut_surrounding_word_characters() {
        let parsed = parse(b"a\"b c\"d");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"ab cd"[..]));
    }

    #[test]
    fn backslash_escapes_an_unquoted_space() {
        let parsed = parse(b"a\\ b");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"a b"[..]));
    }

    #[test]
    fn backslash_escapes_a_double_quote_outside_quotes() {
        let parsed = parse(b"echo \\\"");
        assert_eq!(parsed.token_count(), 2);
        assert_eq!(parsed.token(1), Some(&b"\""[..]));
    }

    #[test]
    fn double_quote_escape_emits_literal_quote() {
        let parsed = parse(b"\"a\\\"b\"");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"a\"b"[..]));
    }

    #[test]
    fn backslash_before_ordinary_char_in_double_quotes_is_kept() {
        let parsed = parse(b"\"a\\b\"");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"a\\b"[..]));
    }

    #[test]
    fn single_quote_inside_double_quotes_is_literal() {
        let parsed = parse(b"\"it's\"");
        assert_eq!(parsed.token_count(), 1);
        assert_eq!(parsed.token(0), Some(&b"it's"[..]));
    }

    #[test]
    fn many_tokens_are_capped_at_the_maximum() {
        let parsed =
            parse(b"a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a a");
        assert_eq!(parsed.token_count(), MAXIMUM_TOKEN_COUNT);
    }

    #[test]
    fn token_index_at_or_beyond_count_is_none() {
        let parsed = parse(b"one two");
        assert!(parsed.token(2).is_none());
    }
}
