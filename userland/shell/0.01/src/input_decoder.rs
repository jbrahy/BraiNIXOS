//! Byte-stream → `InputEvent` decoder for the shell line editor.
//!
//! The shell reads one byte at a time from `syscall_serial_read_byte`. This
//! module owns the small state machine that turns those bytes into editor
//! events. Multi-byte sequences (ANSI escape sequences for the arrow keys)
//! span more than one decoder call, so the state is threaded through
//! `decode_next_byte` by mutable reference.
//!
//! Recognized events:
//!
//! | Byte(s)                | Event                                 |
//! |------------------------|---------------------------------------|
//! | 0x20–0x7E              | `Printable(byte)`                     |
//! | 0x08 (Backspace), 0x7F | `EraseLastCharacter`                  |
//! | 0x17 (Ctrl-W)          | `EraseLastWord`                       |
//! | 0x15 (Ctrl-U)          | `EraseEntireLine`                     |
//! | 0x0D (CR), 0x0A (LF)   | `CommitLine`                          |
//! | 0x03 (Ctrl-C), 0x04    | `ExitShell`                           |
//! | ESC `[` A              | `RecallPreviousHistoryEntry`          |
//! | ESC `[` B              | `RecallNextHistoryEntry`              |
//!
//! Any other ANSI CSI sequence is consumed silently (no event emitted) by
//! walking parameter / intermediate bytes until a final byte in 0x40–0x7E.
//! Bytes that fall through every match arm produce no event.

/// State of the input-decoder state machine.
///
/// Carried by the REPL between successive `decode_next_byte` calls so a
/// multi-byte ANSI escape sequence (e.g. `ESC [ A` for the up arrow) can be
/// recognized across reads from `syscall_serial_read_byte`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InputDecoderState {
    /// Default: every incoming byte is interpreted on its own.
    Ground,
    /// Just saw an `ESC` (0x1B); the next byte tells us whether it was the
    /// start of a CSI sequence or a bare escape we should silently drop.
    SawEscape,
    /// Inside the parameter / intermediate region of a CSI sequence; bytes
    /// accumulate silently until a final byte in 0x40–0x7E ends the
    /// sequence.
    SawCsiIntroducer,
}

impl InputDecoderState {
    /// Constructs a fresh decoder state in `Ground`.
    pub const fn new() -> Self {
        Self::Ground
    }
}

impl Default for InputDecoderState {
    fn default() -> Self {
        Self::new()
    }
}

/// An editing intent extracted from one or more bytes of input.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum InputEvent {
    Printable(u8),
    EraseLastCharacter,
    EraseLastWord,
    EraseEntireLine,
    CommitLine,
    ExitShell,
    RecallPreviousHistoryEntry,
    RecallNextHistoryEntry,
}

const ESCAPE_BYTE: u8 = 0x1B;
const CSI_INTRODUCER_BYTE: u8 = b'[';
const FIRST_PRINTABLE_ASCII_BYTE: u8 = 0x20;
const LAST_PRINTABLE_ASCII_BYTE: u8 = 0x7E;
const FIRST_CSI_FINAL_BYTE: u8 = 0x40;
const LAST_CSI_FINAL_BYTE: u8 = 0x7E;
const CURSOR_UP_FINAL_BYTE: u8 = b'A';
const CURSOR_DOWN_FINAL_BYTE: u8 = b'B';
const CONTROL_C_BYTE: u8 = 0x03;
const CONTROL_D_BYTE: u8 = 0x04;
const CONTROL_U_BYTE: u8 = 0x15;
const CONTROL_W_BYTE: u8 = 0x17;
const BACKSPACE_BYTE: u8 = 0x08;
const DELETE_BYTE: u8 = 0x7F;
const CARRIAGE_RETURN_BYTE: u8 = b'\r';
const LINE_FEED_BYTE: u8 = b'\n';

/// Decodes one input byte against the current decoder `state`.
///
/// Returns the recognized event, or `None` when the byte was part of a
/// multi-byte escape sequence (or fell through every match arm).
pub fn decode_next_byte(state: &mut InputDecoderState, byte: u8) -> Option<InputEvent> {
    match *state {
        InputDecoderState::Ground => decode_byte_in_ground_state(state, byte),
        InputDecoderState::SawEscape => decode_byte_in_saw_escape_state(state, byte),
        InputDecoderState::SawCsiIntroducer => decode_byte_in_csi_state(state, byte),
    }
}

fn decode_byte_in_ground_state(state: &mut InputDecoderState, byte: u8) -> Option<InputEvent> {
    if byte == ESCAPE_BYTE {
        *state = InputDecoderState::SawEscape;
        return None;
    }
    decode_non_escape_byte(byte)
}

fn decode_non_escape_byte(byte: u8) -> Option<InputEvent> {
    decode_control_byte(byte).or_else(|| decode_printable_byte(byte))
}

fn decode_control_byte(byte: u8) -> Option<InputEvent> {
    match byte {
        CONTROL_C_BYTE | CONTROL_D_BYTE => Some(InputEvent::ExitShell),
        CARRIAGE_RETURN_BYTE | LINE_FEED_BYTE => Some(InputEvent::CommitLine),
        BACKSPACE_BYTE | DELETE_BYTE => Some(InputEvent::EraseLastCharacter),
        CONTROL_W_BYTE => Some(InputEvent::EraseLastWord),
        CONTROL_U_BYTE => Some(InputEvent::EraseEntireLine),
        _ => None,
    }
}

fn decode_printable_byte(byte: u8) -> Option<InputEvent> {
    if is_printable_ascii_byte(byte) {
        return Some(InputEvent::Printable(byte));
    }
    None
}

fn is_printable_ascii_byte(byte: u8) -> bool {
    (FIRST_PRINTABLE_ASCII_BYTE..=LAST_PRINTABLE_ASCII_BYTE).contains(&byte)
}

fn decode_byte_in_saw_escape_state(state: &mut InputDecoderState, byte: u8) -> Option<InputEvent> {
    if byte == CSI_INTRODUCER_BYTE {
        *state = InputDecoderState::SawCsiIntroducer;
        return None;
    }
    *state = InputDecoderState::Ground;
    None
}

fn decode_byte_in_csi_state(state: &mut InputDecoderState, byte: u8) -> Option<InputEvent> {
    if !is_csi_final_byte(byte) {
        return None;
    }
    *state = InputDecoderState::Ground;
    decode_csi_final_byte(byte)
}

fn is_csi_final_byte(byte: u8) -> bool {
    (FIRST_CSI_FINAL_BYTE..=LAST_CSI_FINAL_BYTE).contains(&byte)
}

fn decode_csi_final_byte(byte: u8) -> Option<InputEvent> {
    match byte {
        CURSOR_UP_FINAL_BYTE => Some(InputEvent::RecallPreviousHistoryEntry),
        CURSOR_DOWN_FINAL_BYTE => Some(InputEvent::RecallNextHistoryEntry),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;

    fn decode_sequence(bytes: &[u8]) -> Vec<InputEvent> {
        let mut state = InputDecoderState::new();
        let mut events: Vec<InputEvent> = Vec::new();
        for byte in bytes {
            if let Some(event) = decode_next_byte(&mut state, *byte) {
                events.push(event);
            }
        }
        events
    }

    #[test]
    fn printable_ascii_emits_one_printable_event_per_byte() {
        let events = decode_sequence(b"abc");
        assert_eq!(
            events,
            vec![
                InputEvent::Printable(b'a'),
                InputEvent::Printable(b'b'),
                InputEvent::Printable(b'c'),
            ]
        );
    }

    #[test]
    fn space_is_printable() {
        assert_eq!(decode_sequence(b" "), vec![InputEvent::Printable(b' ')]);
    }

    #[test]
    fn tilde_is_printable() {
        assert_eq!(decode_sequence(b"~"), vec![InputEvent::Printable(b'~')]);
    }

    #[test]
    fn carriage_return_emits_commit_line() {
        assert_eq!(decode_sequence(b"\r"), vec![InputEvent::CommitLine]);
    }

    #[test]
    fn line_feed_emits_commit_line() {
        assert_eq!(decode_sequence(b"\n"), vec![InputEvent::CommitLine]);
    }

    #[test]
    fn backspace_emits_erase_last_character() {
        assert_eq!(
            decode_sequence(&[0x08]),
            vec![InputEvent::EraseLastCharacter]
        );
    }

    #[test]
    fn delete_emits_erase_last_character() {
        assert_eq!(
            decode_sequence(&[0x7F]),
            vec![InputEvent::EraseLastCharacter]
        );
    }

    #[test]
    fn control_w_emits_erase_last_word() {
        assert_eq!(decode_sequence(&[0x17]), vec![InputEvent::EraseLastWord]);
    }

    #[test]
    fn control_u_emits_erase_entire_line() {
        assert_eq!(decode_sequence(&[0x15]), vec![InputEvent::EraseEntireLine]);
    }

    #[test]
    fn control_c_emits_exit_shell() {
        assert_eq!(decode_sequence(&[0x03]), vec![InputEvent::ExitShell]);
    }

    #[test]
    fn control_d_emits_exit_shell() {
        assert_eq!(decode_sequence(&[0x04]), vec![InputEvent::ExitShell]);
    }

    #[test]
    fn escape_open_bracket_a_emits_recall_previous() {
        let events = decode_sequence(&[0x1B, b'[', b'A']);
        assert_eq!(events, vec![InputEvent::RecallPreviousHistoryEntry]);
    }

    #[test]
    fn escape_open_bracket_b_emits_recall_next() {
        let events = decode_sequence(&[0x1B, b'[', b'B']);
        assert_eq!(events, vec![InputEvent::RecallNextHistoryEntry]);
    }

    #[test]
    fn bare_escape_followed_by_letter_returns_to_ground_silently() {
        let events = decode_sequence(&[0x1B, b'x']);
        assert_eq!(events, Vec::<InputEvent>::new());
    }

    #[test]
    fn csi_sequence_with_parameters_then_unknown_final_is_silent() {
        let events = decode_sequence(&[0x1B, b'[', b'1', b';', b'5', b'C']);
        assert_eq!(events, Vec::<InputEvent>::new());
    }

    #[test]
    fn typing_after_swallowed_csi_emits_printable() {
        let events = decode_sequence(&[0x1B, b'[', b'C', b'x']);
        assert_eq!(events, vec![InputEvent::Printable(b'x')]);
    }

    #[test]
    fn non_printable_non_recognized_bytes_are_silent() {
        let events = decode_sequence(&[0x00, 0x01, 0x1F]);
        assert_eq!(events, Vec::<InputEvent>::new());
    }

    #[test]
    fn state_returns_to_ground_after_complete_csi() {
        let mut state = InputDecoderState::new();
        for byte in &[0x1B, b'[', b'A'] {
            let _ = decode_next_byte(&mut state, *byte);
        }
        assert_eq!(state, InputDecoderState::Ground);
    }

    #[test]
    fn state_default_is_ground() {
        assert_eq!(InputDecoderState::default(), InputDecoderState::Ground);
    }
}
