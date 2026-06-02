//! Shell entry point and line-editor REPL.
//!
//! [`shell_main`] is the only public entry point. It constructs a
//! `ReplState` holding every piece of shell state — the current-line
//! buffer, the history ring, the navigation cursor, the saved
//! working-line snapshot (used so `↓` past the newest entry can restore
//! what the user was typing), the input-decoder state, and the display
//! sink — and then runs the read / decode / dispatch loop until the
//! user sends `Ctrl-C` or `Ctrl-D`.
//!
//! Every editing or navigation primitive lives in a sibling module:
//!
//!   * [`crate::input_decoder`] — byte stream → [`InputEvent`]
//!   * [`crate::line_buffer`] — current-line state
//!   * [`crate::history`] — ring + navigation cursor
//!   * [`crate::display`] — byte writes to the serial sink
//!
//! No allocation, no unsafe; every function body ≤ 6 executable lines.

use brainix_libsyscall::{
    syscall_auth_login, syscall_auth_set_password, syscall_process_exit, syscall_serial_read_byte,
};

use crate::builtins::execute_command;
use crate::command_line::ParsedCommandLine;
use crate::display::{
    echo_printable_byte, emit_erase_last_character, emit_erase_last_character_repeated,
    write_byte_slice, write_carriage_return_line_feed, write_clear_to_line_start, ByteSink,
    SerialByteSink,
};
use crate::environment::ShellEnvironment;
use crate::history::{HistoryNavigationCursor, HistoryRing};
use crate::input_decoder::{decode_next_byte, InputDecoderState, InputEvent};
use crate::line_buffer::CurrentLineBuffer;
use crate::login::{
    CredentialAuthority, CredentialCheck, LoginFlow, LoginProgress, MAXIMUM_CREDENTIAL_LINE_LENGTH,
};
use crate::prompt::render_prompt;

/// A [`CredentialAuthority`] backed by the kernel auth syscalls. Verification
/// and password changes happen in the kernel TCB against the persistent
/// credential store; the shell only relays the typed bytes.
struct KernelCredentialAuthority;

impl CredentialAuthority for KernelCredentialAuthority {
    fn check_password(&self, username: &[u8], password: &[u8]) -> CredentialCheck {
        match syscall_auth_login(username, password) {
            0 => CredentialCheck::Accepted,
            1 => CredentialCheck::AcceptedMustChange,
            _ => CredentialCheck::Rejected,
        }
    }

    fn set_password(
        &mut self,
        username: &[u8],
        current_password: &[u8],
        new_password: &[u8],
    ) -> bool {
        syscall_auth_set_password(username, current_password, new_password) == 0
    }
}

/// One-line v0.03 greeting written immediately before the first prompt.
const GREETING_BANNER_BYTES: &[u8] =
    b"BraiNIX zsh v0.03 -- type 'help' for builtins; arrows: history; Ctrl-D: exit\r\n";

/// Farewell emitted just before `syscall_process_exit` on `Ctrl-C` / `Ctrl-D`.
const EXIT_FAREWELL_BYTES: &[u8] = b"\r\nbye\r\n";

/// Everything the REPL needs between successive reads from the serial port.
///
/// Held by `shell_main` on the stack; never escapes the binary.
struct ReplState<S: ByteSink> {
    line_buffer: CurrentLineBuffer,
    history_ring: HistoryRing,
    history_cursor: HistoryNavigationCursor,
    working_line_snapshot: CurrentLineBuffer,
    decoder_state: InputDecoderState,
    parsed_command_line: ParsedCommandLine,
    environment: ShellEnvironment,
    display_sink: S,
}

impl<S: ByteSink> ReplState<S> {
    fn new(display_sink: S) -> Self {
        Self {
            line_buffer: CurrentLineBuffer::new(),
            history_ring: HistoryRing::new(),
            history_cursor: HistoryNavigationCursor::new(),
            working_line_snapshot: CurrentLineBuffer::new(),
            decoder_state: InputDecoderState::new(),
            parsed_command_line: ParsedCommandLine::new(),
            environment: ShellEnvironment::new(),
            display_sink,
        }
    }
}

/// Shell entry point. Called from `_start` after the process loader has
/// installed the userland VA layout and CSpace.
pub fn shell_main() -> ! {
    let mut state = ReplState::new(SerialByteSink);
    write_byte_slice(&mut state.display_sink, GREETING_BANNER_BYTES);
    run_login_gate(&mut state.display_sink, &mut state.environment);
    render_current_prompt(&mut state);
    enter_input_loop(&mut state)
}

/// Renders the zsh-style prompt for the current user and working directory.
fn render_current_prompt<S: ByteSink>(state: &mut ReplState<S>) {
    render_prompt(
        &mut state.display_sink,
        state.environment.username(),
        state.environment.working_directory(),
    );
}

/// Authenticates a user before the REPL starts. Reads COM1 a byte at a time,
/// assembles each line, and drives the [`LoginFlow`] until it authenticates.
/// Username bytes echo; password bytes do not.
///
/// Verification + password changes run in the kernel TCB via the auth syscalls
/// (see [`KernelCredentialAuthority`]); the persistent credential store backs them.
fn run_login_gate<S: ByteSink>(sink: &mut S, environment: &mut ShellEnvironment) {
    let mut authority = KernelCredentialAuthority;
    let mut flow = LoginFlow::start(sink);
    let mut line_buffer = [0u8; MAXIMUM_CREDENTIAL_LINE_LENGTH];
    let mut line_length: usize = 0;
    loop {
        match syscall_serial_read_byte() {
            Some(byte_value) => {
                if drive_login_with_byte(
                    &mut flow,
                    &mut authority,
                    sink,
                    &mut line_buffer,
                    &mut line_length,
                    byte_value,
                ) {
                    environment.set_username(flow.authenticated_username());
                    return;
                }
            }
            None => core::hint::spin_loop(),
        }
    }
}

/// Feeds one received byte into the login line assembler. Returns true once the
/// flow reports the user is authenticated.
fn drive_login_with_byte<S: ByteSink, A: CredentialAuthority>(
    flow: &mut LoginFlow,
    authority: &mut A,
    sink: &mut S,
    line_buffer: &mut [u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
    line_length: &mut usize,
    byte_value: u8,
) -> bool {
    if byte_value == CARRIAGE_RETURN_BYTE || byte_value == LINE_FEED_BYTE {
        return submit_login_line(flow, authority, sink, line_buffer, line_length);
    }
    append_login_byte(flow, sink, line_buffer, line_length, byte_value);
    false
}

/// Submits the assembled line to the flow, echoing CR/LF only while the visible
/// username is being entered (the flow emits its own CR/LF for secret lines).
fn submit_login_line<S: ByteSink, A: CredentialAuthority>(
    flow: &mut LoginFlow,
    authority: &mut A,
    sink: &mut S,
    line_buffer: &mut [u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
    line_length: &mut usize,
) -> bool {
    if !flow.is_collecting_secret() {
        write_carriage_return_line_feed(sink);
    }
    let progress = flow.submit_line(&line_buffer[..*line_length], authority, sink);
    *line_length = 0;
    matches!(progress, LoginProgress::Authenticated)
}

/// Appends a printable byte to the line buffer, echoing it only when the
/// username (non-secret) is being entered.
fn append_login_byte<S: ByteSink>(
    flow: &LoginFlow,
    sink: &mut S,
    line_buffer: &mut [u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
    line_length: &mut usize,
    byte_value: u8,
) {
    if *line_length >= MAXIMUM_CREDENTIAL_LINE_LENGTH {
        return;
    }
    line_buffer[*line_length] = byte_value;
    *line_length += 1;
    if !flow.is_collecting_secret() {
        echo_printable_byte(sink, byte_value);
    }
}

/// ASCII carriage return (Enter on most serial terminals).
const CARRIAGE_RETURN_BYTE: u8 = 0x0d;
/// ASCII line feed.
const LINE_FEED_BYTE: u8 = 0x0a;

fn enter_input_loop<S: ByteSink>(state: &mut ReplState<S>) -> ! {
    loop {
        match syscall_serial_read_byte() {
            Some(byte_value) => feed_one_byte_through_decoder(state, byte_value),
            None => spin_on_empty_receive_buffer(),
        }
    }
}

fn feed_one_byte_through_decoder<S: ByteSink>(state: &mut ReplState<S>, byte_value: u8) {
    if let Some(event) = decode_next_byte(&mut state.decoder_state, byte_value) {
        dispatch_input_event(state, event);
    }
}

/// Routes one decoded [`InputEvent`] to the right handler. Split into
/// three category dispatchers (erase / history navigation / remaining) so
/// that no single match block exceeds the 6-line-per-function-body rule.
fn dispatch_input_event<S: ByteSink>(state: &mut ReplState<S>, event: InputEvent) {
    if try_dispatch_erase_event(state, event).is_some() {
        return;
    }
    if try_dispatch_history_navigation_event(state, event).is_some() {
        return;
    }
    handle_remaining_input_event(state, event)
}

fn try_dispatch_erase_event<S: ByteSink>(
    state: &mut ReplState<S>,
    event: InputEvent,
) -> Option<()> {
    match event {
        InputEvent::EraseLastCharacter => handle_erase_last_character_event(state),
        InputEvent::EraseLastWord => handle_erase_last_word_event(state),
        InputEvent::EraseEntireLine => handle_erase_entire_line_event(state),
        _ => return None,
    }
    Some(())
}

fn try_dispatch_history_navigation_event<S: ByteSink>(
    state: &mut ReplState<S>,
    event: InputEvent,
) -> Option<()> {
    match event {
        InputEvent::RecallPreviousHistoryEntry => handle_recall_previous_event(state),
        InputEvent::RecallNextHistoryEntry => handle_recall_next_event(state),
        _ => return None,
    }
    Some(())
}

fn handle_remaining_input_event<S: ByteSink>(state: &mut ReplState<S>, event: InputEvent) {
    match event {
        InputEvent::Printable(byte) => handle_printable_event(state, byte),
        InputEvent::CommitLine => handle_commit_line_event(state),
        InputEvent::ExitShell => exit_shell_process(state),
        _ => {}
    }
}

fn handle_printable_event<S: ByteSink>(state: &mut ReplState<S>, byte: u8) {
    if state.line_buffer.append_printable_byte(byte) {
        echo_printable_byte(&mut state.display_sink, byte);
    }
}

fn handle_erase_last_character_event<S: ByteSink>(state: &mut ReplState<S>) {
    if state.line_buffer.erase_last_character() {
        emit_erase_last_character(&mut state.display_sink);
    }
}

fn handle_erase_last_word_event<S: ByteSink>(state: &mut ReplState<S>) {
    let erased_byte_count = state.line_buffer.erase_last_word();
    emit_erase_last_character_repeated(&mut state.display_sink, erased_byte_count);
}

fn handle_erase_entire_line_event<S: ByteSink>(state: &mut ReplState<S>) {
    let _ = state.line_buffer.erase_entire_line();
    redraw_current_prompt_and_line(state);
}

fn handle_commit_line_event<S: ByteSink>(state: &mut ReplState<S>) {
    let _ = state
        .history_ring
        .record_committed_line(state.line_buffer.as_byte_slice());
    write_carriage_return_line_feed(&mut state.display_sink);
    execute_current_line(state);
    let _ = state.line_buffer.erase_entire_line();
    state.history_cursor.reset_to_working_line();
    finish_command_or_exit(state);
}

/// Tokenizes the committed line and runs the matching builtin, writing any
/// output to the serial sink.
fn execute_current_line<S: ByteSink>(state: &mut ReplState<S>) {
    state
        .parsed_command_line
        .parse(state.line_buffer.as_byte_slice());
    execute_command(
        &state.parsed_command_line,
        &mut state.environment,
        &state.history_ring,
        &mut state.display_sink,
    );
}

/// Exits the process if a builtin requested it; otherwise renders the next
/// prompt for the following command.
fn finish_command_or_exit<S: ByteSink>(state: &mut ReplState<S>) {
    if state.environment.exit_requested() {
        exit_shell_process(state);
    }
    render_current_prompt(state);
}

/// Clears the physical line, renders the prompt, and reprints the current
/// line buffer — used after Ctrl-U and history navigation.
fn redraw_current_prompt_and_line<S: ByteSink>(state: &mut ReplState<S>) {
    write_clear_to_line_start(&mut state.display_sink);
    render_current_prompt(state);
    write_byte_slice(&mut state.display_sink, state.line_buffer.as_byte_slice());
}

fn handle_recall_previous_event<S: ByteSink>(state: &mut ReplState<S>) {
    snapshot_working_line_if_first_entry_into_history(state);
    if state
        .history_cursor
        .navigate_to_previous_entry(&state.history_ring)
    {
        copy_selected_navigation_target_into_line_buffer(state);
        redraw_current_prompt_and_line(state);
    }
}

fn handle_recall_next_event<S: ByteSink>(state: &mut ReplState<S>) {
    if state.history_cursor.navigate_to_next_entry() {
        copy_selected_navigation_target_into_line_buffer(state);
        redraw_current_prompt_and_line(state);
    }
}

fn snapshot_working_line_if_first_entry_into_history<S: ByteSink>(state: &mut ReplState<S>) {
    if state.history_cursor.is_on_working_line() {
        state
            .working_line_snapshot
            .replace_with_byte_slice(state.line_buffer.as_byte_slice());
    }
}

fn copy_selected_navigation_target_into_line_buffer<S: ByteSink>(state: &mut ReplState<S>) {
    match state.history_cursor.current_offset_from_newest() {
        Some(offset) => copy_history_entry_at_offset_into_line_buffer(state, offset),
        None => state
            .line_buffer
            .replace_with_byte_slice(state.working_line_snapshot.as_byte_slice()),
    }
}

fn copy_history_entry_at_offset_into_line_buffer<S: ByteSink>(
    state: &mut ReplState<S>,
    offset_from_newest: usize,
) {
    if let Some(entry) = state
        .history_ring
        .entry_at_offset_from_newest(offset_from_newest)
    {
        state
            .line_buffer
            .replace_with_byte_slice(entry.as_byte_slice());
    }
}

fn exit_shell_process<S: ByteSink>(state: &mut ReplState<S>) -> ! {
    write_byte_slice(&mut state.display_sink, EXIT_FAREWELL_BYTES);
    syscall_process_exit()
}

fn spin_on_empty_receive_buffer() {
    core::hint::spin_loop();
}
