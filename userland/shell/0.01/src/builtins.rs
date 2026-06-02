//! Builtin command execution for the shell.
//!
//! Userland has no `exec` or filesystem syscall, so every command this
//! shell runs is a builtin compiled into the binary. [`execute_command`]
//! takes a tokenized line, runs the matching builtin against the session
//! [`ShellEnvironment`] and command [`HistoryRing`], and writes any output
//! to a [`ByteSink`]. An unrecognized command name produces zsh's familiar
//! `zsh: command not found: <name>` line.
//!
//! Recognized builtins:
//!
//! | Command   | Effect                                              |
//! |-----------|-----------------------------------------------------|
//! | `echo`    | Writes its arguments, space-separated, then CRLF.   |
//! | `pwd`     | Writes the current working directory.               |
//! | `cd`      | Changes the (in-memory) working directory.          |
//! | `whoami`  | Writes the logged-in username.                      |
//! | `history` | Lists committed command lines, oldest first.        |
//! | `help`    | Lists the available builtins.                        |
//! | `which`   | Reports whether each argument is a shell builtin.   |
//! | `clear`   | Clears the terminal screen.                          |
//! | `true`    | Does nothing, successfully.                          |
//! | `false`   | Does nothing.                                        |
//! | `exit`    | Asks the REPL to terminate the process.             |
//!
//! No allocation, no unsafe, no panics; function bodies stay within the
//! shell's six-executable-line budget.

use crate::command_line::ParsedCommandLine;
use crate::display::{write_byte_slice, write_carriage_return_line_feed, ByteSink};
use crate::environment::ShellEnvironment;
use crate::history::HistoryRing;

/// ASCII space, written between `echo` arguments.
const SPACE_BYTE: u8 = 0x20;

/// ANSI "erase entire screen" then "cursor home" — what `clear` emits.
const CLEAR_SCREEN_SEQUENCE: &[u8] = b"\x1b[2J\x1b[H";

/// Header line printed by `help` above the builtin list.
const HELP_HEADER: &[u8] = b"brainix-zsh builtins:\r\n";

/// All builtin command names, sorted, used by `help` and `which`.
const BUILTIN_NAMES: &[&[u8]] = &[
    b"cd", b"clear", b"echo", b"exit", b"false", b"help", b"history", b"pwd", b"true", b"which",
    b"whoami",
];

/// Runs the builtin named by token 0 of `parsed`, if any.
///
/// An empty line (no tokens) does nothing. An unknown command name writes
/// a `zsh: command not found` line to `sink`.
pub fn execute_command<S: ByteSink>(
    parsed: &ParsedCommandLine,
    environment: &mut ShellEnvironment,
    history: &HistoryRing,
    sink: &mut S,
) {
    let command = match parsed.token(0) {
        Some(command) => command,
        None => return,
    };
    dispatch_builtin(command, parsed, environment, history, sink);
}

fn dispatch_builtin<S: ByteSink>(
    command: &[u8],
    parsed: &ParsedCommandLine,
    environment: &mut ShellEnvironment,
    history: &HistoryRing,
    sink: &mut S,
) {
    if try_dispatch_text_builtin(command, parsed, environment, sink).is_some() {
        return;
    }
    if try_dispatch_listing_builtin(command, parsed, history, sink).is_some() {
        return;
    }
    if try_dispatch_stateful_builtin(command, parsed, environment).is_some() {
        return;
    }
    report_command_not_found(sink, command);
}

fn try_dispatch_text_builtin<S: ByteSink>(
    command: &[u8],
    parsed: &ParsedCommandLine,
    environment: &ShellEnvironment,
    sink: &mut S,
) -> Option<()> {
    match command {
        b"echo" => builtin_echo(parsed, sink),
        b"pwd" => builtin_pwd(environment, sink),
        b"whoami" => builtin_whoami(environment, sink),
        b"clear" => write_byte_slice(sink, CLEAR_SCREEN_SEQUENCE),
        _ => return None,
    }
    Some(())
}

fn try_dispatch_listing_builtin<S: ByteSink>(
    command: &[u8],
    parsed: &ParsedCommandLine,
    history: &HistoryRing,
    sink: &mut S,
) -> Option<()> {
    match command {
        b"history" => builtin_history(history, sink),
        b"help" => builtin_help(sink),
        b"which" => builtin_which(parsed, sink),
        _ => return None,
    }
    Some(())
}

fn try_dispatch_stateful_builtin(
    command: &[u8],
    parsed: &ParsedCommandLine,
    environment: &mut ShellEnvironment,
) -> Option<()> {
    match command {
        b"cd" => environment.change_directory(parsed.token(1).unwrap_or(b"")),
        b"exit" => environment.request_exit(),
        b"true" | b"false" => {}
        _ => return None,
    }
    Some(())
}

fn builtin_echo<S: ByteSink>(parsed: &ParsedCommandLine, sink: &mut S) {
    for index in 1..parsed.token_count() {
        if index > 1 {
            sink.write_byte(SPACE_BYTE);
        }
        write_byte_slice(sink, parsed.token(index).unwrap_or(b""));
    }
    write_carriage_return_line_feed(sink);
}

fn builtin_pwd<S: ByteSink>(environment: &ShellEnvironment, sink: &mut S) {
    write_byte_slice(sink, environment.working_directory());
    write_carriage_return_line_feed(sink);
}

fn builtin_whoami<S: ByteSink>(environment: &ShellEnvironment, sink: &mut S) {
    write_byte_slice(sink, environment.username());
    write_carriage_return_line_feed(sink);
}

fn builtin_help<S: ByteSink>(sink: &mut S) {
    write_byte_slice(sink, HELP_HEADER);
    for name in BUILTIN_NAMES {
        write_byte_slice(sink, b"  ");
        write_byte_slice(sink, name);
        write_carriage_return_line_feed(sink);
    }
}

fn builtin_which<S: ByteSink>(parsed: &ParsedCommandLine, sink: &mut S) {
    for index in 1..parsed.token_count() {
        if let Some(name) = parsed.token(index) {
            write_which_result(sink, name);
        }
    }
}

fn write_which_result<S: ByteSink>(sink: &mut S, name: &[u8]) {
    write_byte_slice(sink, name);
    if is_builtin_name(name) {
        write_byte_slice(sink, b": shell builtin\r\n");
    } else {
        write_byte_slice(sink, b" not found\r\n");
    }
}

fn builtin_history<S: ByteSink>(history: &HistoryRing, sink: &mut S) {
    let entry_count = history.entry_count();
    for position in 0..entry_count {
        let offset_from_newest = entry_count.saturating_sub(1).saturating_sub(position);
        write_history_entry_line(
            sink,
            position.saturating_add(1),
            history,
            offset_from_newest,
        );
    }
}

fn write_history_entry_line<S: ByteSink>(
    sink: &mut S,
    entry_number: usize,
    history: &HistoryRing,
    offset_from_newest: usize,
) {
    if let Some(entry) = history.entry_at_offset_from_newest(offset_from_newest) {
        write_decimal_number(sink, entry_number);
        write_byte_slice(sink, b"  ");
        write_byte_slice(sink, entry.as_byte_slice());
        write_carriage_return_line_feed(sink);
    }
}

fn report_command_not_found<S: ByteSink>(sink: &mut S, command: &[u8]) {
    write_byte_slice(sink, b"zsh: command not found: ");
    write_byte_slice(sink, command);
    write_carriage_return_line_feed(sink);
}

fn is_builtin_name(name: &[u8]) -> bool {
    BUILTIN_NAMES.contains(&name)
}

fn write_decimal_number<S: ByteSink>(sink: &mut S, value: usize) {
    let mut digits = [0u8; 20];
    let digit_count = fill_decimal_digits(value, &mut digits);
    write_digits_in_reverse(sink, &digits, digit_count);
}

fn fill_decimal_digits(value: usize, digits: &mut [u8; 20]) -> usize {
    let mut remaining = value;
    let mut digit_count = 0;
    loop {
        digits[digit_count] = b'0'.wrapping_add((remaining % 10) as u8);
        digit_count = digit_count.saturating_add(1);
        remaining /= 10;
        if remaining == 0 || digit_count >= digits.len() {
            return digit_count;
        }
    }
}

fn write_digits_in_reverse<S: ByteSink>(sink: &mut S, digits: &[u8; 20], digit_count: usize) {
    let mut index = digit_count;
    while index > 0 {
        index = index.saturating_sub(1);
        sink.write_byte(digits[index]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_line::ParsedCommandLine;
    use crate::environment::ShellEnvironment;
    use crate::history::HistoryRing;

    struct CapturingByteSink {
        captured: [u8; 1024],
        length: usize,
    }

    impl CapturingByteSink {
        fn new() -> Self {
            Self {
                captured: [0u8; 1024],
                length: 0,
            }
        }

        fn as_slice(&self) -> &[u8] {
            &self.captured[..self.length]
        }

        fn contains(&self, needle: &[u8]) -> bool {
            self.length >= needle.len()
                && self.as_slice().windows(needle.len()).any(|w| w == needle)
        }
    }

    impl ByteSink for CapturingByteSink {
        fn write_byte(&mut self, value: u8) {
            if self.length < self.captured.len() {
                self.captured[self.length] = value;
                self.length += 1;
            }
        }
    }

    fn run(line: &[u8]) -> (CapturingByteSink, ShellEnvironment) {
        let mut parsed = ParsedCommandLine::new();
        parsed.parse(line);
        let mut environment = ShellEnvironment::new();
        let history = HistoryRing::new();
        let mut sink = CapturingByteSink::new();
        execute_command(&parsed, &mut environment, &history, &mut sink);
        (sink, environment)
    }

    #[test]
    fn empty_line_produces_no_output() {
        let (sink, _) = run(b"");
        assert_eq!(sink.as_slice(), b"");
    }

    #[test]
    fn echo_writes_arguments_space_separated_with_crlf() {
        let (sink, _) = run(b"echo hello world");
        assert_eq!(sink.as_slice(), b"hello world\r\n");
    }

    #[test]
    fn echo_with_no_arguments_writes_only_crlf() {
        let (sink, _) = run(b"echo");
        assert_eq!(sink.as_slice(), b"\r\n");
    }

    #[test]
    fn echo_preserves_quoted_spaces() {
        let (sink, _) = run(b"echo 'a   b'");
        assert_eq!(sink.as_slice(), b"a   b\r\n");
    }

    #[test]
    fn pwd_writes_root_by_default() {
        let (sink, _) = run(b"pwd");
        assert_eq!(sink.as_slice(), b"/\r\n");
    }

    #[test]
    fn cd_changes_the_environment_working_directory() {
        let (_, environment) = run(b"cd /etc");
        assert_eq!(environment.working_directory(), b"/etc");
    }

    #[test]
    fn cd_with_no_argument_goes_home() {
        let mut parsed = ParsedCommandLine::new();
        let mut environment = ShellEnvironment::new();
        let history = HistoryRing::new();
        let mut sink = CapturingByteSink::new();
        parsed.parse(b"cd /etc");
        execute_command(&parsed, &mut environment, &history, &mut sink);
        parsed.parse(b"cd");
        execute_command(&parsed, &mut environment, &history, &mut sink);
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn unknown_command_reports_zsh_command_not_found() {
        let (sink, _) = run(b"frobnicate --now");
        assert_eq!(sink.as_slice(), b"zsh: command not found: frobnicate\r\n");
    }

    #[test]
    fn exit_requests_termination() {
        let (_, environment) = run(b"exit");
        assert!(environment.exit_requested());
    }

    #[test]
    fn true_and_false_do_nothing_and_do_not_exit() {
        let (sink, environment) = run(b"true");
        assert_eq!(sink.as_slice(), b"");
        assert!(!environment.exit_requested());
        let (sink, _) = run(b"false");
        assert_eq!(sink.as_slice(), b"");
    }

    #[test]
    fn clear_emits_ansi_clear_screen() {
        let (sink, _) = run(b"clear");
        assert!(sink.contains(b"\x1b[2J"));
    }

    #[test]
    fn which_reports_builtin_for_a_builtin() {
        let (sink, _) = run(b"which echo");
        assert_eq!(sink.as_slice(), b"echo: shell builtin\r\n");
    }

    #[test]
    fn which_reports_not_found_for_a_nonbuiltin() {
        let (sink, _) = run(b"which frobnicate");
        assert_eq!(sink.as_slice(), b"frobnicate not found\r\n");
    }

    #[test]
    fn help_lists_several_builtins() {
        let (sink, _) = run(b"help");
        assert!(sink.contains(b"echo"));
        assert!(sink.contains(b"cd"));
        assert!(sink.contains(b"whoami"));
    }

    #[test]
    fn whoami_writes_the_logged_in_username() {
        let mut parsed = ParsedCommandLine::new();
        let mut environment = ShellEnvironment::new();
        let history = HistoryRing::new();
        let mut sink = CapturingByteSink::new();
        environment.set_username(b"jbrahy");
        parsed.parse(b"whoami");
        execute_command(&parsed, &mut environment, &history, &mut sink);
        assert_eq!(sink.as_slice(), b"jbrahy\r\n");
    }

    #[test]
    fn history_lists_committed_lines_oldest_first_and_numbered() {
        let mut parsed = ParsedCommandLine::new();
        let mut environment = ShellEnvironment::new();
        let mut history = HistoryRing::new();
        let mut sink = CapturingByteSink::new();
        history.record_committed_line(b"echo one");
        history.record_committed_line(b"pwd");
        parsed.parse(b"history");
        execute_command(&parsed, &mut environment, &history, &mut sink);
        assert_eq!(sink.as_slice(), b"1  echo one\r\n2  pwd\r\n");
    }
}
