//! Shell entry point and read-echo REPL over COM1.
//!
//! Structure:
//!   1. Print a greeting + prompt.
//!   2. Poll `syscall_serial_read_byte` in a loop.
//!   3. Echo each byte. Handle CR (0x0D) / LF (0x0A) by printing CRLF +
//!      a fresh prompt. Handle Ctrl-D (0x04) / Ctrl-C (0x03) by exiting.
//!   4. Between polls, spin_loop_hint so the CPU knows we're busy-waiting.
//!
//! No dynamic memory, no unsafe, every function body <= 6 lines.

use brainix_libsyscall::{
    syscall_process_exit, syscall_serial_read_byte, syscall_serial_write_byte,
};

/// ASCII Ctrl-D (end-of-transmission). Treated as "exit shell".
const CONTROL_D_BYTE: u8 = 0x04;

/// ASCII Ctrl-C (end-of-text). Treated as "exit shell".
const CONTROL_C_BYTE: u8 = 0x03;

/// ASCII carriage return.
const CARRIAGE_RETURN_BYTE: u8 = b'\r';

/// ASCII line feed.
const LINE_FEED_BYTE: u8 = b'\n';

/// ASCII backspace (maps Ctrl-H) or DEL (maps 127). Treated as "erase last".
const BACKSPACE_BYTE: u8 = 0x08;

/// ASCII DEL, emitted by many terminals when the user presses Backspace.
const DELETE_BYTE: u8 = 0x7F;

/// Shell entry point. Called by the process loader after CSpace is populated.
///
/// Enforces INV-AUTH-001: uses only the serial-read, serial-write, and
/// process-exit syscalls — no ambient authority, no IPC endpoints needed
/// for v0.01. Future capability-gated versions will route through console-
/// server IPC instead of the direct serial syscalls.
pub fn shell_main() -> ! {
    print_greeting_banner();
    print_prompt();
    enter_read_echo_loop()
}

/// Prints the one-line startup greeting.
fn print_greeting_banner() {
    write_bytes_to_serial(b"BraiNIX shell v0.01 -- Ctrl-D to exit\r\n");
}

/// Prints the command prompt character and a following space.
fn print_prompt() {
    write_bytes_to_serial(b"$ ");
}

/// Writes every byte in `bytes` to serial in order.
fn write_bytes_to_serial(bytes: &[u8]) {
    for byte_value in bytes {
        let _ = syscall_serial_write_byte(*byte_value);
    }
}

/// Polls serial for bytes forever, dispatching each one through `process_incoming_byte`.
fn enter_read_echo_loop() -> ! {
    loop {
        match syscall_serial_read_byte() {
            Some(byte_value) => process_incoming_byte(byte_value),
            None => spin_on_empty_receive_buffer(),
        }
    }
}

/// Dispatches a single received byte to the appropriate handler.
///
/// Exits the process on Ctrl-C or Ctrl-D. CR/LF print CRLF and a fresh prompt.
/// Backspace/DEL send the ANSI erase-last sequence. Other bytes are echoed raw.
fn process_incoming_byte(byte_value: u8) {
    if byte_value == CONTROL_D_BYTE || byte_value == CONTROL_C_BYTE {
        exit_shell_process();
    }
    if byte_value == CARRIAGE_RETURN_BYTE || byte_value == LINE_FEED_BYTE {
        handle_end_of_line();
        return;
    }
    handle_printable_or_backspace_byte(byte_value);
}

/// Emits CRLF and a fresh prompt. Called when the user presses Enter.
fn handle_end_of_line() {
    write_bytes_to_serial(b"\r\n");
    print_prompt();
}

/// Echoes a printable byte as-is; backspace/DEL emits the ANSI erase-last sequence.
fn handle_printable_or_backspace_byte(byte_value: u8) {
    if byte_value == BACKSPACE_BYTE || byte_value == DELETE_BYTE {
        write_bytes_to_serial(b"\x08 \x08");
        return;
    }
    let _ = syscall_serial_write_byte(byte_value);
}

/// Emits a farewell and calls process exit. Never returns.
fn exit_shell_process() -> ! {
    write_bytes_to_serial(b"\r\nbye\r\n");
    syscall_process_exit()
}

/// Hint the CPU that we are idling while waiting for the UART to receive data.
fn spin_on_empty_receive_buffer() {
    core::hint::spin_loop();
}
