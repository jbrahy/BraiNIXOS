//! BraiNIX userspace shell (v0.01 — interactive REPL over COM1).
//!
//! The shell is a capability-native Rust no_std program. v0.01 runs a
//! tight read-echo loop directly against the serial read/write syscalls
//! (`syscall_serial_read_byte`, `syscall_serial_write_byte`). The process
//! holds only the capabilities spawnd grants it at creation time — no
//! ambient authority. Exits cleanly via `syscall_process_exit` when the
//! user sends Ctrl-D (0x04) or Ctrl-C (0x03).
//!
//! Written from scratch — bash-5.3 at ~/OpenSource/bash-5.3/ is a
//! read-only design reference only. Every identifier is a full English
//! word; every function body is <= 6 executable lines; no unsafe.
//!
//! Enforces INV-AUTH-001: the shell holds no ambient authority.
#![no_std]
#![deny(unsafe_code)]

pub mod entry;
pub mod input_decoder;

pub use entry::shell_main;
