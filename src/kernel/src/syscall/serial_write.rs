//! sys_serial_write_byte handler. Writes one byte to COM1, blocking until
//! the transmit buffer is empty.
//!
//! Reads the byte value from KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE
//! (low 8 bits). Returns 0 on success.
//!
//! Falls under `src/kernel/src/syscall/serial_write.rs` allowlist entry in
//! `docs/security/UNSAFE_CODE_POLICY.md` (atomic register load).
//!
//! Enforces INV-BOOT-001: serial access is confined to the kernel.
#![allow(unsafe_code)]

use core::sync::atomic::Ordering;

use crate::boot::serial::SerialOutputPort;
use crate::syscall::kernel_syscall_registers::KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE;

/// Handles the sys_serial_write_byte system call.
///
/// Reads the byte-to-write from the message-register-zero slot (low 8 bits),
/// writes it to COM1, returns 0.
///
/// Verified by: tests::test_serial_write_returns_zero_on_success
pub fn handle_serial_write_byte_syscall() -> i64 {
    let byte_value = read_byte_value_from_syscall_register();
    write_byte_to_serial(byte_value);
    0
}

/// Reads the low 8 bits of the message-register-zero syscall global.
fn read_byte_value_from_syscall_register() -> u8 {
    let register_value = KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.load(Ordering::Relaxed);
    register_value as u8
}

/// Writes one byte to the COM1 UART. Uses a fresh SerialOutputPort handle.
///
/// SerialOutputPort is a zero-sized marker; constructing one does not
/// re-initialize the UART. This matches the pattern in `boot/logger.rs`.
fn write_byte_to_serial(byte_value: u8) {
    let mut serial_port = SerialOutputPort;
    serial_port.write_byte(byte_value);
}
