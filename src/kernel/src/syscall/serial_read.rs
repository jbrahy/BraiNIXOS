//! sys_serial_read_byte handler. Returns one byte from COM1, non-blocking.
//!
//! Returns 0..=255 if the UART receive buffer has a byte ready, -1 otherwise.
//! Not capability-gated today — the only legitimate userspace caller is
//! console-server. A future CapSerial-gated version would be stricter.
//!
//! Enforces INV-BOOT-001 indirectly: relies on COM1 initialized at boot.

use crate::boot::serial::read_serial_byte_non_blocking;

/// Sentinel return value when no byte is available on the UART receive buffer.
const SERIAL_READ_NO_BYTE_AVAILABLE: i64 = -1;

/// Handles the sys_serial_read_byte system call.
///
/// Returns 0..=255 if COM1 has a byte ready, or -1 if not. The value is
/// directly returnable through the SYSCALL ABI (userspace libsyscall wrapper
/// converts to Option<u8>).
///
/// Enforces INV-BOOT-001: serial access is confined to the kernel.
/// Verified by: tests::test_serial_read_returns_minus_one_when_no_data_available
pub fn handle_serial_read_byte_syscall() -> i64 {
    // When the shell is bridged to an SSH session, its input comes from the SSH
    // channel (reading also drives the network), not COM1.
    if crate::boot::ssh_bridge::is_active() {
        return match crate::boot::ssh_bridge::read_input_byte() {
            Some(byte_value) => i64::from(byte_value),
            None => SERIAL_READ_NO_BYTE_AVAILABLE,
        };
    }
    match read_serial_byte_non_blocking() {
        Some(byte_value) => i64::from(byte_value),
        None => SERIAL_READ_NO_BYTE_AVAILABLE,
    }
}
