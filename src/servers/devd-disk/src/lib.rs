#![no_std]
#![deny(unsafe_code)]

//! devd-disk: Isolated device server for block storage.
//!
//! Runs as a ring-3 process with a single CapDevice scoped to the disk's
//! MMIO range and IRQ line. No global memory authority. No cross-device
//! access. Receives CapDevice at boot via kernel-direct grant (D-01).
//!
//! Enforces INV-DEV-002: each device service receives least privilege.

/// Parses an IPC message received on the device server's endpoint.
///
/// Returns the message type identifier from the first data word,
/// or None if the message is empty (zero-length).
pub fn parse_ipc_message_type(message_data: &[u8]) -> Option<u8> {
    extract_first_byte_from_message(message_data)
}

/// Extracts the first byte from a message data buffer.
///
/// Note: Intentionally duplicated from devd-nic. Device server crates
/// must not share code dependencies for isolation reasons — a compromise
/// of one device server's dependency must not affect another.
/// Per CODE_STANDARDS Rule 3, duplication is acceptable when the
/// alternative would create a cross-device dependency.
fn extract_first_byte_from_message(message_data: &[u8]) -> Option<u8> {
    if message_data.is_empty() {
        return None;
    }
    Some(message_data[0])
}

/// Device server main loop for block storage.
///
/// In Phase 8 this is a stub that demonstrates capability receipt.
/// Phase 9 wires real disk register access via the CapDevice MMIO mapping.
///
/// Enforces INV-DEV-002: device server loops only on its assigned endpoint.
pub fn device_server_main_loop() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
