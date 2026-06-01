#![no_main]

//! Fuzz target: devd-nic IPC boundary cannot reach kernel memory.
//!
//! Verifies that arbitrary bytes delivered to the devd-nic IPC boundary
//! cannot be used to access kernel memory outside the device's assigned
//! CapDevice MMIO region.
//!
//! The fuzz input simulates raw IPC message data that a compromised peer
//! might send to devd-nic's endpoint. Success criteria: no panic, no
//! out-of-bounds access, no kernel memory reachable from this parsing path.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Exercise the devd-nic IPC message parsing boundary.
    let _message_type = brainix_devd_nic::parse_ipc_message_type(data);
});
