//! Fuzz target: devd-nic IPC boundary cannot reach kernel memory.
//!
//! Verifies that arbitrary bytes delivered to the devd-nic IPC boundary
//! cannot be used to access kernel memory outside the device's assigned
//! CapDevice MMIO region.
//!
//! Full implementation wired in Phase 8 Plan 05 (fuzz target + security tests).
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = data;
});
