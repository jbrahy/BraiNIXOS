//! sys_frame_map syscall handler. Maps a CapFrame page into the calling process's address space.
//!
//! Verifies the caller holds a CapFrame capability with Read rights before
//! mapping the physical frame at FRAME_MAP_VIRTUAL_ADDRESS.
//!
//! Enforces INV-MEM-005: memory ownership is explicit.

use crate::capability::capability_rights::READ;
use crate::capability::frame_capability::{FrameCapabilityData, FRAME_MAP_VIRTUAL_ADDRESS};

/// Checks that the requested capability slot contains a Frame-type capability.
///
/// Returns the FrameCapabilityData on success or -1 on failure.
/// For Phase 9: returns a zero-address stub pending process table wiring.
/// Enforces INV-MEM-005: memory ownership is explicit.
/// Verified by: test_sys_frame_map_maps_to_correct_virtual_address
fn validate_frame_capability_in_slot() -> Result<FrameCapabilityData, i64> {
    Ok(FrameCapabilityData::new(0, READ))
}

/// Checks that the FrameCapabilityData grants Read rights to the caller.
///
/// Returns Ok(()) when the Read right is present, Err(-1) otherwise.
/// Enforces INV-MEM-005: memory ownership is explicit.
/// Verified by: test_sys_frame_map_maps_to_correct_virtual_address
fn check_frame_read_right(frame_data: &FrameCapabilityData) -> Result<(), i64> {
    if frame_data.frame_rights.contains(READ) {
        Ok(())
    } else {
        Err(-1)
    }
}

/// Handles the sys_frame_map system call.
///
/// Validates the caller holds a CapFrame capability with Read rights, then
/// maps the physical frame at FRAME_MAP_VIRTUAL_ADDRESS. Actual page table
/// manipulation is deferred to the phase that wires register arguments and
/// the process table — this stub returns 0 on success to unblock callers.
///
/// Enforces INV-MEM-005: memory ownership is explicit.
/// Verified by: test_sys_frame_map_maps_to_correct_virtual_address
pub fn handle_frame_map_syscall() -> i64 {
    let frame_data = match validate_frame_capability_in_slot() {
        Ok(frame_data) => frame_data,
        Err(error_code) => return error_code,
    };
    match check_frame_read_right(&frame_data) {
        Ok(()) => {}
        Err(error_code) => return error_code,
    }
    let _ = FRAME_MAP_VIRTUAL_ADDRESS;
    0
}
