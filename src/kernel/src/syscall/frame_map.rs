//! sys_frame_map syscall handler. Validates a CapFrame capability held by the caller.
//!
//! Scope note (Phase 14 / WIRE-02): this file implements the full capability
//! *validation* half of the frame-map syscall — reading the caller-supplied
//! slot index, looking up the caller's cspace, verifying the slot contains a
//! `CapabilityType::Frame` capability with `READ` rights, and reading the
//! backing `FrameCapabilityData` from `slot.object_pointer`.
//!
//! The *mapping* half (per-process PML4 walk, intermediate-table allocation,
//! PTE write at `FRAME_MAP_VIRTUAL_ADDRESS`, TLB flush) is tracked as follow-up
//! work. Until that lands, this handler fails closed by returning `-1` after
//! successful validation, which is strictly more secure than the prior stub
//! that returned `0` while mapping nothing.
//!
//! Argument passing:
//!   CAP_SLOT -> frame_capability_slot_index (low 8 bits)
//!
//! Return value:
//!   -1 on any validation failure, OR on successful validation (page mapping
//!      is not yet implemented — fail closed)
//!
//! Falls under `src/kernel/src/syscall/frame_map.rs` allowlist entry in
//! `docs/security/UNSAFE_CODE_POLICY.md`.
//!
//! Enforces INV-MEM-005: memory ownership is explicit.
//! Enforces INV-AUTH-002: authority is explicit and typed.
#![allow(unsafe_code)]

use core::sync::atomic::Ordering;

use crate::capability::capability_rights::READ;
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::capability::frame_capability::FrameCapabilityData;
use crate::syscall::kernel_ipc_state::kernel_process_table_mut;
use crate::syscall::kernel_syscall_registers::KERNEL_SYSCALL_CAP_SLOT_VALUE;

/// Fail-closed return value for sys_frame_map.
const FRAME_MAP_RETURN_FAIL: i64 = -1;

/// Handles the sys_frame_map system call.
///
/// Validates the caller holds a CapFrame capability at the slot index encoded
/// in the CAP_SLOT syscall register, with READ rights. Returns -1 on any
/// validation failure. Also returns -1 on successful validation because the
/// page-table mapping is tracked as follow-up work.
///
/// Enforces INV-MEM-005: memory ownership is explicit.
/// Enforces INV-AUTH-002: authority is explicit and typed.
/// Verified by: tests::test_frame_map_rejects_null_slot
pub fn handle_frame_map_syscall(thread_identifier: u32) -> i64 {
    let slot_index = read_frame_capability_slot_index();
    let caller_cspace = match look_up_caller_capability_space(thread_identifier) {
        Some(cspace) => cspace,
        None => return FRAME_MAP_RETURN_FAIL,
    };
    validate_caller_holds_readable_frame(caller_cspace, slot_index)
}

/// Reads the frame capability slot index from the CAP_SLOT syscall register.
///
/// Truncates u64 → u8; capability slot indices are u8 by construction.
fn read_frame_capability_slot_index() -> u8 {
    let register_value = KERNEL_SYSCALL_CAP_SLOT_VALUE.load(Ordering::Relaxed);
    register_value as u8
}

/// Resolves the caller's CapabilitySpace via the kernel process table.
///
/// Returns None if the thread_identifier is unknown (fail-closed path).
fn look_up_caller_capability_space(
    thread_identifier: u32,
) -> Option<&'static CapabilitySpace> {
    // SAFETY: kernel_process_table_mut is called only from the single-core
    // SYSCALL dispatch path.
    // - Precondition: initialize_kernel_process_table was called at boot.
    // - Invariant: INV-AUTH-001 (process table ready).
    // - Evidence: identical pattern in syscall::irq_bind::look_up_caller_capability_space.
    unsafe { kernel_process_table_mut().lookup_entry(thread_identifier) }
}

/// Validates the slot holds a CapFrame with READ; returns FRAME_MAP_RETURN_FAIL.
///
/// Even on successful validation, this returns -1 because actual page-table
/// mapping is deferred to a follow-up plan. Fail closed.
fn validate_caller_holds_readable_frame(
    caller_cspace: &CapabilitySpace,
    slot_index: u8,
) -> i64 {
    let frame_data = match read_frame_capability_data(caller_cspace, slot_index) {
        Some(data) => data,
        None => return FRAME_MAP_RETURN_FAIL,
    };
    if !frame_data.frame_rights.contains(READ) {
        return FRAME_MAP_RETURN_FAIL;
    }
    FRAME_MAP_RETURN_FAIL
}

/// Resolves a &'static FrameCapabilityData from the slot, or None.
fn read_frame_capability_data(
    caller_cspace: &CapabilitySpace,
    slot_index: u8,
) -> Option<&'static FrameCapabilityData> {
    let slot = caller_cspace.lookup_slot(slot_index).ok()?;
    if slot.capability_type != CapabilityType::Frame || slot.object_pointer == 0 {
        return None;
    }
    dereference_frame_capability_data(slot.object_pointer)
}

/// Dereferences a validated object_pointer as a &'static FrameCapabilityData.
///
/// # Safety
///
/// The caller MUST have validated that the slot's capability_type is Frame
/// and that object_pointer is non-zero. CapFrame capabilities are granted
/// with object_pointer set to the address of a `'static FrameCapabilityData`.
/// - Precondition: capability_type == Frame && object_pointer != 0.
/// - Invariant: INV-AUTH-002 (authority is explicit and typed).
/// - Evidence: matches the dereference_device_capability_data pattern in irq_bind.rs.
fn dereference_frame_capability_data(
    object_pointer: u64,
) -> Option<&'static FrameCapabilityData> {
    let data_pointer = object_pointer as *const FrameCapabilityData;
    unsafe { data_pointer.as_ref() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::capability_rights;
    use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};

    const FRAME_SLOT_INDEX: u8 = 0;

    static TEST_FRAME_DATA_WITH_READ: FrameCapabilityData = FrameCapabilityData {
        frame_physical_address: 0x0020_0000,
        frame_rights: capability_rights::READ,
    };

    fn build_valid_capability_slot(
        capability_type: CapabilityType,
        object_pointer: u64,
    ) -> CapabilitySlot {
        CapabilitySlot {
            state: CapabilitySlotState::Valid,
            capability_type,
            rights_bitmask: capability_rights::READ,
            object_pointer,
            generation_counter: 0,
            derivation_parent_index: u32::MAX,
            use_count_remaining: None,
            expiry_tick: None,
        }
    }

    /// null slot at the requested index → validation fails.
    #[test]
    fn test_frame_map_rejects_null_slot() {
        let cspace = CapabilitySpace::new();
        let result = validate_caller_holds_readable_frame(&cspace, FRAME_SLOT_INDEX);
        assert_eq!(result, FRAME_MAP_RETURN_FAIL);
    }

    /// slot holds an Endpoint, not a Frame → validation fails.
    #[test]
    fn test_frame_map_rejects_non_frame_capability_at_slot() {
        let mut cspace = CapabilitySpace::new();
        let slot_reference = cspace.lookup_slot_mut(FRAME_SLOT_INDEX);
        *slot_reference = build_valid_capability_slot(CapabilityType::Endpoint, 0xDEAD_BEEF);
        let frame_data = read_frame_capability_data(&cspace, FRAME_SLOT_INDEX);
        assert!(frame_data.is_none());
    }

    /// Successful validation still returns -1 (page mapping not implemented).
    /// Documents the current fail-closed contract explicitly.
    #[test]
    fn test_frame_map_returns_fail_even_on_valid_frame_until_mapping_is_implemented() {
        let mut cspace = CapabilitySpace::new();
        let frame_pointer = &TEST_FRAME_DATA_WITH_READ as *const FrameCapabilityData as u64;
        let slot_reference = cspace.lookup_slot_mut(FRAME_SLOT_INDEX);
        *slot_reference = build_valid_capability_slot(CapabilityType::Frame, frame_pointer);
        let result = validate_caller_holds_readable_frame(&cspace, FRAME_SLOT_INDEX);
        assert_eq!(
            result, FRAME_MAP_RETURN_FAIL,
            "fail closed until page-table mapping is wired"
        );
    }
}
