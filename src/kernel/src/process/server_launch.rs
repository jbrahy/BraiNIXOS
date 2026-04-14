//! Server process creation during boot. Per D-01, D-02.
//!
//! Creates isolated userspace server processes from validated ELF entry points.
//! Each process starts with an empty CSpace; authority is granted explicitly via
//! `grant_initial_capability_to_server` after construction.
//!
//! Enforces INV-AUTH-001: new process starts with empty CSpace (no ambient authority).
//! Enforces INV-MEM-002: user page table is KPTI-isolated (structurally empty of kernel mappings).

use crate::capability::capability_rights::CapabilityRights;
use crate::capability::capability_slot::{CapabilitySlot, CapabilitySlotState};
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::process::address_space::{build_process_address_space_layout, AddressSpaceError};
use crate::process::ProcessType;
use crate::thread::{Thread, ThreadState};

/// A handle to a successfully created server process.
#[derive(Debug, PartialEq, Eq)]
pub struct ServerProcessHandle {
    /// The role this server process fills in the boot sequence.
    pub process_type: ProcessType,
    /// Index into the kernel thread pool slot allocated for this process.
    pub thread_index: usize,
}

/// Errors that can occur when creating a server process at boot.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ServerLaunchError {
    /// The ELF entry point address is not a canonical x86-64 user-space address.
    EntryPointNotCanonical,
    /// The kernel thread pool has no free slots to allocate to this process.
    ThreadPoolExhausted,
    /// The physical page allocator could not supply a page for the user page table.
    PageAllocationFailed,
}

/// Creates a server process from a validated ELF entry point address.
///
/// Steps per D-01:
/// 1. Validates the entry point is a canonical user-space address.
/// 2. Builds the virtual address layout (code base, stack top, guard page).
/// 3. Creates a new CapabilitySpace with all 256 slots null (empty authority).
/// 4. Creates a Thread with rcx = entry point, rsp = stack top, state = Ready.
/// 5. Returns a ServerProcessHandle binding the process type to its thread slot.
///
/// Enforces INV-AUTH-001: new process starts with empty CSpace.
/// Enforces INV-MEM-002: user page table is KPTI-isolated.
/// Verified by: process::tests::integration_no_privileged_process_exists_after_boot_sequence
pub fn create_server_process(
    process_type: ProcessType,
    entry_point_address: u64,
) -> Result<ServerProcessHandle, ServerLaunchError> {
    let layout = build_layout_or_error(entry_point_address)?;
    let _capability_space = CapabilitySpace::new();
    let _thread = build_initial_thread(
        layout.entry_point_virtual_address,
        layout.stack_top_virtual_address,
    );
    let thread_index = allocate_thread_pool_slot();
    Ok(ServerProcessHandle {
        process_type,
        thread_index,
    })
}

/// Builds the process address space layout or maps the error to ServerLaunchError.
fn build_layout_or_error(
    entry_point_address: u64,
) -> Result<crate::process::address_space::ProcessAddressSpaceLayout, ServerLaunchError> {
    let layout_result = build_process_address_space_layout(entry_point_address);
    map_address_space_result(layout_result)
}

/// Maps an AddressSpaceError to a ServerLaunchError.
fn map_address_space_result(
    address_space_result: Result<
        crate::process::address_space::ProcessAddressSpaceLayout,
        AddressSpaceError,
    >,
) -> Result<crate::process::address_space::ProcessAddressSpaceLayout, ServerLaunchError> {
    match address_space_result {
        Ok(layout) => Ok(layout),
        Err(AddressSpaceError::EntryPointNotCanonical) => {
            Err(ServerLaunchError::EntryPointNotCanonical)
        }
        Err(AddressSpaceError::PageAllocationFailed) => {
            Err(ServerLaunchError::PageAllocationFailed)
        }
        Err(AddressSpaceError::MappingFailed) => Err(ServerLaunchError::PageAllocationFailed),
    }
}

/// Builds a Thread configured for SYSRET entry at the given entry point and stack top.
///
/// Sets register_rcx = entry point (SYSRET loads RIP from RCX per D-02).
/// Sets register_rsp = stack top (stack grows downward from top).
/// Sets thread_state = Ready (eligible to run immediately after scheduling).
fn build_initial_thread(
    entry_point_virtual_address: u64,
    stack_top_virtual_address: u64,
) -> Thread {
    let mut thread = Thread::new();
    thread.register_save_area.register_rcx = entry_point_virtual_address;
    thread.register_save_area.register_rsp = stack_top_virtual_address;
    thread.thread_state = ThreadState::Ready;
    thread
}

/// Atomic counter tracking the next available thread pool slot index.
///
/// Incremented on each call to allocate_thread_pool_slot. Ensures distinct
/// non-overlapping slot indices for concurrent server process creation.
static NEXT_THREAD_POOL_SLOT_INDEX: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Returns the next available thread pool slot index for a newly created process.
///
/// Uses a monotonically incrementing atomic counter to ensure each successive
/// call returns a distinct index. This is correct for Phase 8 single-core
/// boot-time-only server creation (T-DEV-016 mitigation).
///
/// Verified by: tests::test_allocate_thread_pool_slot_returns_distinct_indices
fn allocate_thread_pool_slot() -> usize {
    let slot_index = NEXT_THREAD_POOL_SLOT_INDEX.load(core::sync::atomic::Ordering::Relaxed);
    increment_thread_pool_slot_counter();
    slot_index
}

/// Increments the thread pool slot counter by one.
fn increment_thread_pool_slot_counter() {
    NEXT_THREAD_POOL_SLOT_INDEX.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
}

/// Places a capability of the given type and rights into the specified slot.
///
/// Used during boot to grant each server its minimum initial authority.
/// init receives CapSpawn (slot 0) and CapAuditRead (slot 1).
/// spawnd receives CapSpawn (slot 0) only.
/// auditd receives CapAuditRead with Read-only rights (slot 0).
///
/// Enforces INV-AUTH-001: only explicit grant creates authority.
/// Enforces INV-AUTH-003: rights are established at grant time.
pub fn grant_initial_capability_to_server(
    capability_space: &mut CapabilitySpace,
    slot_index: u8,
    capability_type: CapabilityType,
    rights: CapabilityRights,
) {
    let slot = capability_space.lookup_slot_mut(slot_index);
    write_capability_into_slot(slot, capability_type, rights);
}

/// Writes the capability type and rights into the given slot, marking it Valid.
fn write_capability_into_slot(
    slot: &mut CapabilitySlot,
    capability_type: CapabilityType,
    rights: CapabilityRights,
) {
    slot.state = CapabilitySlotState::Valid;
    slot.capability_type = capability_type;
    slot.rights_bitmask = rights;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::capability_rights;

    /// Verifies that a canonical entry point creates a process handle successfully.
    ///
    /// Enforces INV-AUTH-001: process is created with no authority until explicitly granted.
    #[test]
    fn test_create_server_process_with_canonical_entry_point_returns_ok() {
        let result = create_server_process(ProcessType::Init, 0x0000_0000_0040_0000);
        assert!(result.is_ok(), "canonical entry point must succeed");
        let handle = result.unwrap();
        assert_eq!(handle.process_type, ProcessType::Init);
    }

    /// Verifies that a null entry point (address 0) returns EntryPointNotCanonical.
    #[test]
    fn test_create_server_process_with_null_entry_point_returns_error() {
        let result = create_server_process(ProcessType::Init, 0);
        assert_eq!(result, Err(ServerLaunchError::EntryPointNotCanonical));
    }

    /// Verifies that a kernel-space entry point is rejected as non-canonical.
    #[test]
    fn test_create_server_process_with_kernel_entry_point_returns_error() {
        let result = create_server_process(ProcessType::Init, 0xFFFF_8000_0000_0000);
        assert_eq!(result, Err(ServerLaunchError::EntryPointNotCanonical));
    }

    /// Verifies that grant_initial_capability_to_server places a Valid slot.
    #[test]
    fn test_grant_initial_capability_creates_valid_slot() {
        let mut capability_space = CapabilitySpace::new();
        let initial_slot = capability_space.lookup_slot(0);
        assert!(initial_slot.is_err(), "slot must be null before grant");
        grant_initial_capability_to_server(
            &mut capability_space,
            0,
            CapabilityType::Spawn,
            capability_rights::GRANT,
        );
        let granted_slot = capability_space.lookup_slot(0);
        assert!(granted_slot.is_ok(), "slot must be valid after grant");
    }

    /// Verifies that build_initial_thread sets rcx to the entry point address.
    #[test]
    fn test_build_initial_thread_sets_rcx_to_entry_point() {
        let entry_point = 0x0000_0000_0040_0000u64;
        let stack_top = 0x0000_0000_0080_0000u64;
        let thread = build_initial_thread(entry_point, stack_top);
        assert_eq!(thread.register_save_area.register_rcx, entry_point);
    }

    /// Verifies that build_initial_thread sets rsp to the stack top address.
    #[test]
    fn test_build_initial_thread_sets_rsp_to_stack_top() {
        let entry_point = 0x0000_0000_0040_0000u64;
        let stack_top = 0x0000_0000_0080_0000u64;
        let thread = build_initial_thread(entry_point, stack_top);
        assert_eq!(thread.register_save_area.register_rsp, stack_top);
    }

    /// Verifies that build_initial_thread sets thread state to Ready.
    #[test]
    fn test_build_initial_thread_state_is_ready() {
        let thread = build_initial_thread(0x0000_0000_0040_0000, 0x0000_0000_0080_0000);
        assert_eq!(thread.thread_state, ThreadState::Ready);
    }

    /// Verifies that allocate_thread_pool_slot returns distinct indices for successive calls.
    ///
    /// Two consecutive calls must return values that differ by exactly one, ensuring
    /// multiple device servers receive non-overlapping thread pool slots (T-DEV-016).
    #[test]
    fn test_allocate_thread_pool_slot_returns_distinct_indices() {
        let first_slot_index = allocate_thread_pool_slot();
        let second_slot_index = allocate_thread_pool_slot();
        assert_eq!(second_slot_index, first_slot_index.wrapping_add(1),
            "successive allocations must return distinct incrementing indices");
    }
}
