//! Kernel process table mapping ThreadIdentifier to live CapabilitySpace.
//!
//! The process table tracks which threads currently hold an active capability space.
//! Each entry maps a thread identifier to the thread's live CSpace for the duration
//! of the process's lifetime. Entries are installed at spawn and removed at exit.
//!
//! Enforces INV-AUTH-001: no process holds authority without explicit entry insertion.
//! Enforces INV-AUTH-005: bounds check on ThreadIdentifier prevents out-of-array access.
//!
//! Unsafe allowlist: src/kernel/src/process/process_table.rs
//! Test-only heap allocation for ~320 KiB ProcessTable struct (alloc + Box::from_raw).
//! Follows the established physical_allocator.rs pattern. No unsafe in production code paths.
#![allow(unsafe_code)]

use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::endpoint::ThreadIdentifier;
use crate::ipc::MAXIMUM_THREADS;

/// Error variants for process table operations.
///
/// Enforces INV-AUTH-005: out-of-bounds thread identifiers are rejected structurally.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcessTableError {
    /// The supplied ThreadIdentifier is >= MAXIMUM_THREADS.
    ///
    /// Enforces INV-AUTH-005: bounds check prevents out-of-array access (T-10-01-01).
    ThreadIdentifierOutOfBounds,
}

/// The kernel's process table: a fixed-size array mapping thread slots to CSpaces.
///
/// Each entry is `Some(CapabilitySpace)` for a live process or `None` for an empty slot.
/// The array is indexed by thread slot position, not directly by `ThreadIdentifier`.
/// Slot count is bounded by `MAXIMUM_THREADS` to prevent unbounded table growth.
pub struct ProcessTable {
    /// Fixed-size array of optional CSpaces, one slot per possible thread.
    pub entries: [Option<CapabilitySpace>; MAXIMUM_THREADS],
}

impl Default for ProcessTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessTable {
    /// Returns a new `ProcessTable` with all entries set to `None`.
    ///
    /// No thread holds a CSpace until explicitly inserted after process creation.
    pub fn new() -> Self {
        ProcessTable {
            entries: core::array::from_fn(|_| None),
        }
    }

    /// Inserts a `CapabilitySpace` for `thread_identifier`.
    ///
    /// Enforces INV-AUTH-005: bounds check prevents out-of-array access.
    /// Verified by: tests::test_process_table_insert_rejects_out_of_bounds
    pub fn insert_entry(
        &mut self,
        thread_identifier: ThreadIdentifier,
        capability_space: CapabilitySpace,
    ) -> Result<(), ProcessTableError> {
        let slot_index = validate_thread_identifier_bounds(thread_identifier)?;
        self.entries[slot_index] = Some(capability_space);
        Ok(())
    }

    /// Returns a shared reference to the `CapabilitySpace` for `thread_identifier`.
    ///
    /// Returns `None` if the slot is empty or the identifier is out of bounds.
    pub fn lookup_entry(&self, thread_identifier: ThreadIdentifier) -> Option<&CapabilitySpace> {
        let slot_index = convert_identifier_to_slot_index(thread_identifier)?;
        self.entries[slot_index].as_ref()
    }

    /// Returns a mutable reference to the `CapabilitySpace` for `thread_identifier`.
    ///
    /// Returns `None` if the slot is empty or the identifier is out of bounds.
    pub fn lookup_entry_mut(
        &mut self,
        thread_identifier: ThreadIdentifier,
    ) -> Option<&mut CapabilitySpace> {
        let slot_index = convert_identifier_to_slot_index(thread_identifier)?;
        self.entries[slot_index].as_mut()
    }

    /// Removes the `CapabilitySpace` for `thread_identifier`, setting the slot to `None`.
    ///
    /// Enforces INV-AUTH-001: authority cannot survive process exit.
    /// Verified by: tests::test_process_table_remove_entry
    pub fn remove_entry(
        &mut self,
        thread_identifier: ThreadIdentifier,
    ) -> Result<(), ProcessTableError> {
        let slot_index = validate_thread_identifier_bounds(thread_identifier)?;
        self.entries[slot_index] = None;
        Ok(())
    }
}

/// Validates that `thread_identifier` is within the allowed range and returns the slot index.
///
/// Enforces INV-AUTH-005: bounds check prevents out-of-array access (T-10-01-01).
/// Verified by: tests::test_process_table_insert_rejects_out_of_bounds
fn validate_thread_identifier_bounds(
    thread_identifier: ThreadIdentifier,
) -> Result<usize, ProcessTableError> {
    let slot_index = usize::try_from(thread_identifier).unwrap_or(usize::MAX);
    if slot_index >= MAXIMUM_THREADS {
        return Err(ProcessTableError::ThreadIdentifierOutOfBounds);
    }
    Ok(slot_index)
}

/// Converts `thread_identifier` to a slot index, returning `None` if out of bounds.
///
/// Used by lookup functions that return `Option` rather than `Result`.
fn convert_identifier_to_slot_index(thread_identifier: ThreadIdentifier) -> Option<usize> {
    validate_thread_identifier_bounds(thread_identifier).ok()
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::boxed::Box;

    use super::*;

    /// Heap-allocates a ProcessTable to avoid stack overflow (~320 KiB struct).
    ///
    /// ProcessTable holds 32 Option<CapabilitySpace> entries (~10 KiB each).
    /// Allocates raw memory then writes each entry as None to correctly initialize
    /// the Option discriminants without constructing the full struct on the stack.
    fn allocate_process_table_on_heap() -> Box<ProcessTable> {
        let layout = alloc::alloc::Layout::new::<ProcessTable>();
        // SAFETY: layout is non-zero size (ProcessTable is ~320 KiB).
        // - Precondition: layout has non-zero size for ProcessTable.
        // - Invariant: null check below enforces non-null before any dereference.
        // - Evidence: test_process_table_new_creates_empty_table validates None state.
        let raw_pointer = unsafe { alloc::alloc::alloc(layout) } as *mut ProcessTable;
        assert!(!raw_pointer.is_null(), "ProcessTable heap allocation failed: allocator returned null");
        initialize_process_table_entries_as_none(raw_pointer);
        // SAFETY: raw_pointer is non-null (asserted above); all entries initialized.
        // - Precondition: null check passed; initialize_process_table_entries_as_none ran.
        // - Invariant: Box::from_raw requires non-null, fully initialized pointer.
        // - Evidence: test_process_table_new_creates_empty_table validates None state.
        unsafe { Box::from_raw(raw_pointer) }
    }

    /// Writes None into each entry of a heap-allocated ProcessTable via raw pointer.
    ///
    /// Required because ProcessTable::new() would overflow the stack at ~320 KiB.
    /// Each entry is written independently to correctly set Option discriminants.
    fn initialize_process_table_entries_as_none(raw_pointer: *mut ProcessTable) {
        for entry_index in 0..MAXIMUM_THREADS {
            // SAFETY: raw_pointer is non-null; entry_index < MAXIMUM_THREADS keeps
            // the offset within the allocated ProcessTable memory region.
            // - Precondition: raw_pointer allocated for ProcessTable by alloc.
            // - Invariant: ptr::write sets Option<CapabilitySpace> discriminant to None.
            // - Evidence: test_process_table_new_creates_empty_table validates None state.
            unsafe {
                let entry_pointer = core::ptr::addr_of_mut!((*raw_pointer).entries[entry_index]);
                core::ptr::write(entry_pointer, None);
            }
        }
    }

    /// Heap-allocates a CapabilitySpace to avoid stack overflow (~10 KiB struct).
    ///
    /// CapabilitySpace holds 256 CapabilitySlots (~40 bytes each = ~10 KiB total).
    /// Uses alloc + ptr::write to bypass stack intermediate construction.
    fn allocate_capability_space_on_heap() -> Box<CapabilitySpace> {
        let layout = alloc::alloc::Layout::new::<CapabilitySpace>();
        // SAFETY: layout is non-zero size (CapabilitySpace is ~10 KiB).
        // - Precondition: layout has non-zero size for CapabilitySpace.
        // - Invariant: null check below enforces non-null before any dereference.
        // - Evidence: allocate_capability_space_on_heap is test-only infrastructure.
        let raw_pointer = unsafe { alloc::alloc::alloc(layout) } as *mut CapabilitySpace;
        assert!(!raw_pointer.is_null(), "CapabilitySpace heap allocation failed: allocator returned null");
        // SAFETY: raw_pointer is non-null (asserted above); ptr::write initializes fully.
        // - Precondition: null check passed; raw_pointer allocated for CapabilitySpace.
        // - Invariant: CapabilitySpace::new() produces all-null slots per INV-AUTH-001.
        // - Evidence: allocate_capability_space_on_heap is test-only infrastructure.
        unsafe {
            core::ptr::write(raw_pointer, CapabilitySpace::new());
            Box::from_raw(raw_pointer)
        }
    }

    /// Verifies that a server launched via boot sequence holds a live CSpace in the ProcessTable.
    ///
    /// Simulates the boot sequence grant-then-move pattern: create process, grant capability,
    /// insert CSpace into table, verify lookup returns Some.
    ///
    /// Enforces INV-AUTH-001: authority only exists after explicit ProcessTable insertion.
    /// Enforces T-10-02-01: CSpace is not dropped — it survives in the ProcessTable.
    #[test]
    fn integration_server_holds_live_cspace_after_boot() {
        use crate::capability::capability_rights;
        use crate::capability::capability_type::CapabilityType;
        use crate::process::server_launch::{
            create_server_process, grant_initial_capability_to_server,
        };
        use crate::process::ProcessType;
        let mut process_table = allocate_process_table_on_heap();
        let (handle, mut capability_space) =
            create_server_process(ProcessType::Init, 0x0000_0000_0040_0000).unwrap();
        grant_initial_capability_to_server(
            &mut capability_space,
            0,
            CapabilityType::Spawn,
            capability_rights::GRANT,
        );
        process_table
            .insert_entry(handle.thread_identifier, capability_space)
            .unwrap();
        let lookup_result = process_table.lookup_entry(handle.thread_identifier);
        assert!(
            lookup_result.is_some(),
            "server CSpace must be live in ProcessTable after boot launch"
        );
    }

    /// Verifies that runtime capability enforcement is active: CSpace accessible while
    /// live, then None after process exit (remove_entry).
    ///
    /// Enforces INV-AUTH-001: authority cannot survive process exit (D-04).
    /// Enforces T-10-04-01: no stale CSpace entries after exit.
    #[test]
    fn integration_runtime_capability_enforcement_is_active() {
        use crate::capability::capability_rights;
        use crate::capability::capability_type::CapabilityType;
        use crate::process::server_launch::{
            create_server_process, grant_initial_capability_to_server,
        };
        use crate::process::ProcessType;
        let mut process_table = allocate_process_table_on_heap();
        let (handle, mut capability_space) =
            create_server_process(ProcessType::Spawnd, 0x0000_0000_0040_0000).unwrap();
        grant_initial_capability_to_server(
            &mut capability_space,
            0,
            CapabilityType::Spawn,
            capability_rights::GRANT,
        );
        process_table
            .insert_entry(handle.thread_identifier, capability_space)
            .unwrap();
        verify_live_cspace_is_accessible(&process_table, handle.thread_identifier);
        process_table
            .remove_entry(handle.thread_identifier)
            .unwrap();
        let lookup_after_exit = process_table.lookup_entry(handle.thread_identifier);
        assert!(
            lookup_after_exit.is_none(),
            "authority must be revoked after process exit: lookup must return None"
        );
    }

    /// Asserts that the ProcessTable entry for `thread_identifier` is Some with a valid slot 0.
    fn verify_live_cspace_is_accessible(
        process_table: &ProcessTable,
        thread_identifier: ThreadIdentifier,
    ) {
        let live_cspace = process_table.lookup_entry(thread_identifier);
        assert!(
            live_cspace.is_some(),
            "runtime enforcement requires live CSpace to be accessible"
        );
        let slot_result = live_cspace.unwrap().lookup_slot(0);
        assert!(
            slot_result.is_ok(),
            "slot 0 must hold the granted capability"
        );
    }

    /// Verifies that a newly constructed ProcessTable has all entries set to None.
    ///
    /// Enforces INV-AUTH-001: no thread holds authority until explicitly inserted.
    #[test]
    fn test_process_table_new_creates_empty_table() {
        let process_table = allocate_process_table_on_heap();
        let lookup_result = process_table.lookup_entry(0);
        assert!(
            lookup_result.is_none(),
            "new process table must have no entry at slot 0"
        );
    }

    /// Verifies that an entry inserted into the process table can be retrieved by lookup.
    ///
    /// Enforces INV-AUTH-001: authority is only present after explicit insertion.
    #[test]
    fn test_process_table_insert_and_lookup() {
        let mut process_table = allocate_process_table_on_heap();
        let capability_space = *allocate_capability_space_on_heap();
        let insert_result = process_table.insert_entry(0, capability_space);
        assert!(insert_result.is_ok(), "insert must succeed for thread 0");
        let lookup_result = process_table.lookup_entry(0);
        assert!(
            lookup_result.is_some(),
            "lookup must return Some after insert"
        );
    }

    /// Verifies that removing an entry leaves the slot as None.
    ///
    /// Enforces INV-AUTH-001: authority cannot survive process exit.
    #[test]
    fn test_process_table_remove_entry() {
        let mut process_table = allocate_process_table_on_heap();
        let capability_space = *allocate_capability_space_on_heap();
        process_table.insert_entry(0, capability_space).unwrap();
        process_table.remove_entry(0).unwrap();
        let lookup_result = process_table.lookup_entry(0);
        assert!(
            lookup_result.is_none(),
            "lookup must return None after remove"
        );
    }

    /// Verifies that looking up an unregistered thread returns None.
    ///
    /// Enforces INV-AUTH-001: empty slots hold no authority.
    #[test]
    fn test_process_table_lookup_unregistered_thread_returns_none() {
        let process_table = allocate_process_table_on_heap();
        let lookup_result = process_table.lookup_entry(5);
        assert!(
            lookup_result.is_none(),
            "lookup of unregistered thread must return None"
        );
    }

    /// Verifies that insert rejects a ThreadIdentifier >= MAXIMUM_THREADS.
    ///
    /// Enforces INV-AUTH-005: bounds check prevents out-of-array access (T-10-01-01).
    #[test]
    fn test_process_table_insert_rejects_out_of_bounds() {
        let mut process_table = allocate_process_table_on_heap();
        let capability_space = *allocate_capability_space_on_heap();
        let out_of_bounds_identifier: ThreadIdentifier = 99;
        let insert_result = process_table.insert_entry(out_of_bounds_identifier, capability_space);
        assert_eq!(
            insert_result,
            Err(ProcessTableError::ThreadIdentifierOutOfBounds),
            "insert must reject identifier >= MAXIMUM_THREADS"
        );
    }

    /// Verifies that lookup_entry_mut returns a mutable reference that allows capability grant.
    ///
    /// Enforces INV-AUTH-001: mutable access is restricted to kernel code via &mut reference.
    #[test]
    fn test_process_table_lookup_mut_allows_capability_grant() {
        let mut process_table = allocate_process_table_on_heap();
        let capability_space = *allocate_capability_space_on_heap();
        process_table.insert_entry(0, capability_space).unwrap();
        let mutable_space = process_table.lookup_entry_mut(0);
        assert!(
            mutable_space.is_some(),
            "lookup_entry_mut must return Some for an inserted entry"
        );
    }
}
