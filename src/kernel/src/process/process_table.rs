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
        // - Invariant: each entry is initialized via initialize_entries_as_none before use.
        // - Evidence: test_process_table_new_creates_empty_table validates None state.
        let raw_pointer = unsafe { alloc::alloc::alloc(layout) } as *mut ProcessTable;
        initialize_process_table_entries_as_none(raw_pointer);
        // SAFETY: raw_pointer is non-null; all entries initialized by initialize helper.
        // - Precondition: initialize_process_table_entries_as_none ran on raw_pointer.
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
        // - Invariant: ptr::write initializes the struct before Box::from_raw.
        // - Evidence: allocate_capability_space_on_heap is test-only infrastructure.
        let raw_pointer = unsafe { alloc::alloc::alloc(layout) } as *mut CapabilitySpace;
        // SAFETY: raw_pointer is non-null; ptr::write initializes the struct fully.
        // - Precondition: raw_pointer allocated for CapabilitySpace by alloc.
        // - Invariant: CapabilitySpace::new() produces all-null slots per INV-AUTH-001.
        // - Evidence: allocate_capability_space_on_heap is test-only infrastructure.
        unsafe {
            core::ptr::write(raw_pointer, CapabilitySpace::new());
            Box::from_raw(raw_pointer)
        }
    }

    /// Verifies that a running server holds a live CSpace binding after kernel boot.
    ///
    /// Integration test stub — to be implemented in Plan 02.
    #[test]
    fn integration_server_holds_live_cspace_after_boot() {
        todo!()
    }

    /// Verifies that runtime capability enforcement is active for all live processes.
    ///
    /// Integration test stub — to be implemented in Plan 03.
    #[test]
    fn integration_runtime_capability_enforcement_is_active() {
        todo!()
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
