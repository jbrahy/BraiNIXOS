//! Kernel process table mapping ThreadIdentifier to live CapabilitySpace.
//!
//! The process table tracks which threads currently hold an active capability space.
//! Each entry maps a thread identifier to the thread's live CSpace for the duration
//! of the process's lifetime. Entries are installed at spawn and removed at exit.
//!
//! This is a skeleton module — only the struct definition and constructor are
//! implemented here. Insert, lookup, and remove operations are added in Plan 01.

use crate::capability::capability_space::CapabilitySpace;
use crate::ipc::MAXIMUM_THREADS;

/// The kernel's process table: a fixed-size array mapping thread slots to CSpaces.
///
/// Each entry is `Some(CapabilitySpace)` for a live process or `None` for an empty slot.
/// The array is indexed by thread slot position, not directly by `ThreadIdentifier`.
/// Slot count is bounded by `MAXIMUM_THREADS` to prevent unbounded table growth.
pub struct ProcessTable {
    /// Fixed-size array of optional CSpaces, one slot per possible thread.
    pub entries: [Option<CapabilitySpace>; MAXIMUM_THREADS],
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
}

#[cfg(test)]
mod tests {
    /// Verifies that a running server holds a live CSpace binding after kernel boot.
    ///
    /// Integration test stub — to be implemented in Plan 02.
    #[test]
    fn integration_server_holds_live_cspace_after_boot() {
        todo!()
    }

    /// Verifies that runtime capability enforcement is active for all live processes.
    ///
    /// Integration test stub — to be implemented in Plan 02.
    #[test]
    fn integration_runtime_capability_enforcement_is_active() {
        todo!()
    }

    /// Verifies that a newly constructed ProcessTable has all entries set to None.
    ///
    /// Unit test stub — to be implemented in Plan 01.
    #[test]
    fn test_process_table_new_creates_empty_table() {
        todo!()
    }

    /// Verifies that an entry inserted into the process table can be retrieved by lookup.
    ///
    /// Unit test stub — to be implemented in Plan 01.
    #[test]
    fn test_process_table_insert_and_lookup() {
        todo!()
    }

    /// Verifies that removing an entry leaves the slot as None.
    ///
    /// Unit test stub — to be implemented in Plan 01.
    #[test]
    fn test_process_table_remove_entry() {
        todo!()
    }
}
