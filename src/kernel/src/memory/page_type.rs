//! Canonical page type enum per MEMORY_MODEL.md Section 2.
//!
//! Every physical page frame is tagged with exactly one type at any time.
//! Enforces invariant INV-MEM-005: memory ownership is explicit.

/// The type of a physical page frame. Determines ownership, permitted use,
/// and allowed operations.
///
/// Enforces invariant INV-MEM-005: memory ownership is explicit.
/// Verified by: tests::test_kernel_page_is_not_user_allocatable
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageType {
    /// Kernel code, data, stacks, object pools. Never mapped in user page tables.
    Kernel = 0,
    /// Owned by a specific process for user code, data, stacks, heap.
    UserOwned = 1,
    /// Available for allocation. Zeroed before grant to any new owner.
    Free = 2,
    /// Memory-mapped I/O regions for hardware device access.
    DeviceMapped = 3,
    /// Shared buffer for large IPC data transfers (future extension).
    IpcBuffer = 4,
}

impl PageType {
    /// Returns true if this page is owned by the kernel.
    pub const fn is_kernel_owned(self) -> bool {
        matches!(self, PageType::Kernel)
    }

    /// Returns true if this page is free (unallocated).
    pub const fn is_free(self) -> bool {
        matches!(self, PageType::Free)
    }

    /// Returns true if this page may be allocated to a user process.
    /// Only free pages are eligible for user allocation.
    pub const fn is_user_allocatable(self) -> bool {
        matches!(self, PageType::Free)
    }
}

#[cfg(test)]
mod tests {
    use super::PageType;

    #[test]
    fn test_kernel_page_is_not_user_allocatable() {
        assert!(!PageType::Kernel.is_user_allocatable());
        assert!(PageType::Free.is_user_allocatable());
    }

    #[test]
    fn test_kernel_owned_returns_true_for_kernel() {
        assert!(PageType::Kernel.is_kernel_owned());
        assert!(!PageType::Free.is_kernel_owned());
    }

    #[test]
    fn test_is_free_returns_true_only_for_free() {
        assert!(PageType::Free.is_free());
        assert!(!PageType::Kernel.is_free());
        assert!(!PageType::UserOwned.is_free());
    }
}
