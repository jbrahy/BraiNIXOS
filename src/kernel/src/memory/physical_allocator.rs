//! Physical page allocator with typed page tags, zeroing, and double-free detection.
//!
//! Enforces INV-MEM-005 (explicit ownership), INV-MEM-006 (page zeroing),
//! INV-SCHED-004 (explicit exhaustion). Uses BoundedStack for free page tracking
//! and page_type_table/page_owner_table arrays for typed ownership.
//!
//! Allowlist: `src/kernel/src/memory/` -- write_bytes for page zeroing (INV-MEM-006).
#![allow(unsafe_code)]

use crate::memory::allocation_error::AllocationError;
use crate::memory::bounded_stack::BoundedStack;
use crate::memory::page_type::PageType;
#[cfg(not(test))]
use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;
use crate::memory::virtual_address_layout::PAGE_SIZE_IN_BYTES;

/// Maximum number of physical pages supported (1 GB / 4096 bytes per page).
const MAXIMUM_PHYSICAL_PAGES: usize = 262_144;

/// Sentinel value indicating no process owns the page.
const PROCESS_IDENTIFIER_NONE: u16 = 0;

/// Tracks all physical pages with typed ownership, zeroing, and double-free detection.
///
/// Every page has exactly one type at any time (INV-MEM-005).
/// Pages are zeroed before allocation and after deallocation (INV-MEM-006).
pub struct PhysicalAllocator {
    free_page_stack: BoundedStack<MAXIMUM_PHYSICAL_PAGES>,
    page_type_table: [PageType; MAXIMUM_PHYSICAL_PAGES],
    page_owner_table: [u16; MAXIMUM_PHYSICAL_PAGES],
    total_pages_discovered: usize,
}

impl Default for PhysicalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalAllocator {
    /// Creates a new physical allocator with all pages marked as Free.
    pub const fn new() -> Self {
        Self {
            free_page_stack: BoundedStack::new(),
            page_type_table: [PageType::Free; MAXIMUM_PHYSICAL_PAGES],
            page_owner_table: [PROCESS_IDENTIFIER_NONE; MAXIMUM_PHYSICAL_PAGES],
            total_pages_discovered: 0,
        }
    }

    /// Registers a physical page with the given type.
    ///
    /// Free pages are pushed onto the free stack for later allocation.
    ///
    /// Pages whose frame number exceeds `MAXIMUM_PHYSICAL_PAGES` are silently
    /// dropped. The multiboot2 memory map originates outside the TCB and can
    /// describe regions beyond the allocator's fixed-size tables (e.g. QEMU's
    /// PCI hole near 0xB0000000); accepting them would index out-of-bounds.
    pub fn register_physical_page(&mut self, physical_address: u64, page_type: PageType) {
        let frame_number = compute_page_frame_number(physical_address);
        if frame_number >= MAXIMUM_PHYSICAL_PAGES {
            return;
        }
        self.page_type_table[frame_number] = page_type;
        self.total_pages_discovered = self.total_pages_discovered.wrapping_add(1);
        // Boot registration: stack capacity equals MAXIMUM_PHYSICAL_PAGES; overflow is structurally impossible.
        let _ = push_if_free_page(&mut self.free_page_stack, physical_address, page_type);
    }

    /// Allocates a user-owned page from the free pool.
    ///
    /// Enforces INV-MEM-005 (explicit ownership), INV-MEM-006 (page zeroing).
    /// Verified by: test_kernel_tagged_page_is_not_returned_by_user_allocator,
    /// test_allocated_page_is_zeroed_before_return.
    pub fn allocate_user_page(&mut self) -> Result<u64, AllocationError> {
        let physical_address = pop_free_page_address(&mut self.free_page_stack)?;
        let frame_number = compute_page_frame_number(physical_address);
        verify_page_is_free(self.page_type_table[frame_number])?;
        zero_page_at_address(physical_address);
        self.page_type_table[frame_number] = PageType::UserOwned;
        Ok(physical_address)
    }

    /// Allocates a kernel-owned page from the free pool.
    ///
    /// Enforces INV-MEM-005 (explicit ownership), INV-MEM-006 (page zeroing).
    pub fn allocate_kernel_page(&mut self) -> Result<u64, AllocationError> {
        let physical_address = pop_free_page_address(&mut self.free_page_stack)?;
        let frame_number = compute_page_frame_number(physical_address);
        verify_page_is_free(self.page_type_table[frame_number])?;
        zero_page_at_address(physical_address);
        self.page_type_table[frame_number] = PageType::Kernel;
        Ok(physical_address)
    }

    /// Deallocates a page, returning it to the free pool after zeroing.
    ///
    /// Enforces INV-MEM-006 (freed memory sanitized). Kernel pages cannot be freed.
    /// Returns PoolExhausted if the free stack is full (page is permanently lost otherwise).
    /// Verified by: test_double_free_is_detected_and_refused.
    pub fn deallocate_page(&mut self, physical_address: u64) -> Result<(), AllocationError> {
        let frame_number = compute_page_frame_number(physical_address);
        reject_invalid_deallocation(self.page_type_table[frame_number])?;
        zero_page_at_address(physical_address);
        self.page_type_table[frame_number] = PageType::Free;
        self.page_owner_table[frame_number] = PROCESS_IDENTIFIER_NONE;
        self.free_page_stack
            .push(physical_address)
            .map_err(|_| AllocationError::PoolExhausted)
    }

    /// Returns the total number of pages discovered during boot.
    pub const fn total_pages_discovered(&self) -> usize {
        self.total_pages_discovered
    }
}

/// Computes the page frame number from a physical address.
#[allow(clippy::arithmetic_side_effects)]
fn compute_page_frame_number(physical_address: u64) -> usize {
    (physical_address / PAGE_SIZE_IN_BYTES as u64) as usize
}

/// Pops a free page address from the stack or returns OutOfMemory.
fn pop_free_page_address(
    free_page_stack: &mut BoundedStack<MAXIMUM_PHYSICAL_PAGES>,
) -> Result<u64, AllocationError> {
    free_page_stack.pop().ok_or(AllocationError::OutOfMemory)
}

/// Verifies that the page type is Free (defense in depth).
fn verify_page_is_free(page_type: PageType) -> Result<(), AllocationError> {
    if !page_type.is_free() {
        return Err(AllocationError::DoubleFree);
    }
    Ok(())
}

/// Rejects deallocation of pages that are already free or are kernel-owned.
fn reject_invalid_deallocation(page_type: PageType) -> Result<(), AllocationError> {
    if page_type.is_free() {
        return Err(AllocationError::DoubleFree);
    }
    if page_type.is_kernel_owned() {
        return Err(AllocationError::ForbiddenFree);
    }
    Ok(())
}

/// Pushes the address onto the free stack if the page type is Free.
///
/// Returns PoolExhausted if the free stack is full and the page type is Free.
fn push_if_free_page(
    free_page_stack: &mut BoundedStack<MAXIMUM_PHYSICAL_PAGES>,
    physical_address: u64,
    page_type: PageType,
) -> Result<(), AllocationError> {
    if page_type.is_free() {
        free_page_stack
            .push(physical_address)
            .map_err(|_| AllocationError::PoolExhausted)?;
    }
    Ok(())
}

/// Zeroes a page at the given physical address (bare-metal implementation).
///
/// Enforces INV-MEM-006: freed memory is sanitized before reuse.
#[cfg(not(test))]
fn zero_page_at_address(physical_address: u64) {
    let virtual_address = physical_address.wrapping_add(DIRECT_MAP_REGION_START);
    let page_pointer = virtual_address as *mut u8;
    // SAFETY: physical_address is a valid page-aligned address from the free stack.
    // The direct map region maps all physical memory 1:1 starting at DIRECT_MAP_REGION_START.
    // - Precondition: physical_address is valid and kernel-mapped via direct map.
    // - Invariant: INV-MEM-006 (freed memory sanitized before reuse).
    // - Evidence: test_allocated_page_is_zeroed_before_return.
    unsafe {
        core::ptr::write_bytes(page_pointer, 0u8, PAGE_SIZE_IN_BYTES);
    }
}

/// Test-mode zeroing: increments a counter instead of writing to memory.
#[cfg(test)]
fn zero_page_at_address(_physical_address: u64) {
    ZERO_PAGE_CALL_COUNT.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Counter tracking how many times zero_page_at_address was called in test mode.
#[cfg(test)]
static ZERO_PAGE_CALL_COUNT: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
mod tests {
    extern crate alloc;
    use super::*;
    use alloc::boxed::Box;
    use core::sync::atomic::Ordering;

    /// Creates a heap-allocated test allocator with the specified number of free pages.
    fn create_test_allocator_with_free_pages(count: usize) -> Box<PhysicalAllocator> {
        let mut allocator = allocate_physical_allocator_on_heap();
        let base_address: u64 = 0x100000;
        register_free_pages(&mut allocator, base_address, count);
        allocator
    }

    /// Heap-allocates a PhysicalAllocator to avoid stack overflow (~1.5 MB struct).
    fn allocate_physical_allocator_on_heap() -> Box<PhysicalAllocator> {
        let layout = alloc::alloc::Layout::new::<PhysicalAllocator>();
        // SAFETY: Layout is non-zero size. We initialize all fields before use.
        // - Precondition: layout has non-zero size for PhysicalAllocator.
        // - Invariant: test-only code, no production unsafe.
        // - Evidence: test execution validates correct allocation.
        let pointer = unsafe { alloc::alloc::alloc_zeroed(layout) } as *mut PhysicalAllocator;
        let mut boxed = unsafe { Box::from_raw(pointer) };
        initialize_allocator_fields(&mut boxed);
        boxed
    }

    /// Sets all page_type_table entries to Free (zeroed memory has them as Kernel=0).
    fn initialize_allocator_fields(allocator: &mut PhysicalAllocator) {
        for index in 0..MAXIMUM_PHYSICAL_PAGES {
            allocator.page_type_table[index] = PageType::Free;
        }
    }

    /// Registers free pages starting at the given base address.
    fn register_free_pages(allocator: &mut PhysicalAllocator, base: u64, count: usize) {
        for page_index in 0..count {
            let address = base.wrapping_add((page_index * PAGE_SIZE_IN_BYTES) as u64);
            allocator.register_physical_page(address, PageType::Free);
        }
    }

    #[test]
    fn test_kernel_tagged_page_is_not_returned_by_user_allocator() {
        let mut allocator = allocate_physical_allocator_on_heap();
        allocator.register_physical_page(0x200000, PageType::Kernel);
        allocator.register_physical_page(0x201000, PageType::Free);
        let allocated_address = allocator.allocate_user_page().unwrap();
        assert_eq!(allocated_address, 0x201000);
    }

    #[test]
    fn test_allocated_page_is_zeroed_before_return() {
        ZERO_PAGE_CALL_COUNT.store(0, Ordering::SeqCst);
        let mut allocator = create_test_allocator_with_free_pages(1);
        let count_before = ZERO_PAGE_CALL_COUNT.load(Ordering::SeqCst);
        let _allocated = allocator.allocate_user_page().unwrap();
        let count_after = ZERO_PAGE_CALL_COUNT.load(Ordering::SeqCst);
        assert_eq!(count_after.wrapping_sub(count_before), 1);
    }

    #[test]
    fn test_double_free_is_detected_and_refused() {
        let mut allocator = create_test_allocator_with_free_pages(1);
        let address = allocator.allocate_user_page().unwrap();
        assert!(allocator.deallocate_page(address).is_ok());
        let second_free_result = allocator.deallocate_page(address);
        assert_eq!(second_free_result, Err(AllocationError::DoubleFree));
    }

    #[test]
    fn property_no_two_allocations_return_same_physical_address() {
        let mut allocator = create_test_allocator_with_free_pages(100);
        let mut addresses = [0u64; 100];
        for index in 0..100 {
            addresses[index] = allocator.allocate_user_page().unwrap();
        }
        assert_all_addresses_unique(&addresses);
    }

    /// Asserts that every address in the slice is unique.
    fn assert_all_addresses_unique(addresses: &[u64; 100]) {
        for outer_index in 0..addresses.len() {
            for inner_index in (outer_index.wrapping_add(1))..addresses.len() {
                assert_ne!(addresses[outer_index], addresses[inner_index]);
            }
        }
    }

    #[test]
    fn test_allocation_from_empty_returns_out_of_memory() {
        let mut allocator = allocate_physical_allocator_on_heap();
        let result = allocator.allocate_user_page();
        assert_eq!(result, Err(AllocationError::OutOfMemory));
    }

    #[test]
    fn test_kernel_page_cannot_be_deallocated() {
        let mut allocator = allocate_physical_allocator_on_heap();
        allocator.register_physical_page(0x200000, PageType::Kernel);
        let result = allocator.deallocate_page(0x200000);
        assert_eq!(result, Err(AllocationError::ForbiddenFree));
    }

    #[test]
    fn test_kernel_page_is_not_returned_after_kernel_allocation() {
        let mut allocator = allocate_physical_allocator_on_heap();
        allocator.register_physical_page(0x200000, PageType::Free);
        let allocated_address = allocator.allocate_kernel_page().unwrap();
        assert_eq!(allocated_address, 0x200000);
        let second_result = allocator.allocate_user_page();
        assert_eq!(second_result, Err(AllocationError::OutOfMemory));
    }
}
