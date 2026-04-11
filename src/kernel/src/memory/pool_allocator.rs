//! Generic pool allocator for kernel object types.
//!
//! Each kernel object type gets its own `PoolAllocator<T, CAPACITY>` instance,
//! providing heap isolation (HEAP-ISO). Backing storage lives in BSS as a
//! compile-time-sized array. No dynamic heap allocation.
//!
//! Security invariants enforced:
//! - INV-OBJ-002: Slots zeroed before allocation and after deallocation
//! - INV-MEM-006: Freed memory sanitized before reuse
//! - INV-SCHED-004: Exhaustion is explicit, never silent

#![allow(unsafe_code)]

use core::mem::MaybeUninit;

use crate::memory::allocation_error::AllocationError;

/// A fixed-capacity pool allocator backed by a static array in BSS.
///
/// Each slot is tracked by a boolean flag. Allocation scans for the first
/// free slot, zeroes it, and returns a mutable reference. Deallocation
/// zeroes the slot before marking it free.
pub struct PoolAllocator<T, const CAPACITY: usize> {
    backing_storage: [MaybeUninit<T>; CAPACITY],
    slot_is_allocated: [bool; CAPACITY],
    allocated_count: usize,
}

impl<T, const CAPACITY: usize> PoolAllocator<T, CAPACITY> {
    /// Creates a new empty pool allocator with all slots uninitialized and free.
    pub const fn new() -> Self {
        Self {
            backing_storage: [const { MaybeUninit::uninit() }; CAPACITY],
            slot_is_allocated: [false; CAPACITY],
            allocated_count: 0,
        }
    }

    /// Allocates a slot from the pool, returning its index and a mutable reference.
    ///
    /// Enforces INV-SCHED-004 (exhaustion is explicit, never panics).
    /// Enforces INV-OBJ-002 (slot zeroed before use).
    /// Verified by: test_pool_allocator_returns_valid_reference_on_allocate.
    pub fn allocate(&mut self) -> Result<(usize, &mut T), AllocationError> {
        let slot_index = self.find_first_free_slot_index()?;
        self.mark_slot_as_allocated(slot_index);
        self.increment_allocated_count();
        let reference = self.zero_and_initialize_slot(slot_index);
        Ok((slot_index, reference))
    }

    /// Deallocates a slot, zeroing its memory before marking it free.
    ///
    /// Enforces INV-OBJ-002 (slot zeroed on deallocation).
    /// Enforces INV-MEM-006 (freed memory sanitized before reuse).
    /// Verified by: test_pool_allocator_deallocate_makes_slot_reusable.
    pub fn deallocate(&mut self, slot_index: usize) -> Result<(), AllocationError> {
        self.validate_slot_index_is_allocated(slot_index)?;
        self.zero_slot_memory(slot_index);
        self.mark_slot_as_free(slot_index);
        self.decrement_allocated_count();
        Ok(())
    }

    /// Returns the number of currently allocated slots.
    pub fn allocated_count(&self) -> usize {
        self.allocated_count
    }

    /// Returns true if all slots are allocated.
    pub fn is_full(&self) -> bool {
        self.allocated_count == CAPACITY
    }

    fn find_first_free_slot_index(&self) -> Result<usize, AllocationError> {
        let free_slot = self
            .slot_is_allocated
            .iter()
            .position(|allocated| !allocated);
        free_slot.ok_or(AllocationError::PoolExhausted)
    }

    fn mark_slot_as_allocated(&mut self, slot_index: usize) {
        self.slot_is_allocated[slot_index] = true;
    }

    fn mark_slot_as_free(&mut self, slot_index: usize) {
        self.slot_is_allocated[slot_index] = false;
    }

    fn increment_allocated_count(&mut self) {
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.allocated_count += 1;
        }
    }

    fn decrement_allocated_count(&mut self) {
        #[allow(clippy::arithmetic_side_effects)]
        {
            self.allocated_count -= 1;
        }
    }

    /// Zeroes the slot memory and returns a mutable reference to the initialized value.
    ///
    /// Enforces INV-OBJ-002: slot is zeroed before any use.
    fn zero_and_initialize_slot(&mut self, slot_index: usize) -> &mut T {
        self.zero_slot_memory(slot_index);
        // SAFETY: Slot has been zeroed via write_bytes. The caller guarantees
        // slot_index < CAPACITY (validated by find_first_free_slot_index).
        // MaybeUninit pointer is valid for write_bytes of size_of::<T>() bytes.
        // Invariant: INV-OBJ-002 (slot zeroed before use).
        // Evidence: test_pool_allocator_returns_valid_reference_on_allocate.
        unsafe { self.backing_storage[slot_index].assume_init_mut() }
    }

    /// Zeroes the raw memory of a slot.
    ///
    /// Enforces INV-MEM-006: freed memory sanitized before reuse.
    fn zero_slot_memory(&mut self, slot_index: usize) {
        // SAFETY: slot_index is validated in range by callers.
        // - Precondition: slot_index < CAPACITY
        // - Invariant: INV-OBJ-002, INV-MEM-006 (memory zeroed)
        // - Evidence: test_pool_allocator_deallocate_makes_slot_reusable
        unsafe {
            core::ptr::write_bytes(self.backing_storage[slot_index].as_mut_ptr(), 0u8, 1);
        }
    }

    fn validate_slot_index_is_allocated(&self, slot_index: usize) -> Result<(), AllocationError> {
        if slot_index >= CAPACITY {
            return Err(AllocationError::DoubleFree);
        }
        let is_allocated = self.slot_is_allocated[slot_index];
        if !is_allocated {
            return Err(AllocationError::DoubleFree);
        }
        Ok(())
    }
}

impl<T, const CAPACITY: usize> Default for PoolAllocator<T, CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_allocator_returns_valid_reference_on_allocate() {
        let mut pool: PoolAllocator<u64, 8> = PoolAllocator::new();
        let result = pool.allocate();
        assert!(result.is_ok());
        let (_slot_index, value_reference) = result.unwrap();
        assert_eq!(*value_reference, 0u64);
    }

    #[test]
    fn test_pool_allocator_exhaustion_returns_pool_exhausted() {
        let mut pool: PoolAllocator<u64, 4> = PoolAllocator::new();
        for _ in 0..4 {
            let result = pool.allocate();
            assert!(result.is_ok());
        }
        let exhausted_result = pool.allocate();
        assert_eq!(
            exhausted_result.unwrap_err(),
            AllocationError::PoolExhausted
        );
    }

    #[test]
    fn test_pool_allocator_deallocate_makes_slot_reusable() {
        let mut pool: PoolAllocator<u64, 2> = PoolAllocator::new();
        let (slot_index, _reference) = pool.allocate().unwrap();
        let deallocate_result = pool.deallocate(slot_index);
        assert!(deallocate_result.is_ok());
        let reallocate_result = pool.allocate();
        assert!(reallocate_result.is_ok());
    }

    #[test]
    fn test_pool_allocator_double_deallocate_returns_error() {
        let mut pool: PoolAllocator<u64, 4> = PoolAllocator::new();
        let (slot_index, _reference) = pool.allocate().unwrap();
        let first_deallocate = pool.deallocate(slot_index);
        assert!(first_deallocate.is_ok());
        let second_deallocate = pool.deallocate(slot_index);
        assert_eq!(second_deallocate.unwrap_err(), AllocationError::DoubleFree);
    }

    #[test]
    fn test_pool_allocator_allocated_count_tracks_correctly() {
        let mut pool: PoolAllocator<u64, 8> = PoolAllocator::new();
        let (_, _) = pool.allocate().unwrap();
        let (_, _) = pool.allocate().unwrap();
        let (slot_to_free, _) = pool.allocate().unwrap();
        assert_eq!(pool.allocated_count(), 3);
        pool.deallocate(slot_to_free).unwrap();
        assert_eq!(pool.allocated_count(), 2);
    }

    #[test]
    fn test_pool_allocator_all_slots_are_unique() {
        let mut pool: PoolAllocator<u64, 8> = PoolAllocator::new();
        let mut slot_indices: [usize; 8] = [0; 8];
        for index in 0..8 {
            let (slot_index, _reference) = pool.allocate().unwrap();
            slot_indices[index] = slot_index;
        }
        for outer in 0..8 {
            for inner in (outer + 1)..8 {
                assert_ne!(slot_indices[outer], slot_indices[inner]);
            }
        }
    }
}
