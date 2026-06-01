//! Fixed-size stack for physical page addresses.
//!
//! Provides a bounded LIFO stack that stores physical page addresses (u64).
//! Returns explicit errors on overflow rather than panicking (INV-SCHED-004).

use crate::memory::allocation_error::AllocationError;

/// A fixed-capacity stack of physical page addresses.
///
/// Used by the physical allocator to track free pages. Capacity is
/// a compile-time const generic. Overflow returns an explicit error.
pub struct BoundedStack<const CAPACITY: usize> {
    storage: [u64; CAPACITY],
    count: usize,
}

impl<const CAPACITY: usize> Default for BoundedStack<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> BoundedStack<CAPACITY> {
    /// Creates a new empty bounded stack with zeroed storage.
    pub const fn new() -> Self {
        Self {
            storage: [0u64; CAPACITY],
            count: 0,
        }
    }

    /// Pushes a value onto the stack, returning an error if full.
    ///
    /// Enforces INV-SCHED-004: exhaustion is explicit, never silent.
    pub fn push(&mut self, value: u64) -> Result<(), AllocationError> {
        if self.count == CAPACITY {
            return Err(AllocationError::OutOfMemory);
        }
        self.storage[self.count] = value;
        self.count = self.count.wrapping_add(1);
        Ok(())
    }

    /// Pops a value from the stack, returning None if empty.
    pub fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count = self.count.wrapping_sub(1);
        Some(self.storage[self.count])
    }

    /// Returns true if the stack contains no elements.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of elements currently on the stack.
    pub const fn count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_stack_push_returns_error_on_full() {
        let mut stack: BoundedStack<2> = BoundedStack::new();
        assert!(stack.push(0x1000).is_ok());
        assert!(stack.push(0x2000).is_ok());
        let overflow_result = stack.push(0x3000);
        assert_eq!(overflow_result, Err(AllocationError::OutOfMemory));
    }

    #[test]
    fn test_bounded_stack_pop_returns_none_on_empty() {
        let mut stack: BoundedStack<4> = BoundedStack::new();
        let pop_result = stack.pop();
        assert_eq!(pop_result, None);
    }

    #[test]
    fn test_bounded_stack_push_and_pop_lifo_order() {
        let mut stack: BoundedStack<4> = BoundedStack::new();
        assert!(stack.push(0x1000).is_ok());
        assert!(stack.push(0x2000).is_ok());
        assert_eq!(stack.pop(), Some(0x2000));
        assert_eq!(stack.pop(), Some(0x1000));
    }

    #[test]
    fn test_bounded_stack_count_and_is_empty() {
        let mut stack: BoundedStack<4> = BoundedStack::new();
        assert!(stack.is_empty());
        assert_eq!(stack.count(), 0);
        assert!(stack.push(0x1000).is_ok());
        assert!(!stack.is_empty());
        assert_eq!(stack.count(), 1);
    }
}
