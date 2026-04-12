//! Fixed-capacity FIFO queue backed by a BSS array.
//!
//! Used for endpoint sender and receiver queues. No heap allocation.
//! Mirrors the BoundedStack pattern from Phase 2.

use crate::ipc::IpcError;

/// A fixed-capacity FIFO queue backed by an array.
///
/// `T` must be `Copy + Default` for const initialization.
/// `CAPACITY` is a const generic; for endpoints use `MAXIMUM_THREADS_PER_ENDPOINT`.
pub struct BoundedQueue<T, const CAPACITY: usize>
where
    T: Copy + Default,
{
    storage: [T; CAPACITY],
    head_index: usize,
    tail_index: usize,
    current_count: usize,
}

impl<T: Copy + Default, const CAPACITY: usize> BoundedQueue<T, CAPACITY> {
    /// Returns a new empty queue with all slots set to `T::default()`.
    pub fn new() -> Self {
        BoundedQueue {
            storage: [T::default(); CAPACITY],
            head_index: 0,
            tail_index: 0,
            current_count: 0,
        }
    }

    /// Returns `true` if the queue contains no elements.
    pub fn is_empty(&self) -> bool {
        self.current_count == 0
    }

    /// Returns `true` if the queue is at capacity.
    pub fn is_full(&self) -> bool {
        self.current_count == CAPACITY
    }

    /// Adds `value` to the back of the queue.
    ///
    /// Returns `Err(IpcError::QueueFull)` if the queue is at capacity.
    pub fn enqueue(&mut self, value: T) -> Result<(), IpcError> {
        if self.is_full() {
            return Err(IpcError::QueueFull);
        }
        self.write_value_at_tail(value);
        Ok(())
    }

    /// Removes and returns the front element, or `None` if empty.
    pub fn dequeue(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        Some(self.read_value_from_head())
    }

    /// Writes `value` at the current tail index and advances tail.
    fn write_value_at_tail(&mut self, value: T) {
        self.storage[self.tail_index] = value;
        self.tail_index = self.next_circular_index(self.tail_index);
        self.current_count = self.current_count.saturating_add(1);
    }

    /// Reads from the current head index and advances head.
    fn read_value_from_head(&mut self) -> T {
        let value = self.storage[self.head_index];
        self.head_index = self.next_circular_index(self.head_index);
        self.current_count = self.current_count.saturating_sub(1);
        value
    }

    /// Returns the next index in the circular buffer.
    fn next_circular_index(&self, index: usize) -> usize {
        let next = index.saturating_add(1);
        if next >= CAPACITY { 0 } else { next }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_queue_is_empty() {
        let queue: BoundedQueue<u32, 4> = BoundedQueue::new();
        assert!(queue.is_empty());
    }

    #[test]
    fn enqueue_then_dequeue_preserves_fifo_order() {
        let mut queue: BoundedQueue<u32, 4> = BoundedQueue::new();
        queue.enqueue(10).unwrap();
        queue.enqueue(20).unwrap();
        assert_eq!(queue.dequeue(), Some(10));
        assert_eq!(queue.dequeue(), Some(20));
        assert_eq!(queue.dequeue(), None);
    }

    #[test]
    fn enqueue_at_capacity_returns_queue_full() {
        let mut queue: BoundedQueue<u32, 2> = BoundedQueue::new();
        queue.enqueue(1).unwrap();
        queue.enqueue(2).unwrap();
        let result = queue.enqueue(3);
        assert_eq!(result, Err(IpcError::QueueFull));
    }

    #[test]
    fn circular_wraparound_reuses_slots() {
        let mut queue: BoundedQueue<u32, 2> = BoundedQueue::new();
        queue.enqueue(1).unwrap();
        queue.dequeue();
        queue.enqueue(2).unwrap();
        queue.enqueue(3).unwrap();
        assert_eq!(queue.dequeue(), Some(2));
        assert_eq!(queue.dequeue(), Some(3));
    }
}
