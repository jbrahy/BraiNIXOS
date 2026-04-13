//! Fixed-size priority-sorted run queue for eligible threads.
//!
//! Holds thread indices sorted by effective priority (highest first).
//! Domain eligibility and budget checks are enforced by callers before insertion.
//! This module is a pure priority-sorted container — it does not inspect domain slots.
//! Bounded by MAXIMUM_THREADS to avoid dynamic allocation.

use super::{SchedulerError, MAXIMUM_THREADS};

/// Fixed-size run queue bounded by MAXIMUM_THREADS.
///
/// Entries are sorted by effective priority (highest first).
/// Domain eligibility and budget checks are enforced by callers before insertion.
/// The run queue is a pure priority-sorted container — it does not inspect domain slots.
///
/// INV-SCHED-001 is enforced by `is_thread_eligible_to_run` in context_switch.rs
/// before any insertion into this queue.
/// Verified by: test_run_queue_insert_and_select_highest_priority
pub struct RunQueue {
    /// Thread indices stored in priority-descending order.
    thread_indices: [u32; MAXIMUM_THREADS],
    /// Effective priorities parallel to thread_indices.
    effective_priorities: [u8; MAXIMUM_THREADS],
    /// Number of valid entries in the queue.
    entry_count: usize,
}

impl RunQueue {
    /// Creates a new empty run queue.
    pub const fn new() -> Self {
        RunQueue {
            thread_indices: [0; MAXIMUM_THREADS],
            effective_priorities: [0; MAXIMUM_THREADS],
            entry_count: 0,
        }
    }

    /// Inserts a thread into the run queue sorted by effective priority (descending).
    ///
    /// Returns `SchedulerError::NoEligibleThread` if the queue is full.
    ///
    /// Caller is responsible for domain eligibility validation
    /// (see `is_thread_eligible_to_run` in context_switch.rs) before calling this function.
    /// Verified by: test_run_queue_insert_and_select_highest_priority
    pub fn insert_thread(
        &mut self,
        thread_index: u32,
        effective_priority: u8,
    ) -> Result<(), SchedulerError> {
        if self.entry_count >= MAXIMUM_THREADS {
            return Err(SchedulerError::NoEligibleThread);
        }
        let insertion_position = self.find_insertion_position(effective_priority);
        self.shift_entries_right(insertion_position);
        self.write_entry_at(insertion_position, thread_index, effective_priority);
        Ok(())
    }

    /// Removes a thread from the run queue by its index.
    ///
    /// If the thread is not in the queue, this is a no-op.
    pub fn remove_thread(&mut self, thread_index: u32) {
        let position = self.find_thread_position(thread_index);
        if let Some(found_position) = position {
            self.shift_entries_left(found_position);
        }
    }

    /// Returns the thread index with the highest effective priority.
    ///
    /// Returns `None` if the queue is empty.
    pub fn select_highest_priority_thread(&self) -> Option<u32> {
        if self.entry_count == 0 {
            return None;
        }
        Some(self.thread_indices[0])
    }

    /// Returns the number of entries currently in the queue.
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }

    /// Returns true if the queue contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    /// Finds the position where a new entry with the given priority should be inserted.
    fn find_insertion_position(&self, effective_priority: u8) -> usize {
        let mut position: usize = 0;
        while position < self.entry_count {
            if self.effective_priorities[position] < effective_priority {
                return position;
            }
            position += 1;
        }
        position
    }

    /// Shifts entries right starting from the given position to make room for insertion.
    fn shift_entries_right(&mut self, from_position: usize) {
        let mut shift_index = self.entry_count;
        while shift_index > from_position {
            self.thread_indices[shift_index] = self.thread_indices[shift_index - 1];
            self.effective_priorities[shift_index] = self.effective_priorities[shift_index - 1];
            shift_index -= 1;
        }
    }

    /// Writes a thread entry at the specified position and increments the count.
    fn write_entry_at(&mut self, position: usize, thread_index: u32, effective_priority: u8) {
        self.thread_indices[position] = thread_index;
        self.effective_priorities[position] = effective_priority;
        self.entry_count += 1;
    }

    /// Finds the position of a thread in the queue by its index.
    fn find_thread_position(&self, thread_index: u32) -> Option<usize> {
        let mut search_index: usize = 0;
        while search_index < self.entry_count {
            if self.thread_indices[search_index] == thread_index {
                return Some(search_index);
            }
            search_index += 1;
        }
        None
    }

    /// Shifts entries left to fill the gap at the given position after removal.
    fn shift_entries_left(&mut self, removed_position: usize) {
        let mut shift_index = removed_position;
        while shift_index + 1 < self.entry_count {
            self.thread_indices[shift_index] = self.thread_indices[shift_index + 1];
            self.effective_priorities[shift_index] = self.effective_priorities[shift_index + 1];
            shift_index += 1;
        }
        self.entry_count -= 1;
    }
}
