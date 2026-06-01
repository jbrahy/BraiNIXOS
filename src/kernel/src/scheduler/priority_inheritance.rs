//! Priority inheritance protocol for bounded priority inversion.
//!
//! When a high-priority thread blocks waiting for a resource held by a
//! low-priority thread, the holder's effective priority is temporarily raised
//! to the waiter's level. This prevents medium-priority threads from preempting
//! the holder and causing unbounded priority inversion (INV-SCHED-002).

use super::MAXIMUM_THREADS;

/// Tracks the effective priority for a single thread under priority inheritance.
///
/// Enforces INV-SCHED-002: effective priority is always max(base, inherited).
#[derive(Debug, Clone, Copy)]
pub struct EffectivePriorityRecord {
    /// The thread's fixed base priority assigned at creation.
    pub base_priority: u8,
    /// The priority temporarily inherited from a waiting higher-priority thread.
    pub inherited_priority: u8,
    /// True when a priority boost is active; false when operating at base priority.
    pub inheritance_is_active: bool,
}

/// Returns a new EffectivePriorityRecord with no active inheritance.
///
/// The inherited_priority field is initialized to zero and inheritance_is_active
/// to false, indicating no priority boost is in effect.
pub const fn new_effective_priority_record(base_priority: u8) -> EffectivePriorityRecord {
    EffectivePriorityRecord {
        base_priority,
        inherited_priority: 0,
        inheritance_is_active: false,
    }
}

/// Returns the effective scheduling priority for a thread.
///
/// Enforces INV-SCHED-002: when inheritance is active, returns max(base, inherited)
/// to ensure the holder is never preempted by a medium-priority thread.
pub fn compute_effective_priority(record: &EffectivePriorityRecord) -> u8 {
    if record.inheritance_is_active {
        return core::cmp::max(record.base_priority, record.inherited_priority);
    }
    record.base_priority
}

/// Boosts the holder thread's effective priority to the waiter's priority level.
///
/// Enforces INV-SCHED-002: sets inherited_priority and marks inheritance active.
/// Called when a high-priority thread begins waiting on a resource held by holder.
pub fn apply_priority_inheritance_boost(
    holder_index: u32,
    waiter_priority: u8,
    table: &mut [EffectivePriorityRecord; MAXIMUM_THREADS],
) {
    table[holder_index as usize].inherited_priority = waiter_priority;
    table[holder_index as usize].inheritance_is_active = true;
}

/// Restores the thread's effective priority to its base priority.
///
/// Enforces INV-SCHED-002. Called on rendezvous completion, timeout, or
/// thread termination to remove the temporary priority boost.
pub fn restore_base_priority(
    thread_index: u32,
    table: &mut [EffectivePriorityRecord; MAXIMUM_THREADS],
) {
    table[thread_index as usize].inheritance_is_active = false;
    table[thread_index as usize].inherited_priority = 0;
}

/// Boosts a single thread in the chain during propagation.
fn boost_thread_in_chain(
    thread_index: usize,
    waiter_priority: u8,
    table: &mut [EffectivePriorityRecord; MAXIMUM_THREADS],
) {
    table[thread_index].inherited_priority = waiter_priority;
    table[thread_index].inheritance_is_active = true;
}

/// Walks one step in the waiting-on chain, returning the next thread index.
fn advance_chain_step(
    current_index: usize,
    waiting_on_thread: &[Option<u32>; MAXIMUM_THREADS],
) -> Option<usize> {
    waiting_on_thread[current_index].map(|next| next as usize)
}

/// Propagates priority inheritance transitively along the waiting-on chain.
///
/// Walks from start_thread_index following waiting_on_thread links, boosting
/// each thread to waiter_priority. Bounded by MAXIMUM_THREADS iterations to
/// prevent infinite loops. Defense-in-depth: WaitForGraph already prevents
/// cycles at the IPC layer.
///
/// Enforces INV-SCHED-002.
pub fn propagate_priority_inheritance(
    start_thread_index: u32,
    waiter_priority: u8,
    waiting_on_thread: &[Option<u32>; MAXIMUM_THREADS],
    table: &mut [EffectivePriorityRecord; MAXIMUM_THREADS],
) {
    let mut current_index = start_thread_index as usize;
    for _ in 0..MAXIMUM_THREADS {
        boost_thread_in_chain(current_index, waiter_priority, table);
        match advance_chain_step(current_index, waiting_on_thread) {
            Some(next_index) => current_index = next_index,
            None => return,
        }
    }
}
