//! Synchronous rendezvous endpoint (IPC_SPEC.md §2).
//!
//! An endpoint is a rendezvous point: senders and receivers block until
//! both parties are present. No buffering — messages exist only in registers.

use crate::ipc::bounded_queue::BoundedQueue;
use crate::ipc::{IpcError, MAXIMUM_THREADS_PER_ENDPOINT};

/// Thread identifier within the fixed thread pool (index into the thread array).
///
/// Using u32 (not usize) to keep pool items Copy + Default.
/// Value 0 is a valid thread index; use has_no_waiting_sender() to test emptiness.
pub type ThreadIdentifier = u32;

/// A synchronous rendezvous endpoint (IPC_SPEC.md §2).
///
/// Holds queues of blocked senders and receivers. When both sides arrive,
/// the kernel performs the rendezvous: copies registers, transfers capability,
/// wakes both threads.
pub struct Endpoint {
    /// Threads blocked waiting to send to this endpoint.
    sender_queue: BoundedQueue<ThreadIdentifier, MAXIMUM_THREADS_PER_ENDPOINT>,
    /// Threads blocked waiting to receive from this endpoint.
    receiver_queue: BoundedQueue<ThreadIdentifier, MAXIMUM_THREADS_PER_ENDPOINT>,
    /// Badge stamped onto messages; identifies sender authority to the receiver.
    pub badge: u64,
}

impl Endpoint {
    /// Returns a new endpoint with empty queues and zero badge.
    pub fn new() -> Self {
        Endpoint {
            sender_queue: BoundedQueue::new(),
            receiver_queue: BoundedQueue::new(),
            badge: 0,
        }
    }

    /// Returns `true` if no sender is currently queued.
    pub fn has_no_waiting_sender(&self) -> bool {
        self.sender_queue.is_empty()
    }

    /// Returns `true` if no receiver is currently queued.
    pub fn has_no_waiting_receiver(&self) -> bool {
        self.receiver_queue.is_empty()
    }

    /// Queues `thread_identifier` on the sender side.
    pub fn enqueue_sender(&mut self, thread_identifier: ThreadIdentifier) -> Result<(), IpcError> {
        self.sender_queue.enqueue(thread_identifier)
    }

    /// Queues `thread_identifier` on the receiver side.
    pub fn enqueue_receiver(&mut self, thread_identifier: ThreadIdentifier) -> Result<(), IpcError> {
        self.receiver_queue.enqueue(thread_identifier)
    }

    /// Removes and returns the next waiting sender, or `None`.
    pub fn dequeue_sender(&mut self) -> Option<ThreadIdentifier> {
        self.sender_queue.dequeue()
    }

    /// Removes and returns the next waiting receiver, or `None`.
    pub fn dequeue_receiver(&mut self) -> Option<ThreadIdentifier> {
        self.receiver_queue.dequeue()
    }
}

/// Initializes a single `Endpoint` for use in array construction.
fn build_empty_endpoint() -> Endpoint {
    Endpoint::new()
}

/// A fixed-size pool of endpoints backed by a BSS array.
pub struct EndpointPool {
    endpoints: [Endpoint; crate::ipc::MAXIMUM_ENDPOINTS],
}

impl EndpointPool {
    /// Returns a new pool with all endpoints initialized to empty state.
    pub fn new() -> Self {
        EndpointPool {
            endpoints: core::array::from_fn(|_| build_empty_endpoint()),
        }
    }

    /// Returns a mutable reference to the endpoint at `endpoint_index`.
    ///
    /// `endpoint_index` must be less than `MAXIMUM_ENDPOINTS`.
    pub fn endpoint_at_mut(&mut self, endpoint_index: usize) -> Option<&mut Endpoint> {
        self.endpoints.get_mut(endpoint_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_endpoint_has_no_waiting_threads() {
        let endpoint = Endpoint::new();
        assert!(endpoint.has_no_waiting_sender());
        assert!(endpoint.has_no_waiting_receiver());
    }

    #[test]
    fn enqueue_sender_then_dequeue_returns_thread_identifier() {
        let mut endpoint = Endpoint::new();
        endpoint.enqueue_sender(42).unwrap();
        assert!(!endpoint.has_no_waiting_sender());
        let dequeued = endpoint.dequeue_sender();
        assert_eq!(dequeued, Some(42));
        assert!(endpoint.has_no_waiting_sender());
    }

    #[test]
    fn enqueue_receiver_then_dequeue_returns_thread_identifier() {
        let mut endpoint = Endpoint::new();
        endpoint.enqueue_receiver(7).unwrap();
        assert!(!endpoint.has_no_waiting_receiver());
        let dequeued = endpoint.dequeue_receiver();
        assert_eq!(dequeued, Some(7));
        assert!(endpoint.has_no_waiting_receiver());
    }

    #[test]
    fn sender_queue_full_returns_queue_full_error() {
        let mut endpoint = Endpoint::new();
        for thread_identifier in 0..MAXIMUM_THREADS_PER_ENDPOINT as u32 {
            endpoint.enqueue_sender(thread_identifier).unwrap();
        }
        let overflow_result = endpoint.enqueue_sender(99);
        assert_eq!(overflow_result, Err(IpcError::QueueFull));
    }
}
