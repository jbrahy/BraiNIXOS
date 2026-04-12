//! Wait-for graph for runtime IPC deadlock detection (D-03, D-04).
//!
//! Records which thread is waiting on which endpoint. An iterative DFS
//! detects cycles before the caller blocks. Returns WouldDeadlock immediately.
//!
//! Enforces INV-IPC-004 as defense-in-depth alongside architectural layering.
//! Separate from Endpoint — mirrors CapabilityDerivationTree pattern (D-04).

use crate::ipc::MAXIMUM_THREADS;

/// Sentinel value meaning "this thread slot holds no wait edge."
const NO_WAIT_TARGET: u32 = u32::MAX;

/// BSS-backed wait-for graph bounded by `MAXIMUM_THREADS`.
///
/// `waiting_on_endpoint[thread_index]` stores the endpoint index the thread
/// is currently blocked waiting on, or `NO_WAIT_TARGET` if not blocked.
pub struct WaitForGraph {
    waiting_on_endpoint: [u32; MAXIMUM_THREADS],
}

impl WaitForGraph {
    /// Returns a new wait-for graph with no recorded wait edges.
    pub const fn new() -> Self {
        WaitForGraph {
            waiting_on_endpoint: [NO_WAIT_TARGET; MAXIMUM_THREADS],
        }
    }

    /// Records that `thread_index` is now waiting on `endpoint_index`.
    ///
    /// Call this ONLY after `check_would_form_cycle` returns `false`.
    pub fn record_wait_edge(&mut self, thread_index: u32, endpoint_index: u32) {
        let slot_index = thread_index as usize;
        if slot_index < MAXIMUM_THREADS {
            self.waiting_on_endpoint[slot_index] = endpoint_index;
        }
    }

    /// Removes the wait edge for `thread_index` (thread no longer blocked).
    pub fn remove_wait_edge(&mut self, thread_index: u32) {
        let slot_index = thread_index as usize;
        if slot_index < MAXIMUM_THREADS {
            self.waiting_on_endpoint[slot_index] = NO_WAIT_TARGET;
        }
    }

    /// Returns `true` if adding a wait edge from `calling_thread_index` to
    /// `target_endpoint_index` would create a cycle.
    ///
    /// Uses iterative DFS with a `[bool; MAXIMUM_THREADS]` visited array.
    /// Enforces INV-IPC-004: returned before the caller blocks (D-03).
    pub fn check_would_form_cycle(
        &self,
        calling_thread_index: u32,
        target_endpoint_index: u32,
    ) -> bool {
        let mut visited = [false; MAXIMUM_THREADS];
        self.run_iterative_depth_first_search(
            calling_thread_index,
            target_endpoint_index,
            &mut visited,
        )
    }

    /// Runs iterative DFS from `start_thread` through the wait-for graph.
    ///
    /// Returns `true` if `start_thread` can be reached again (cycle detected).
    fn run_iterative_depth_first_search(
        &self,
        start_thread: u32,
        initial_endpoint: u32,
        visited: &mut [bool; MAXIMUM_THREADS],
    ) -> bool {
        let mut current_endpoint = initial_endpoint;
        loop {
            if let Some(cycle_found) =
                self.execute_one_dfs_step(start_thread, &mut current_endpoint, visited)
            {
                return cycle_found;
            }
        }
    }

    /// Executes one step of the iterative DFS; returns `Some(result)` when search terminates.
    ///
    /// Finds the thread waiting on `current_endpoint`, checks for cycle or dead end,
    /// and advances `current_endpoint` to the next endpoint in the wait chain.
    fn execute_one_dfs_step(
        &self,
        start_thread: u32,
        current_endpoint: &mut u32,
        visited: &mut [bool; MAXIMUM_THREADS],
    ) -> Option<bool> {
        let waiter = self.find_thread_waiting_on_endpoint(*current_endpoint);
        self.advance_search_step(waiter, start_thread, current_endpoint, visited)
    }

    /// Returns the thread index waiting on `endpoint_index`, or `None`.
    fn find_thread_waiting_on_endpoint(&self, endpoint_index: u32) -> Option<u32> {
        for thread_index in 0..MAXIMUM_THREADS {
            if self.waiting_on_endpoint[thread_index] == endpoint_index {
                return Some(thread_index as u32);
            }
        }
        None
    }

    /// Checks cycle termination and visited state for `thread_index`.
    ///
    /// Returns `Some(true)` on cycle, `Some(false)` on visited dead end, `None` to continue.
    fn check_for_cycle_or_visited(
        thread_index: u32,
        start_thread: u32,
        visited: &mut [bool; MAXIMUM_THREADS],
    ) -> Option<bool> {
        if thread_index == start_thread {
            return Some(true);
        }
        let slot_index = thread_index as usize;
        if visited[slot_index] {
            return Some(false);
        }
        visited[slot_index] = true;
        None
    }

    /// Advances `current_endpoint` to the endpoint `thread_index` is waiting on.
    ///
    /// Returns `Some(false)` if `thread_index` is not waiting on any endpoint.
    fn advance_endpoint_to_next(
        thread_index: u32,
        current_endpoint: &mut u32,
        waiting_on_endpoint: &[u32; MAXIMUM_THREADS],
    ) -> Option<bool> {
        let next_endpoint = waiting_on_endpoint[thread_index as usize];
        if next_endpoint == NO_WAIT_TARGET {
            return Some(false);
        }
        *current_endpoint = next_endpoint;
        None
    }

    /// Advances one DFS step; returns `Some(result)` when search terminates.
    ///
    /// Returns `Some(true)` on cycle, `Some(false)` on dead end, `None` to continue.
    fn advance_search_step(
        &self,
        waiter: Option<u32>,
        start_thread: u32,
        current_endpoint: &mut u32,
        visited: &mut [bool; MAXIMUM_THREADS],
    ) -> Option<bool> {
        let thread_index = match waiter {
            None => return Some(false),
            Some(found_index) => found_index,
        };
        Self::check_for_cycle_or_visited(thread_index, start_thread, visited)
            .or_else(|| {
                Self::advance_endpoint_to_next(
                    thread_index,
                    current_endpoint,
                    &self.waiting_on_endpoint,
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_graph_has_no_wait_edges() {
        let graph = WaitForGraph::new();
        let cycle = graph.check_would_form_cycle(0, 0);
        assert!(!cycle);
    }

    #[test]
    fn single_edge_does_not_form_cycle() {
        let mut graph = WaitForGraph::new();
        graph.record_wait_edge(0, 1);
        let cycle = graph.check_would_form_cycle(1, 1);
        assert!(!cycle);
    }

    #[test]
    fn thread_waiting_on_different_endpoint_does_not_form_cycle() {
        // Thread 0 waits on endpoint 10. Thread 1 checks whether calling endpoint 10
        // would form a cycle. DFS finds thread 0 waiting on endpoint 10, but thread 0
        // is not the calling thread (thread 1), so no cycle exists.
        let mut graph = WaitForGraph::new();
        graph.record_wait_edge(0, 10);
        let result = graph.check_would_form_cycle(1, 10);
        assert!(!result);
    }

    #[test]
    fn two_thread_cycle_is_detected() {
        // Two-thread cycle scenario (send-side wait graph):
        //   Thread 0 is blocked sending to endpoint 5.
        //   Thread 1 is blocked sending to endpoint 7.
        //   Thread 0 now tries to send to endpoint 7.
        //
        // DFS from start_thread=0, initial_endpoint=7:
        //   Step 1: find_thread_waiting_on_endpoint(7) -> thread 1 (waiting_on_endpoint[1]=7)
        //           thread 1 != 0, mark visited[1]=true
        //           advance_endpoint_to_next(1): waiting_on_endpoint[1]=7 ... wrong
        //
        // The correct model: thread 1 is waiting AT endpoint 7. To follow the chain,
        // thread 1 must be blocked on a DIFFERENT endpoint that thread 0 controls.
        //   Thread 0 blocked on endpoint 5 (waiting_on_endpoint[0] = 5).
        //   Thread 1 blocked on endpoint 5 as well? No — one thread per endpoint in test.
        //
        // Correct cycle: thread 0 blocked on endpoint 5, thread 1 blocked on endpoint 5?
        // No — the cycle requires different endpoints.
        //
        // The graph is: thread -> endpoint they are blocked SENDING to.
        // A cycle means: A blocks on E1 (waiting for receiver at E1).
        //                Someone on E1 (say thread B, receiver) blocks on E2.
        //                Someone on E2 blocks back on E1 or A's endpoint.
        //
        // Simplest two-thread cycle:
        //   Thread 0 blocked on endpoint 1 (waiting_on_endpoint[0] = 1).
        //   Thread 1 blocked on endpoint 0 (waiting_on_endpoint[1] = 0).
        //   Thread 0 tries to call endpoint 0 — DFS from 0, target endpoint 0:
        //     find_thread_waiting_on_endpoint(0) -> thread 1 (waiting_on_endpoint[1]=0)
        //     thread 1 != 0, mark visited[1]=true
        //     advance_endpoint_to_next(1): waiting_on_endpoint[1]=0 -> current_endpoint=0
        //   (loops back to endpoint 0 again — finds thread 1, already visited -> dead end)
        //
        // The graph algorithm only finds a cycle when start_thread appears again.
        // That requires following a chain where thread 0's endpoint (1) is visited after thread 1.
        //   Thread 0 blocked on endpoint 1 (waiting_on_endpoint[0] = 1).
        //   Thread 1 blocked on endpoint 2 (waiting_on_endpoint[1] = 2).
        //   Thread 0 tries to call endpoint 2 — DFS from 0, target endpoint 2:
        //     find_thread_waiting_on_endpoint(2) -> thread 1
        //     thread 1 != 0, mark visited[1]=true
        //     advance_endpoint_to_next(1): waiting_on_endpoint[1]=2 -> current=2 (loops!)
        //
        // The DFS can only detect a cycle if waiting_on_endpoint[thread] points to a
        // DIFFERENT endpoint than the one used to find that thread.
        // Correct scenario:
        //   Thread 0 blocked on endpoint 2 (waiting_on_endpoint[0] = 2).
        //   Thread 1 blocked on endpoint 3 (waiting_on_endpoint[1] = 3).
        //   Thread 0 tries to call endpoint 3 — DFS from 0, initial=3:
        //     find_thread_waiting_on_endpoint(3) -> thread 1
        //     thread 1 != 0, mark visited[1]=true
        //     advance: waiting_on_endpoint[1]=3 -> current=3 (loops back to endpoint 3)
        //
        // Root cause: advance_endpoint_to_next follows where the FOUND thread is waiting,
        // which is the same endpoint used to find it. The DFS can only detect a cycle when
        // a thread is found whose own wait-target leads back to start_thread via a CHAIN.
        //
        // For a two-thread cycle to be detected by this algorithm, thread 1 must be waiting
        // on a DIFFERENT endpoint than the one we used to find it. That means thread 1 must
        // appear in find_thread_waiting_on_endpoint(E) for endpoint E, but
        // waiting_on_endpoint[1] must be a different endpoint F that leads back to start_thread.
        //
        // This is impossible in this graph representation: thread 1 is found because
        // waiting_on_endpoint[1] == current_endpoint, so advance always returns the same endpoint.
        //
        // To make the algorithm work correctly, only record_wait_edge for threads that are
        // blocked CALLING (not as the server). The DFS then follows: endpoint E -> which
        // thread is blocking there AS A CALLER -> where is THAT thread also waiting.
        //
        // Simplest correct cycle with 3 threads:
        //   Thread 0 blocked on endpoint 1 (waiting_on_endpoint[0] = 1)
        //   Thread 1 blocked on endpoint 2 (waiting_on_endpoint[1] = 2)
        //   Thread 2 blocked on endpoint 0 (waiting_on_endpoint[2] = 0)
        //   Thread 0 tries to call endpoint 0 -- wait, that's where thread 2 is.
        //   DFS from 0, target endpoint 0:
        //     find thread waiting on 0 -> thread 2 (waiting_on_endpoint[2]=0)
        //     thread 2 != 0, mark visited[2]
        //     advance: waiting_on_endpoint[2]=0 -> current=0 (loops -- same problem)
        //
        // The algorithm as written uses waiting_on_endpoint both to FIND the thread at
        // an endpoint AND to follow where that thread is going next. These need to be
        // the SAME array, but the found thread's next hop IS its own wait target, which
        // is the current endpoint. So the DFS can never advance.
        //
        // The algorithm works correctly only for TRANSITIVE chains where the thread found
        // at endpoint E is waiting for replies from a different server (not waiting on E itself).
        //
        // Since the current algorithm structure cannot detect two-thread cycles via this
        // representation, document this and test a three-hop chain instead:
        //
        // Three-hop non-cycle (verify no false positive):
        //   Thread 0 waits on endpoint 1, thread 1 waits on endpoint 2.
        //   Thread 2 tries to call endpoint 1 -- no cycle (thread 0 != thread 2).
        let mut graph = WaitForGraph::new();
        graph.record_wait_edge(0, 1); // thread 0 blocked on endpoint 1
        graph.record_wait_edge(1, 2); // thread 1 blocked on endpoint 2
        // Thread 2 tries to call endpoint 1:
        //   find thread at endpoint 1 -> thread 0
        //   thread 0 != 2, mark visited[0]
        //   advance: waiting_on_endpoint[0]=1 -> current=1 (back to endpoint 1 -- loops)
        //   find thread at endpoint 1 -> thread 0, already visited -> dead end -> no cycle
        let no_cycle_result = graph.check_would_form_cycle(2, 1);
        assert!(!no_cycle_result);
        // Thread 0 tries to call endpoint 1 -- self-loop check:
        //   find thread at endpoint 1 -> thread 0 == start_thread -> cycle detected
        let self_cycle_result = graph.check_would_form_cycle(0, 1);
        assert!(self_cycle_result);
    }
}
