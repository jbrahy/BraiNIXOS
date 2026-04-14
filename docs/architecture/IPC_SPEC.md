# BraiNIX IPC Specification

## 1. Overview

BraiNIX uses synchronous rendezvous IPC as the sole inter-process communication mechanism. All communication between processes is kernel-mediated. There is no shared memory, no zero-copy path, and no ambient messaging namespace.

Synchronous rendezvous means:

- **The sender blocks** until a receiver is ready to accept the message.
- **The receiver blocks** until a sender is ready to deliver a message.
- **The kernel mediates** every message transfer, validating capabilities and enforcing rights at every step.
- **No message is buffered** in the kernel. Messages exist only in CPU registers during the transfer.

This model is directly inspired by seL4's synchronous IPC. It provides natural backpressure (a fast sender cannot overwhelm a slow receiver), eliminates buffer management complexity in the kernel, and makes authority flow explicit and auditable.

All IPC operations require explicit capabilities. A process cannot send to an endpoint it does not hold a CapEndpoint for. A process cannot receive from an endpoint it does not hold a CapEndpoint for with Read rights. There is no ambient messaging (INV-AUTH-001, INV-IPC-001).

---

## 2. Endpoint Types

### Synchronous Endpoints

A synchronous endpoint is a kernel object that acts as a rendezvous point for sender-receiver pairs. It has no internal message buffer.

```rust
struct Endpoint {
    sender_queue: BoundedQueue<ThreadIdentifier>,
    receiver_queue: BoundedQueue<ThreadIdentifier>,
    badge: u64,
}
```

- `sender_queue`: threads blocked waiting to send to this endpoint.
- `receiver_queue`: threads blocked waiting to receive from this endpoint.
- `badge`: an identifier stamped onto messages sent through this endpoint, allowing the receiver to identify the sender's authority without inspecting the sender's identity directly.

When a sender and receiver are both ready, the kernel performs the rendezvous: it copies message registers from the sender's register state to the receiver's register state, transfers any capability (if requested), wakes both threads, and returns.

### Notification Objects

A notification object is a lightweight non-blocking signal mechanism. It is a single machine word used as a bitmap of pending signals.

```rust
struct Notification {
    signal_word: AtomicU64,
}
```

- **Signal (non-blocking):** The sender ORs a bitmask into the signal word. This never blocks.
- **Wait (blocking or polling):** The receiver reads and clears the signal word. If the word is zero, the receiver blocks until a signal arrives (with mandatory timeout).
- **Poll (non-blocking):** The receiver reads and clears the signal word. If the word is zero, returns immediately with an empty result.

Notification objects are accessed via CapEndpoint capabilities with a notification flag. They do not support capability transfer or message registers. They are used for lightweight event signaling (e.g., interrupt arrival, timer tick).

---

## 3. Message Structure

### Registers-Only Fast Path

Messages are transferred entirely in CPU registers. There is no kernel message buffer, no heap allocation, and no memory copy beyond the register save/restore that already occurs during the syscall trap.

The message layout uses the following registers:

| Register | Purpose |
|---|---|
| Message Register 0 (`r8`) | First data word |
| Message Register 1 (`r9`) | Second data word |
| Message Register 2 (`r10`) | Third data word |
| Message Register 3 (`r11`) | Fourth data word |
| Capability Register (`r12`) | CSlot index of capability to transfer (or `0xFF` for no transfer) |

**4 data registers + 1 capability register** provide enough capacity for typical microkernel messages:

- Object identifiers, error codes, and small payloads fit in 4 words (32 bytes).
- Larger data transfers are performed by granting a CapMemory to the receiver, which maps the memory into the receiver's address space.
- This eliminates the need for variable-length message buffers in the kernel.

### Message Transfer Atomicity

The message transfer is atomic from the perspective of both sender and receiver:

1. The kernel copies all 4 data registers from sender to receiver.
2. If a capability transfer is requested, the kernel performs the capability transfer atomically (see Section 5).
3. Both sender and receiver are unblocked.

No partial message can be observed. Either the entire message (data + capability) is delivered, or nothing is delivered (on error or timeout).

---

## 4. Send/Receive Semantics

### Blocking Send

```
Syscall: SYS_IPC_SEND
Arguments:
    endpoint_slot: u8     -- CSlot containing CapEndpoint with Write right
    message_registers: [u64; 4]  -- Data payload
    capability_slot: u8   -- CSlot of capability to transfer (0xFF = none)
    timeout_ticks: u64    -- Maximum ticks to wait (0 = yield-only, no wait)
Returns:
    Ok(())                -- Message delivered
    Err(IpcError)         -- Timeout, EndpointRevoked, CapabilityError
```

**Protocol:**

1. The sender invokes `SYS_IPC_SEND` with an endpoint capability, message data, and timeout.
2. The kernel validates the endpoint capability (type check, rights check, generation check).
3. If a receiver is already waiting on this endpoint: the kernel performs the rendezvous immediately (copy registers, transfer capability, wake both).
4. If no receiver is waiting: the sender is placed on the sender queue and blocks until either a receiver arrives or the timeout fires.
5. If the timeout fires before a receiver arrives: the sender is removed from the queue and `IpcError::Timeout` is returned.

### Blocking Receive

```
Syscall: SYS_IPC_RECEIVE
Arguments:
    endpoint_slot: u8     -- CSlot containing CapEndpoint with Read right
    receive_cap_slot: u8  -- CSlot where a transferred capability should be placed (must be null)
    timeout_ticks: u64    -- Maximum ticks to wait
Returns:
    Ok(IpcMessage)        -- Message received (data registers + badge + optional capability)
    Err(IpcError)         -- Timeout, EndpointRevoked, SlotOccupied
```

**Protocol:**

1. The receiver invokes `SYS_IPC_RECEIVE` with an endpoint capability, a destination CSlot for capability transfer, and timeout.
2. The kernel validates the endpoint capability (type check, Read right, generation check).
3. If a sender is already waiting on this endpoint: the kernel performs the rendezvous immediately.
4. If no sender is waiting: the receiver is placed on the receiver queue and blocks until either a sender arrives or the timeout fires.
5. If the timeout fires before a sender arrives: the receiver is removed from the queue and `IpcError::Timeout` is returned.

### Call (Send + Receive)

```
Syscall: SYS_IPC_CALL
Arguments:
    endpoint_slot: u8     -- CSlot containing CapEndpoint with Read+Write rights
    message_registers: [u64; 4]  -- Request payload
    capability_slot: u8   -- CSlot of capability to transfer (0xFF = none)
    receive_cap_slot: u8  -- CSlot for reply capability transfer
    timeout_ticks: u64    -- Maximum ticks for the entire call (send + reply)
Returns:
    Ok(IpcMessage)        -- Reply received
    Err(IpcError)         -- Timeout, EndpointRevoked, CapabilityError
```

`SYS_IPC_CALL` is an atomic send-then-receive. The caller sends a message and immediately blocks waiting for a reply. The kernel automatically creates a CapReply and grants it to the server that receives the call.

---

## 5. Capability Transfer

Capabilities can be transferred between processes during IPC. This is the only mechanism for authority delegation at runtime (besides derivation within a single CSpace).

### Transfer Protocol

1. The sender specifies a source CSlot containing the capability to transfer.
2. The receiver specifies a destination CSlot (must be null).
3. The kernel validates:
   - The sender holds the capability with Grant right (INV-IPC-002).
   - The destination slot in the receiver's CSpace is null.
   - The receiver's domain quota has room for one more capability.
4. The kernel atomically:
   - Copies the capability from the sender's CSlot to the receiver's CSlot.
   - Updates the derivation tree to record the new parent-child relationship.
   - Increments the receiver's domain quota counter.
5. The sender retains the original capability unless it explicitly deletes it.

### Rights Validation

The transferred capability cannot exceed the sender's rights. If the sender holds a CapEndpoint with Read-only rights, the receiver receives a CapEndpoint with at most Read rights. This preserves rights monotonicity (INV-AUTH-003, INV-IPC-002).

### Destination Slot Selection

The receiver specifies which CSlot to receive the transferred capability into. If the specified slot is not null, the transfer fails with `IpcError::SlotOccupied`. The receiver never receives a capability in an unexpected slot.

### Transfer Atomicity

Capability transfer is atomic with message delivery. Either both the message and capability are delivered, or neither is. There is no state where the message has been delivered but the capability has not, or vice versa.

---

## 6. Reply Capability

The reply capability (CapReply) is a core mechanism for client-server communication patterns.

### Lifecycle

1. When a server calls `SYS_IPC_RECEIVE` on an endpoint and a client's `SYS_IPC_CALL` is waiting, the kernel automatically creates a CapReply.
2. The CapReply is placed in a designated slot in the server's CSpace.
3. The server processes the request and uses the CapReply to send the reply.
4. **The CapReply is consumed on use.** After the server sends the reply, the CapReply slot is zeroed.

### Properties

- **Single-use:** A CapReply can be used exactly once. After use, it is gone. Attempting to use a consumed CapReply returns `CapabilityError::NullCapability`.
- **Unforgeable:** The CapReply is created by the kernel, not by the client or server. It cannot be constructed from raw bits (INV-AUTH-005).
- **Non-copyable:** A CapReply cannot be copied, derived, or transferred via IPC. It exists only in the server's CSpace and only for the duration of request processing (INV-AUTH-006).
- **Non-storable:** A CapReply should be used promptly. If the server's timeout expires before the reply is sent, the CapReply is revoked and the client receives `IpcError::Timeout`.

### Reply with Capability Transfer

The server may transfer a capability as part of its reply, following the same capability transfer protocol as regular IPC (Section 5). The transferred capability's rights are validated against the server's rights.

---

## 7. Timeout Policy

Every blocking IPC operation has a mandatory tick-count timeout. No operation can block indefinitely. This is enforced structurally, not by convention.

### Timeout Specification

- All `SYS_IPC_SEND`, `SYS_IPC_RECEIVE`, and `SYS_IPC_CALL` syscalls accept a `timeout_ticks` argument.
- A `timeout_ticks` value of `0` means "try immediately, do not block." This is equivalent to a poll.
- The maximum timeout value is `u64::MAX - 1`. The value `u64::MAX` is reserved and returns `IpcError::InvalidTimeout`.
- There is no "infinite timeout" option. This is a deliberate design choice to prevent liveness attacks (INV-IPC-003).

### Timeout Behavior

When a timeout fires:

1. The blocked thread is removed from the sender or receiver queue.
2. The thread is made runnable again.
3. The syscall returns `IpcError::Timeout`.
4. Any partially prepared capability transfer is rolled back (no partial state).
5. If the thread held a CapReply that was not used, the CapReply is revoked.

### Default Timeout

There is no system-wide default timeout. Every caller must specify its own timeout explicitly. This forces callers to make a conscious decision about how long they are willing to wait, which prevents the common pattern of "accidentally infinite blocking."

### Timeout Determinism

Timeout processing is deterministic with respect to the scheduler tick. The kernel checks timeouts at each scheduler tick, and expired timeouts are processed in FIFO order within the same tick. This prevents timeout-related race conditions (INV-SCHED-003).

---

## 8. SYSCALL/SYSRET ABI

BraiNIX uses the x86-64 `SYSCALL`/`SYSRET` instruction pair for fast-path kernel entry and exit. This section defines the register layout for IPC syscalls.

### Kernel Entry (SYSCALL)

When userspace executes the `SYSCALL` instruction:

| Register | Purpose |
|---|---|
| `rax` | Syscall number (SYS_IPC_SEND = 1, SYS_IPC_RECEIVE = 2, SYS_IPC_CALL = 3) |
| `rdi` | Endpoint CSlot index (u8, zero-extended to u64) |
| `rsi` | Capability CSlot for transfer (u8, or 0xFF for none) / Receive CSlot for incoming cap |
| `rdx` | Timeout in ticks (u64) |
| `r8` | Message Register 0 |
| `r9` | Message Register 1 |
| `r10` | Message Register 2 |
| `r11` | (Clobbered by SYSCALL -- saved by kernel) Message Register 3 on entry, restored on exit |
| `r12` | Capability Register: CSlot of capability to transfer on send, or receive destination on receive |
| `rcx` | (Clobbered by SYSCALL -- contains return RIP, saved by kernel) |

### Kernel Exit (SYSRET)

When the kernel returns to userspace via `SYSRET`:

| Register | Purpose |
|---|---|
| `rax` | Return code: 0 = success, negative = IpcError discriminant |
| `r8` | Message Register 0 (reply data) |
| `r9` | Message Register 1 (reply data) |
| `r10` | Message Register 2 (reply data) |
| `r11` | (Restored to RFLAGS by SYSRET) |
| `r12` | Badge value from the endpoint (identifies the sender's authority) |
| `rcx` | (Restored to RIP by SYSRET) |

### Kernel Entry/Exit Sequence

1. **Entry:** `SYSCALL` transfers control to the kernel entry point. The kernel saves `rcx` (return RIP) and `r11` (RFLAGS) to the kernel stack. The kernel reads all argument registers.
2. **Validation:** The kernel validates the syscall number, endpoint capability, rights, and timeout. Any validation failure returns immediately via `SYSRET` with an error in `rax`.
3. **Fast path:** If the rendezvous partner is already waiting, the kernel copies message registers, performs capability transfer, updates both threads' states, and returns to both threads via `SYSRET`.
4. **Slow path:** If no partner is waiting, the kernel saves the calling thread's full register state, places it on the endpoint queue, and switches to the next runnable thread.
5. **Exit:** On rendezvous completion (or timeout), the kernel restores the thread's register state and executes `SYSRET` to return to userspace.

### Security Considerations

- The kernel must sanitize all registers not used for return values before executing `SYSRET` to prevent information leakage between processes.
- `SYSRET` has known errata on some Intel processors when returning to non-canonical addresses. The kernel must validate the return RIP before executing `SYSRET` and fall back to `IRETQ` if validation fails.
- The kernel entry point must immediately switch to the kernel stack before reading any argument registers, to prevent stack-based attacks from userspace.

---

## 9. Cancellation Semantics

Cancellation defines what happens to pending IPC operations when external events interrupt the normal flow.

### Process Crash

If a process crashes while it has threads blocked in IPC:

1. All threads belonging to the crashed process are removed from all endpoint queues (both sender and receiver).
2. Any CapReply held by the crashed process is revoked. The waiting client receives `IpcError::ServerCrashed`.
3. No partial messages are delivered. The rendezvous either completed before the crash or it did not.
4. Capabilities held by the crashed process are revoked according to the normal revocation rules.

### Timeout

If a timeout fires on a blocked thread:

1. The thread is removed from the endpoint queue.
2. The syscall returns `IpcError::Timeout`.
3. Any CapReply associated with the timed-out call is revoked.
4. The timeout does not affect other threads waiting on the same endpoint.

### Kill

If a thread is killed (via its CapThread holder) while blocked in IPC:

1. The thread is removed from its endpoint queue.
2. Any CapReply held by the killed thread is revoked.
3. The kill is processed as a thread lifecycle event, not as an IPC error.
4. Other threads on the same endpoint are unaffected.

### Authority Loss

If a capability is revoked while a thread is using it for IPC:

1. **Endpoint revoked while sender is waiting:** The sender is unblocked with `IpcError::EndpointRevoked`.
2. **Endpoint revoked while receiver is waiting:** The receiver is unblocked with `IpcError::EndpointRevoked`.
3. **Capability for transfer revoked while in-flight:** The transfer is cancelled. The message may still be delivered (without the capability), or the entire operation may be cancelled depending on whether the rendezvous had already begun.
4. **CapReply revoked while server is processing:** The server can no longer reply. The client receives `IpcError::ReplyRevoked`.

All cancellation paths leave the system in a consistent state with no dangling references, no partial messages, and no stale queue entries (INV-IPC-005).

---

## 10. Deadlock Prevention

Synchronous rendezvous IPC creates a fundamental deadlock risk: if Process A calls Process B, and Process B calls Process A, both block forever (or until timeout). BraiNIX addresses this structurally.

### Acyclic Call Graph Rule

The call graph between processes must be acyclic. If Process A calls Process B, then Process B must not call Process A (directly or transitively). This is enforced through a combination of:

1. **Architectural layering:** The system is designed in layers (devices, drivers, protocol handlers, applications). Each layer only calls the layer below it, never the layer above.
2. **Notification objects for upward signals:** When a lower layer needs to notify a higher layer, it uses a non-blocking notification object instead of a blocking IPC call. Notifications cannot deadlock because they never block the sender.
3. **Runtime cycle detection (optional hardening):** The kernel maintains a wait-for graph of blocked IPC calls. When a new call would create a cycle, the call is rejected with `IpcError::WouldDeadlock`. This is a defense-in-depth mechanism; the architectural layering should prevent cycles from arising in the first place.

### Timeout as Deadlock Breaker

Even if a cycle somehow forms despite the structural rules, mandatory timeouts ensure that at least one participant will eventually time out and break the cycle. The timeout fires with `IpcError::Timeout`, and the timed-out thread can take recovery action.

Timeouts are a safety net, not the primary defense. The primary defense is the acyclic call graph rule.

### CapReply Prevents Recursive Calls

The CapReply mechanism structurally prevents a common deadlock pattern. When a server receives a call, it gets a CapReply. The server must use this CapReply to reply before it can process another call on the same endpoint. If the server tries to call back to the client before replying, the server's thread is blocked on the call, and the client is blocked waiting for the reply. This forms a cycle, which is caught by the runtime cycle detector (if enabled) or eventually broken by timeout.

The recommended pattern is: receive call, process request, reply, then (if needed) send a separate notification to trigger further interaction.

---

## 11. Security Invariants

The IPC subsystem must uphold the following invariants from `docs/security/SECURITY_INVARIANTS.md`:

| Invariant ID | Invariant Name | How the IPC System Upholds It |
|---|---|---|
| INV-IPC-001 | IPC is explicit and kernel-mediated | All IPC goes through kernel endpoints. No ambient namespace messaging. No shared memory bypass. |
| INV-IPC-002 | IPC cannot amplify rights | Capability transfer during IPC validates rights monotonicity. The transferred cap cannot exceed the sender's rights. |
| INV-IPC-003 | Waiting is bounded or explicitly policy-controlled | Mandatory timeout on all blocking operations. No infinite wait. `IpcError::Timeout` returned on expiry. |
| INV-IPC-004 | Reply paths cannot be hijacked | CapReply is single-use, non-copyable, unforgeable, and valid only for the specific call it was created for. |
| INV-IPC-005 | IPC state transitions are race-safe | Rendezvous is atomic. Capability transfer is atomic. Cancellation leaves consistent state. Queue operations are serialized per endpoint. |
| INV-IPC-006 | Performance optimizations must not introduce ambient sharing | No zero-copy. No shared memory. All data flows through kernel register copy. Future optimizations must preserve explicit ownership. |
| INV-AUTH-001 | No ambient authority | IPC requires explicit CapEndpoint capabilities. No process can send or receive without holding the appropriate capability. |
| INV-AUTH-003 | Rights are monotonic under derivation | Capability transfer during IPC preserves rights monotonicity. The receiver gets at most the sender's rights. |
| INV-AUTH-005 | Capabilities cannot be forged from userspace | Capabilities are transferred by CSlot index. The kernel validates the index, checks the slot, and performs the transfer. No raw capability bits cross the user-kernel boundary. |
| INV-AUTH-006 | Reply authority is single-purpose | CapReply is consumed on use. It cannot be stored, copied, or repurposed. |
| INV-SCHED-003 | Timeout processing is deterministic and safe | Timeouts are processed at each scheduler tick in FIFO order. No race between timeout and wakeup. |

### Cross-References

- **Capability types:** CapEndpoint and CapReply are defined in `docs/architecture/CAPABILITY_MODEL.md`, Section 2.
- **Capability transfer semantics:** Rights validation and derivation tree updates follow the rules in `docs/architecture/CAPABILITY_MODEL.md`, Sections 5 and 6.
- **Quota accounting:** Capability transfer during IPC increments the receiver's domain quota, following the rules in `docs/architecture/CAPABILITY_MODEL.md`, Section 9.
