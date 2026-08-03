# BraiNIX Capability Model

## 1. Overview

BraiNIX uses an seL4-inspired capability-based access control model. Every kernel object is accessed exclusively through an unforgeable, typed capability. There is no ambient authority anywhere in the system. No process, thread, or service possesses authority merely by existence, identity, or namespace presence.

A capability is a kernel-managed token that grants its holder permission to perform specific operations on a specific kernel object. Capabilities are:

- **Typed** -- each capability names a specific object type and cannot be reinterpreted as another type (INV-AUTH-002).
- **Rights-bearing** -- each capability carries an explicit bitmask of permitted operations.
- **Unforgeable** -- userspace cannot construct, guess, or coerce a valid capability (INV-AUTH-005).
- **Derivable** -- a holder can create child capabilities with equal or fewer rights, never more (INV-AUTH-003).
- **Revocable** -- a parent capability can revoke all its descendants atomically (INV-AUTH-004).
- **Quota-controlled** -- capability slot allocation is bounded per security domain (INV-SCHED-001).

This model eliminates confused deputy attacks, ambient authority escalation, and the entire class of vulnerabilities that arise from implicit privilege. Authority is always explicit, always typed, always bounded, and always revocable.

---

## 2. Capability Types

Every capability has exactly one type. The type determines which kernel object the capability refers to and which operations are meaningful. The following capability types are defined:

| Type | Purpose | Authorized Operations |
|---|---|---|
| **CapMemory** | Authority over a physical memory region (one or more pages) | Map into address space, unmap, change permissions (within W^X constraint), grant to another process, split into smaller regions |
| **CapEndpoint** | Authority to send to or receive from an IPC endpoint | Send (blocking), receive (blocking), send-with-capability-transfer, receive-with-capability-transfer |
| **CapThread** | Authority over a thread's execution | Suspend, resume, set priority (within domain budget), set CPU affinity, read register state (for debugging), terminate |
| **CapCNode** | Authority over a capability space node (a container of capability slots) | Lookup slot by index, insert capability into slot, delete capability from slot, copy capability between slots, derive new capability in slot |
| **CapIrq** | Authority to bind and handle a specific hardware interrupt line | Bind interrupt to endpoint, unbind interrupt, acknowledge interrupt |
| **CapDevice** | Authority to access a specific hardware device's MMIO region and interrupt set | Map device MMIO range into server address space, access device registers, bind device interrupts |
| **CapUntyped** | Authority over raw untyped memory that can be retyped into kernel objects | Retype into CapMemory, CapEndpoint, CapThread, CapCNode, or other kernel objects. The untyped memory is consumed on retype. |
| **CapReply** | Single-use authority to reply to a specific IPC call | Reply with message registers and optionally transfer a capability. Consumed on use. Cannot be copied, stored, or reused. |
| **CapSpawn** | Authority to create new processes from a compile-time whitelist | Spawn a process of a permitted type with an explicit initial capability set. The whitelist is compiled into the holder. |
| **CapAuditRead** | Authority to read (but not write) the kernel audit log | Read audit entries from the kernel ring buffer. No write authority. No authority to modify or delete entries. |

#### Serving-era types *(planned — P2-T5)*

*(Added 2026-08-02 with the serving pivot. The `CapabilityType` enum currently ends at `Frame = 10`;
these extend it to `Serve=11, Model=12, Gpu=13, Admin=14`. **This document is the only normative home of
those discriminants** — `NORTH_STAR.md` deliberately carries no numeric capability IDs. They are
**specified but not yet implemented** — the change that adds them must extend the proofs in
`src/capability-verify/` in the same commit, not afterward.)*

| Type | Discriminant | Purpose | Authorized Operations |
|---|---|---|---|
| **CapServe** | `11` | Authority over **one client session** on the serving path | Read and write that session's request/response stream; reference that session's KV partition. **Cannot name any other session** — this is the structural basis of `INV-SERVE-001`. Granted per-connection by `servd`, frozen at grant, revoked at teardown. |
| **CapModel** | `12` | Authority to invoke the served model within a session | Submit a confined inference request against the read-only weights view and the caller's own KV slice. Confers **no** authority to spawn, mutate the kernel, reach the network, or read another session (`INV-MODEL-001`). |
| **CapGpu** | `13` | Authority over an accelerator's bounded MMIO and DMA windows | **In scope on the primary platform (AS-5).** Access device registers within the granted window; submit command buffers. **Cannot widen its own DMA window** (`INV-DEV-006`) — this is the control that makes running Apple's opaque, DMA-capable GPU firmware survivable, and it must be proven before that firmware is ever loaded. |
| **CapAdmin** | `14` | Authority over **one admin session** on the same serving transport | Invoke the six frozen administrative verbs below, and nothing else. Granted per-connection by `servd`, decided at accept and frozen there. **Not derivable from `CapServe`, and `CapServe` is not derivable from it** — the two session types are distinguished by capability and by nothing else. |

#### The admin verb set — frozen at six

Administration is a second session *type* on the single authenticated, capability-gated transport, not a
shell (owner decision 2026-08-02; `NORTH_STAR.md` §*Non-goals*). The verbs are compile-time enumerated and
the set is closed:

| Verb | What it may do |
|---|---|
| `enroll-key` | Add a client or admin pre-shared key to the credential store. Refuses the break-glass handle unconditionally. |
| `revoke-key` | Remove one. Refuses the break-glass handle unconditionally. |
| `load-weights` | Activate a weight blob by **measured digest** — never a path and never a byte stream. |
| `read-audit-log` | Bounded, read-only cursor over the serving log. Reading grants no authority. |
| `restart-server` | Relaunch an **enumerated** server identity with its existing frozen manifest. Mints nothing. |
| `reboot` | Tear down the admin session, then reboot. |

**There is no `rotate` verb.** Rotation is `enroll-key` followed by `revoke-key` — two attributable
operations against the credential store, not one primitive that does both.

**No verb may add, remove, or widen a capability.** A verb that could would be a derivation path outside
the rights-monotonicity rule of §5, which is the same thing as ambient authority with a nicer name. The
handler table therefore contains exactly six entries, and `restart-server` relaunches against the
target's *existing* manifest rather than composing a new capability set.

The **break-glass admin pre-shared key authenticates over the serial transport and nowhere else** — the
network listener refuses it outright — so a compromised admin session can neither revoke nor replace it.

Four properties of these types are load-bearing and must survive implementation:

1. **CapServe is per-session, not per-client-class.** One capability, one session. A capability that
   covered "all sessions of this client" would reintroduce exactly the cross-naming path INV-SERVE exists
   to eliminate.
2. **CapModel confers compute, not authority.** The served model is a confined tenant. It receives all
   available compute and reserved memory and **zero** authority — that asymmetry is the entire INV-MODEL
   design, and it is what makes prompt injection a bounded problem rather than an escalation path.
3. **Neither is derivable into something broader.** Rights monotonicity (§5) applies with no exception:
   there is no derivation from CapServe or CapModel that yields authority over another session.
4. **CapAdmin is a separate grant, not a stronger CapServe.** There is no derivation path from CapServe
   to CapAdmin, and none the other way. A session's type is decided at accept and frozen there; nothing
   promotes one into the other. This is what makes "one transport, two capability grants" hold rather
   than merely be asserted.

### Type Safety

Capability types are represented as a Rust enum. The type tag is checked on every capability invocation. Attempting to invoke a CapMemory as if it were a CapEndpoint returns `CapabilityError::TypeMismatch`. There is no raw integer type field that could be confused or reinterpreted.

```rust
#[repr(u8)]
enum CapabilityType {
    Memory = 0,
    Endpoint = 1,
    Thread = 2,
    CNode = 3,
    Irq = 4,
    Device = 5,
    Untyped = 6,
    Reply = 7,
    Spawn = 8,
    AuditRead = 9,
}
```

---

## 3. Capability Structure

A capability is a kernel-only data structure. Userspace never sees the raw bits of a capability. Userspace refers to capabilities by slot index within their CSpace.

### Data Layout

| Field | Type | Size | Description |
|---|---|---|---|
| `capability_type` | `CapabilityType` (enum) | 1 byte | Discriminant identifying the object type. Checked on every invocation. |
| `rights_bitmask` | `u32` | 4 bytes | Bitmask of permitted operations. See Section 5 for the rights model. |
| `object_pointer` | `*const KernelObject` | 8 bytes | Pointer to the kernel object this capability grants access to. Kernel-space only; never exposed to userspace. |
| `generation_counter` | `u64` | 8 bytes | Monotonically increasing counter. Prevents stale references from being reused after an object is destroyed and its storage recycled (INV-OBJ-003). |
| `derivation_parent_index` | `u32` | 4 bytes | Index of the parent capability in the derivation tree. `u32::MAX` for root capabilities that have no parent. |
| `use_count_remaining` | `Option<u32>` | 5 bytes | If `Some(n)`, the capability auto-revokes after `n` invocations. If `None`, no use-count limit. See Section 8. |
| `expiry_tick` | `Option<u64>` | 9 bytes | If `Some(t)`, the capability auto-revokes after kernel tick `t`. If `None`, no time-based expiry. See Section 8. |

**Total size:** 39 bytes (padded to 40 bytes for alignment).

### Null Capability Sentinel

A null capability is defined as all fields zeroed: `capability_type = 0`, `rights_bitmask = 0`, `object_pointer = null`, `generation_counter = 0`, `derivation_parent_index = u32::MAX`, `use_count_remaining = None`, `expiry_tick = None`.

The null capability is the initial value of every slot in a new CSpace. Invoking a null capability returns `CapabilityError::NullCapability`. Reading a slot that contains a null capability returns the null sentinel, never stale data from a prior occupant.

---

## 4. CSpace Layout

Each process has a CSpace (capability space): a flat array of capability slots. The CSpace is the process's entire view of system authority.

### Structure

```rust
const MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS: usize = 256;

struct CapabilitySpace {
    slots: [CapabilitySlot; MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS],
    derivation_tree: CapabilityDerivationTree,
}
```

### Slot Addressing

Slots are addressed by a `u8` index (0 through 255). This fixed-size addressing eliminates bounds-check complexity and ensures constant-time slot lookup regardless of the number of capabilities a process holds.

### Rationale for 256 Slots

- **256 is sufficient** for a microkernel's minimal-capability design. A typical BraiNIX process needs: a few memory capabilities, an IPC endpoint or two, its thread capability, and perhaps a device or audit capability. Even the most capability-rich process (such as `spawnd`) needs far fewer than 256.
- **256 fits in a `u8` index**, which eliminates integer overflow and bounds-check concerns entirely. The index type itself guarantees it is always in range.
- **256 slots per process** with a 40-byte capability structure means each CSpace consumes approximately 10 KiB of kernel memory. This is small enough for fixed-size allocation and large enough for any anticipated workload.
- **Fixed size eliminates dynamic allocation** in the CSpace path, which means no allocation failure, no fragmentation, and no unbounded growth.

### Slot States

Each slot is in exactly one of two states:

1. **Valid** -- the slot contains a capability with a non-null type, valid rights, a valid object pointer, and a current generation counter.
2. **Null** -- the slot contains the null capability sentinel. This is the initial state and the state after deletion or revocation.

There is no "reserved," "pending," or "partially initialized" state. A slot is either valid or null. This two-state model eliminates an entire class of lifecycle bugs.

---

## 5. Rights Model

Each capability carries a rights bitmask that specifies which operations the holder may perform. Rights are defined as bit flags:

```rust
bitflags! {
    struct CapabilityRights: u32 {
        const READ        = 0b0001;
        const WRITE       = 0b0010;
        const GRANT       = 0b0100;
        const GRANT_REPLY = 0b1000;
    }
}
```

| Right | Meaning |
|---|---|
| **Read** | Permission to read the object's state (e.g., read memory, receive from endpoint, read audit entries) |
| **Write** | Permission to modify the object's state (e.g., write memory, send to endpoint, modify thread state) |
| **Grant** | Permission to derive a child capability and transfer it to another process via IPC |
| **GrantReply** | Permission to create a single-use CapReply capability during IPC receive |

### Rights Monotonicity Invariant

**A derived capability can never have rights not present in its parent.** This is the rights monotonicity invariant (INV-AUTH-003).

Formally: for any derivation operation `derive(parent, child_rights)`, the result satisfies `child_rights & !parent.rights_bitmask == 0`. If the caller requests rights not present in the parent, the derivation fails with `CapabilityError::RightsExceedParent`.

This invariant is enforced at derivation time, at copy time, and at transfer time. It is a candidate for formal verification via Kani model checking.

### Rights Interpretation Per Type

The meaning of Read/Write/Grant/GrantReply varies by capability type:

| Type | Read | Write | Grant | GrantReply |
|---|---|---|---|---|
| CapMemory | Map as readable | Map as writable (never with execute; W^X) | Transfer via IPC | Not applicable |
| CapEndpoint | Receive messages | Send messages | Transfer endpoint cap via IPC | Create CapReply on receive |
| CapThread | Read register state | Modify thread (suspend, resume, set priority) | Transfer thread cap via IPC | Not applicable |
| CapCNode | Lookup and read slots | Insert, delete, copy slots | Transfer CNode cap via IPC | Not applicable |
| CapIrq | Query interrupt status | Bind/unbind interrupt | Transfer IRQ cap via IPC | Not applicable |
| CapDevice | Read device registers | Write device registers | Transfer device cap via IPC | Not applicable |
| CapUntyped | Query remaining size | Retype into objects | Transfer untyped cap via IPC | Not applicable |
| CapReply | Not applicable | Reply to caller | Not applicable (single-use) | Not applicable |
| CapSpawn | Query whitelist | Spawn process | Transfer spawn cap via IPC | Not applicable |
| CapAuditRead | Read audit entries | Not applicable (read-only) | Transfer audit cap via IPC | Not applicable |

---

## 6. Derivation Tree (MDB)

The Mapping Database (MDB) is a tree structure that tracks parent-child relationships between capabilities. Every derived capability has exactly one parent. Every root capability has no parent.

### Structure

The derivation tree is stored as an array of derivation records, one per CSpace slot:

```rust
struct DerivationRecord {
    parent_index: u32,
    first_child_index: u32,
    next_sibling_index: u32,
}
```

- `parent_index`: the slot index of the parent capability, or `u32::MAX` for root capabilities.
- `first_child_index`: the slot index of the first child in the derivation chain, or `u32::MAX` if no children.
- `next_sibling_index`: the slot index of the next sibling (child of the same parent), or `u32::MAX` if no more siblings.

This linked structure allows the tree to be walked efficiently for revocation without allocating additional memory.

### Derivation Rules

1. A capability can only be derived from a valid (non-null) parent capability.
2. The child's rights must be a subset of the parent's rights (rights monotonicity, INV-AUTH-003).
3. The child's capability type must match the parent's capability type. Cross-type derivation is prohibited.
4. The child's generation counter is copied from the parent. If the underlying object is recycled, both parent and child become stale.
5. Derivation consumes one CSpace slot. If the target slot is not null, the derivation fails with `CapabilityError::SlotOccupied`.

### Instant Revocation via Tree Walk

Revoking a parent capability triggers a depth-first walk of all descendants. Each descendant is zeroed using `core::ptr::write_volatile` (see Section 7). The walk visits every descendant exactly once via the linked `first_child_index` / `next_sibling_index` structure.

The walk is bounded: the maximum depth is `MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS` (256), which means revocation completes in bounded time with no dynamic allocation.

---

## 7. Revocation Semantics

Revocation is the mechanism by which authority is withdrawn. When a capability is revoked, all of its descendants in the derivation tree are also revoked, atomically and completely.

### Atomic Revocation

Parent revocation revokes all children. There is no partial revocation. After revocation completes:

1. The parent slot contains the null capability sentinel.
2. Every descendant slot contains the null capability sentinel.
3. No descendant capability is usable for any operation.
4. The derivation tree records for all affected slots are reset.

### Slot Zeroing via write_volatile

Capability slot zeroing uses `core::ptr::write_volatile` to write the null capability sentinel to the slot. This prevents the Rust compiler from eliding the write as a dead store optimization.

This upholds:
- **INV-AUTH-004** (revocation is final within defined scope) -- a revoked capability cannot be recovered from the slot.
- **INV-OBJ-002** (object reuse cannot preserve stale authority) -- the slot contains the null sentinel, not remnants of the prior capability.
- **INV-MEM-006** (freed memory is sanitized before reuse) -- the slot is sanitized immediately on revocation, not deferred.

```rust
/// Zeroes a capability slot on revocation.
///
/// Enforces invariant INV-AUTH-004: a revoked capability slot must not be
/// readable with its prior contents. Uses write_volatile to prevent the
/// compiler from eliding the write as a dead store.
///
/// SAFETY: slot_pointer must be non-null, properly aligned, and exclusively
/// owned by the kernel. The caller must hold the CSpace lock.
unsafe fn zero_capability_slot(slot_pointer: *mut CapabilitySlot) {
    core::ptr::write_volatile(slot_pointer, CapabilitySlot::null());
}
```

### Generation Counter Check

Even if a slot is reallocated after revocation, the generation counter prevents stale references from being valid. When a kernel object is destroyed and its storage is recycled for a new object, the new object receives a new generation counter. Any capability referencing the old generation counter is invalid (INV-OBJ-003).

---

## 8. Temporal Capabilities

Temporal capabilities extend the base capability model with automatic expiry. A capability can be configured to expire based on invocation count, elapsed time, or both.

### Use-Count Expiry

A capability with `use_count_remaining = Some(n)` is automatically revoked after `n` successful invocations.

- Each successful invocation decrements the counter: `n = n - 1`.
- When `n` reaches zero, the next invocation attempt returns `CapabilityError::CapabilityExpired`.
- The capability is then revoked (slot zeroed via `write_volatile`, descendants revoked).
- The decrement and check are performed atomically with respect to the capability invocation.

**Example:** A capability with `use_count_remaining = Some(3)` permits exactly 3 invocations. The 4th attempt returns `CapabilityExpired`.

### Time-Window Expiry

A capability with `expiry_tick = Some(t)` is automatically revoked after kernel tick `t`.

- The kernel maintains a monotonic tick counter that increments on every timer interrupt.
- On every capability invocation, the kernel checks `current_tick >= expiry_tick`.
- If expired, the invocation returns `CapabilityError::CapabilityExpired` and the capability is revoked.
- Expiry check is performed before the invocation is executed, ensuring no expired capability is ever used.

### Combined Expiry

Both `use_count_remaining` and `expiry_tick` may be set simultaneously. The capability expires on whichever condition is reached first.

### Derivation of Temporal Capabilities

When deriving from a temporal capability:

- The child's `use_count_remaining` must be less than or equal to the parent's remaining count (if the parent has one).
- The child's `expiry_tick` must be less than or equal to the parent's expiry tick (if the parent has one).
- A child cannot add temporal constraints that the parent does not have. If the parent has `use_count_remaining = None`, the child may set any use count. If the parent has `use_count_remaining = Some(5)`, the child may set at most `Some(5)`.

This preserves rights monotonicity: the child can never outlive or outuse the parent.

---

## 9. Quota Control

Every security domain (process or group of processes under a single administrative authority) has a capability slot budget that bounds the total number of capability slots it may occupy.

### Per-Domain Budget

```rust
struct DomainQuota {
    maximum_capability_slots: u32,
    current_capability_slots: u32,
}
```

- `maximum_capability_slots` is set at domain creation and can only be decreased, never increased without explicit authority.
- `current_capability_slots` tracks the number of non-null slots currently in use across all CSpaces in the domain.

### Exhaustion Behavior

When a domain attempts to create, derive, copy, or receive a capability and `current_capability_slots >= maximum_capability_slots`:

- The operation fails with `CapabilityError::QuotaExhausted`.
- The kernel does not panic, does not silently drop the capability, and does not borrow from another domain's quota.
- The caller receives the error and must decide whether to revoke existing capabilities to free slots.

This upholds INV-SCHED-001 (one domain cannot silently consume another domain's budget) and INV-SCHED-004 (exhaustion is explicit, never silent).

### Quota Accounting

Quota changes occur at these points:

| Operation | Effect on current_capability_slots |
|---|---|
| Mint (create from untyped) | +1 |
| Copy | +1 |
| Derive | +1 |
| Receive via IPC | +1 |
| Delete | -1 |
| Revoke (per descendant) | -1 per revoked slot |
| Expiry (temporal) | -1 |

All quota changes are atomic with respect to the operation that triggers them.

---

## 10. Security Invariants

The capability model must uphold the following invariants from `docs/security/SECURITY_INVARIANTS.md`:

| Invariant ID | Invariant Name | How the Capability Model Upholds It |
|---|---|---|
| INV-AUTH-001 | No ambient authority | Every operation requires an explicit capability. No process has authority by identity. |
| INV-AUTH-002 | Authority is explicit and typed | Each capability has an enum type tag checked on every invocation. Type confusion returns `CapabilityError::TypeMismatch`. |
| INV-AUTH-003 | Rights are monotonic under derivation | Derivation enforces `child_rights & !parent.rights == 0`. Amplification is structurally impossible. |
| INV-AUTH-004 | Revocation is final within defined scope | Revocation walks the full derivation tree and zeros every descendant via `write_volatile`. |
| INV-AUTH-005 | Capabilities cannot be forged from userspace | Userspace refers to capabilities by slot index only. The kernel validates the index, checks the slot state, and checks the generation counter. No raw capability bits are ever exposed to userspace. |
| INV-AUTH-006 | Reply authority is single-purpose | CapReply is single-use, non-copyable, and consumed on use. It cannot become general communication authority. |
| INV-AUTH-007 | Process creation cannot mint ambient privilege | CapSpawn requires an explicit whitelist and an explicit initial capability set. No hidden inheritance. |
| INV-AUTH-008 | Cross-domain authority flow is auditable | Capability transfer via IPC is a distinct kernel-mediated operation logged to the audit ring buffer. |
| INV-OBJ-001 | Every kernel object has a defined lifecycle | Capabilities track object lifecycle via generation counters. Stale references are detected. |
| INV-OBJ-002 | Object reuse cannot preserve stale authority | Slot zeroing via `write_volatile` and generation counter checks prevent stale authority from surviving. |
| INV-OBJ-003 | Object identity cannot be confused across generations | Generation counters ensure a capability from one lifecycle cannot target a later object in the same storage. |

---

## 11. API Contracts

The capability system is accessed through the following syscall interface. All syscalls use the BraiNIX custom ABI (no POSIX compatibility). Arguments and return values are passed in registers.

### mint

Create a new capability from untyped memory.

```
Syscall: SYS_CAP_MINT
Arguments:
    source_slot: u8       -- CSlot containing a CapUntyped with Write right
    target_slot: u8       -- CSlot to place the new capability (must be null)
    object_type: u8       -- CapabilityType enum discriminant
    rights: u32           -- Initial rights bitmask
Returns:
    Ok(())                -- Capability created in target_slot
    Err(CapabilityError)  -- NullCapability, TypeMismatch, RightsExceedParent,
                             SlotOccupied, QuotaExhausted, InvalidObjectType
```

### copy

Duplicate a capability with equal or fewer rights.

```
Syscall: SYS_CAP_COPY
Arguments:
    source_slot: u8       -- CSlot containing the capability to copy
    target_slot: u8       -- CSlot to place the copy (must be null)
    rights: u32           -- Rights for the copy (must be subset of source rights)
Returns:
    Ok(())                -- Copy created in target_slot
    Err(CapabilityError)  -- NullCapability, SlotOccupied, RightsExceedParent,
                             QuotaExhausted
```

### delete

Remove a capability from a slot.

```
Syscall: SYS_CAP_DELETE
Arguments:
    target_slot: u8       -- CSlot to delete
Returns:
    Ok(())                -- Slot is now null
    Err(CapabilityError)  -- NullCapability (slot was already null)
```

Delete zeroes the slot via `write_volatile` but does not revoke children. Use revoke for cascade deletion.

### revoke

Remove a capability and all its descendants from the derivation tree.

```
Syscall: SYS_CAP_REVOKE
Arguments:
    target_slot: u8       -- CSlot containing the capability to revoke
Returns:
    Ok(u32)               -- Number of capabilities revoked (including the target)
    Err(CapabilityError)  -- NullCapability (slot was already null)
```

Revoke walks the derivation tree depth-first, zeroing every descendant via `write_volatile`, then zeroes the target slot itself. The return value indicates how many slots were freed, which allows the caller to update their mental model of quota usage.

### derive

Create a child capability with a subset of the parent's rights.

```
Syscall: SYS_CAP_DERIVE
Arguments:
    parent_slot: u8       -- CSlot containing the parent capability
    child_slot: u8        -- CSlot to place the child (must be null)
    rights: u32           -- Rights for the child (must be subset of parent rights)
    use_count: Option<u32> -- Optional use-count limit for temporal capability
    expiry_tick: Option<u64> -- Optional tick-based expiry for temporal capability
Returns:
    Ok(())                -- Child capability created in child_slot
    Err(CapabilityError)  -- NullCapability, SlotOccupied, RightsExceedParent,
                             QuotaExhausted, TemporalExceedsParent
```

The derive operation is the primary mechanism for authority delegation. A process that holds a capability with Grant rights can derive a child capability and transfer it to another process via IPC.

### Error Types

```rust
enum CapabilityError {
    NullCapability,
    TypeMismatch,
    RightsExceedParent,
    SlotOccupied,
    QuotaExhausted,
    InvalidObjectType,
    CapabilityExpired,
    TemporalExceedsParent,
    GenerationMismatch,
    WriteRightNotGranted,
    ReadRightNotGranted,
    GrantRightNotGranted,
}
```

Every error is explicit. No operation silently succeeds, silently fails, or panics. The kernel returns a typed error and the caller decides how to proceed. This upholds INV-SCHED-004 (exhaustion is explicit, never silent) and INV-FAIL-001 (failure modes are defined).
