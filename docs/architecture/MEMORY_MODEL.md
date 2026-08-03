# BraiNIX Memory Model

## 1. Overview

BraiNIX uses a typed physical memory model with per-process page tables. The kernel has no dynamic heap. All kernel objects are allocated from fixed-size pool allocators that are pre-allocated at boot time.

The memory model is designed around three core principles:

1. **Every page has exactly one type at any time.** There is no ambiguous ownership, no shared-state page, and no page that exists in two categories simultaneously.
2. **The kernel is not mapped in user page tables.** Kernel Page Table Isolation (KPTI) ensures that userspace cannot address kernel memory, even speculatively.
3. **No page is simultaneously writable and executable.** W^X is enforced globally with no exceptions.
4. **Page size is a platform parameter, never a constant.** *(Added 2026-08-02.)* Apple Silicon — the primary platform — uses **16 KiB** base pages; x86-64 uses 4 KiB. Every size, alignment, and bound in this document is expressed in **pages**, and any byte-valued constant derives from the HAL's page size. See §12.

These four properties -- typed ownership, KPTI, W^X, and page-size parametricity -- form the foundation of BraiNIX's memory security. They are structural guarantees, not optional hardening flags.

> **Reconciled 2026-08-02.** Sections 12 and 13 were added for the Apple-primary platform decision and the
> serving pivot. Byte-valued constants elsewhere in this document (`4096`, "one page") are **x86-64
> illustrations**, not portable values — read them as "one page" and see §12.

---

## 2. Page Types

Every physical page frame in the system is tagged with exactly one type at any given time. The type determines who owns the page, what it may be used for, and what operations are permitted on it.

```rust
#[repr(u8)]
enum PageType {
    Kernel = 0,
    UserOwned = 1,
    Free = 2,
    DeviceMapped = 3,
    IpcBuffer = 4,
}
```

| Page Type | Owner | Permitted Use | Notes |
|---|---|---|---|
| **Kernel** | The kernel | Kernel code, kernel data, kernel stacks, kernel object pools | Never mapped in user page tables. Never returned by the user allocator. |
| **UserOwned** | A specific process | User code, user data, user stacks, user heap | Mapped only in the owning process's user page table. Subject to W^X. |
| **Free** | No one | Available for allocation | Zeroed before allocation to any new owner. Not mapped in any page table. |
| **DeviceMapped** | A specific device server process | Memory-mapped I/O regions for hardware device access | Mapped only in the owning device server's address space. Not cacheable. Requires CapDevice authority. |
| **IpcBuffer** | A specific process (lender) | Shared buffer for large IPC data transfers (future extension) | Mapped in the lender's address space with specific rights. Revocable. Subject to capability governance per INV-IPC-006. |

### Type Transition Rules

Page type transitions are controlled and auditable. Not all transitions are permitted:

| From | To | Permitted? | Condition |
|---|---|---|---|
| Free | Kernel | Yes | Boot-time allocation only |
| Free | UserOwned | Yes | Allocation via CapMemory mint from CapUntyped |
| Free | DeviceMapped | Yes | Device server initialization via CapDevice |
| UserOwned | Free | Yes | Process termination or explicit page return. Page is zeroed before becoming Free. |
| DeviceMapped | Free | Yes | Device server termination. Page is zeroed before becoming Free. |
| Kernel | Free | No | Kernel pages are never freed. They are allocated at boot and retained for the lifetime of the system. |
| UserOwned | Kernel | No | User pages cannot become kernel pages. |
| Any | IpcBuffer | Yes | Temporary transition for capability-governed buffer lending. Reverts on revocation. |

Every type transition is logged to the audit ring buffer as a security-relevant event (INV-AUD-001).

---

## 3. Physical Allocator

The physical allocator manages free page frames and dispenses them as typed pages. It is pool-based with no dynamic heap.

### Design

```rust
struct PhysicalAllocator {
    free_page_stack: BoundedStack<PhysicalAddress>,
    page_type_table: [PageType; TOTAL_PHYSICAL_PAGES],
    page_owner_table: [ProcessIdentifier; TOTAL_PHYSICAL_PAGES],
}
```

- `free_page_stack`: A stack (LIFO) of free physical page addresses. Bounded at boot by the total number of physical pages.
- `page_type_table`: An array that tracks the type of every physical page frame. Indexed by physical page frame number.
- `page_owner_table`: An array that tracks the owning process of every physical page frame. Meaningful only for UserOwned and DeviceMapped pages.

### Allocation Protocol

1. The caller requests a page of a specific type (UserOwned, DeviceMapped).
2. The allocator pops a physical address from the free page stack.
3. If the stack is empty, the allocator returns `AllocationError::OutOfMemory`. No panic, no retry, no fallback (INV-SCHED-004).
4. The allocator zeroes the page (see Section 6).
5. The allocator sets the page type in the page_type_table.
6. The allocator sets the page owner in the page_owner_table.
7. The allocator returns a typed page handle, not a raw address.

### Deallocation Protocol

1. The caller returns a page for deallocation.
2. The allocator verifies the caller is the page owner.
3. The allocator zeroes the page.
4. The allocator resets the page type to Free and the owner to None.
5. The allocator pushes the physical address back onto the free page stack.

### No Raw Addresses

The allocator never returns raw physical addresses to callers. It returns typed page handles that encode the page type and owner. This prevents callers from bypassing the type system by casting addresses.

---

## 4. KPTI (Kernel Page Table Isolation)

BraiNIX implements Kernel Page Table Isolation: the kernel is not mapped in user page tables. Each process has a separate user page table that contains only user mappings. The kernel has its own page table that contains both kernel and (temporarily, during syscalls) user mappings.

### Page Table Structure

Each process has two page table hierarchies:

1. **User page table:** Contains only UserOwned and DeviceMapped (for device servers) page mappings. No kernel pages are present. This page table is active when the process is running in user mode (Ring 3).
2. **Kernel page table:** Contains all kernel pages plus the ability to temporarily access user pages (via SMAP-controlled access) during syscalls. This page table is active when the kernel is running in kernel mode (Ring 0) on behalf of this process.

### CR3 Handling

The CR3 register holds the physical address of the active PML4 (Page Map Level 4) table. On every transition between user mode and kernel mode, the kernel swaps CR3:

1. **User-to-kernel transition (syscall, interrupt, exception):** The kernel entry point immediately writes the kernel page table address to CR3. This is the first instruction executed after the privilege level change.
2. **Kernel-to-user transition (sysret, iret):** The kernel exit path writes the user page table address to CR3 as the last operation before returning to user mode.

```rust
/// Loads the kernel page table into CR3.
///
/// Enforces invariant INV-MEM-001: userspace cannot read arbitrary kernel memory.
/// The kernel page table is loaded immediately on kernel entry, before any kernel
/// data is accessed, to prevent speculative access to kernel memory from user mode.
///
/// SAFETY: kernel_page_table_physical_address must be a valid, aligned PML4 address.
unsafe fn load_kernel_page_table(kernel_page_table_physical_address: PhysicalAddress) {
    core::arch::asm!("mov cr3, {}", in(reg) kernel_page_table_physical_address.as_u64());
}
```

### TLB Invalidation

Switching CR3 implicitly flushes the TLB. This ensures that stale user-mode translations do not persist when the kernel is executing, and stale kernel-mode translations do not persist when user code is executing.

For targeted invalidation (e.g., when a single page mapping changes), the kernel uses `INVLPG` for the specific virtual address. Global kernel mappings use the PCID (Process Context Identifier) mechanism if available, to avoid unnecessary TLB flushes on context switches between processes (INV-X86-006).

### Security Properties

KPTI provides:

- **INV-MEM-001:** Userspace cannot read arbitrary kernel memory, because kernel pages are not present in the user page table.
- **INV-MEM-002:** Userspace cannot write arbitrary kernel memory, because no kernel page is mapped writable in the user page table.
- **Spectre mitigation:** Even speculative execution in user mode cannot access kernel pages, because the translations do not exist in the user page table.

---

## 5. W^X Enforcement

No page in the system is simultaneously writable and executable. This invariant (INV-MEM-003) is enforced at the page table entry level with no exceptions.

### Enforcement Mechanism

Every page table entry has two relevant bits:

- **Writable (W):** If set, the page can be written to.
- **No Execute (NX):** If set, the page cannot be executed. (The NX bit is in position 63 of the page table entry.)

W^X is enforced by ensuring that for every page table entry, the following is true:

```
NOT (Writable AND NOT NoExecute)
```

Equivalently: if a page is writable, its NX bit must be set. If a page is executable, it must not be writable.

### Page Mapping Rules

| Page Content | Readable | Writable | Executable | NX Bit |
|---|---|---|---|---|
| Code (kernel .text) | Yes | No | Yes | Clear |
| Read-only data (kernel .rodata) | Yes | No | No | Set |
| Mutable data (kernel stacks, pools) | Yes | Yes | No | Set |
| User code | Yes | No | Yes | Clear |
| User data / heap / stack | Yes | Yes | No | Set |
| Device MMIO | Yes | Yes | No | Set |
| Guard pages | No | No | No | Set (not present) |

### No Exceptions

There are no exceptions to W^X:

- No JIT compilation (BraiNIX does not support runtime code generation).
- No trampolines that require writable+executable memory.
- No debugging features that temporarily make code pages writable.
- No loader that maps code as writable during loading and then makes it read-only. Code pages are mapped read-only+executable from the start; the loading process writes to a separate staging area and then maps the final pages as read-only+executable.

### Enforcement in the Mapping API

The page table mapping function rejects any attempt to create a writable+executable mapping:

```rust
fn validate_page_table_flags_enforce_write_xor_execute(
    flags: PageTableFlags,
) -> Result<(), MappingError> {
    let is_writable = flags.contains(PageTableFlags::WRITABLE);
    let is_executable = !flags.contains(PageTableFlags::NO_EXECUTE);
    if is_writable && is_executable {
        return Err(MappingError::WritableAndExecutableViolation);
    }
    Ok(())
}
```

This validation is called on every `map_page` operation. It is a hard error, not a warning. A caller that requests a writable+executable mapping receives `MappingError::WritableAndExecutableViolation` and the mapping is not created.

---

## 6. Page Zeroing

Every page is zeroed before it is granted to a new owner or reused after being freed. This prevents information leakage between processes (INV-MEM-006).

### Mandatory Zeroing Points

1. **Allocation:** When a page transitions from Free to UserOwned or DeviceMapped, it is zeroed before the new owner receives it.
2. **Deallocation:** When a page transitions from UserOwned or DeviceMapped to Free, it is zeroed before being pushed onto the free page stack.
3. **Capability slot zeroing:** When a capability slot is revoked, it is zeroed via `core::ptr::write_volatile` (per the capability model in `docs/architecture/CAPABILITY_MODEL.md`, Section 7).

### Zeroing Implementation

Page zeroing uses `core::ptr::write_bytes` to write zero to every byte of the page:

```rust
/// Zeroes a physical page before granting it to a new owner.
///
/// Enforces invariant INV-MEM-006: freed memory is sanitized before reuse.
/// Uses write_bytes to ensure the entire page is overwritten, preventing
/// information leakage from the previous owner.
///
/// SAFETY: page_virtual_address must be a valid, aligned, kernel-mapped address
/// for a page that is exclusively owned by the kernel (in transition).
unsafe fn zero_physical_page(page_virtual_address: *mut u8) {
    core::ptr::write_bytes(page_virtual_address, 0u8, PAGE_SIZE_IN_BYTES);
}
```

### No Deferred Zeroing

Zeroing is not deferred, batched, or performed lazily. Every page is zeroed synchronously at the point of transition. This eliminates the window where stale data could be observed.

### No Compiler Elision

For capability slot zeroing, `write_volatile` is used to prevent the compiler from optimizing away the zero-write. For page zeroing, `write_bytes` is sufficient because the zeroed page will be subsequently read by the new owner (preventing dead-store elimination).

---

## 7. Page Deduplication Prohibition

Page deduplication is explicitly forbidden in BraiNIX. No mechanism exists to detect identical page contents and merge them into a shared mapping.

### Rationale

Page deduplication creates a side channel: by observing whether a write to a page triggers a copy-on-write fault (and measuring the timing of that fault), an attacker can determine whether another process has a page with identical contents. This has been demonstrated in real-world attacks against Linux KSM (Kernel Same-page Merging).

### Policy

1. **No kernel-side deduplication.** The kernel does not scan pages for identical contents.
2. **No copy-on-write sharing.** When a process forks or when memory is duplicated, a full copy is made immediately. There is no shared mapping with deferred copy.
3. **No userspace-initiated deduplication.** No syscall or capability operation allows a process to request that two pages be merged.

This eliminates an entire class of side-channel attacks at the cost of higher memory usage. For a security-first microkernel, this is the correct trade-off.

---

## 8. Heap Isolation

Each kernel object type is allocated from a dedicated memory region. A bug in one object type's allocator cannot corrupt another type's pool.

### Isolated Pools

The kernel maintains separate memory pools for each kernel object type:

| Pool | Object Type | Object Size | Purpose |
|---|---|---|---|
| Thread Pool | Thread control blocks | Fixed size per thread | All thread metadata and register save areas |
| Endpoint Pool | IPC endpoint objects | Fixed size per endpoint | All endpoint state including sender/receiver queues |
| CNode Pool | Capability space nodes | Fixed size per CNode | All capability slots and derivation tree records |
| Page Table Pool | Page table pages | 4096 bytes (one page) | PML4, PDPT, PD, and PT pages |
| Notification Pool | Notification objects | Fixed size per notification | All notification signal words |

### Isolation Mechanism

Each pool is allocated from a contiguous region of physical memory that is determined at boot time. The regions do not overlap. A buffer overflow in the Thread Pool cannot reach the Endpoint Pool because they are in different physical memory ranges.

```rust
struct KernelObjectPool<T> {
    base_address: PhysicalAddress,
    pool_size_in_objects: usize,
    allocation_bitmap: [u64; BITMAP_WORDS],
    _phantom: core::marker::PhantomData<T>,
}
```

### No Cross-Pool Allocation

An allocation request for a thread control block always goes to the Thread Pool. An allocation request for an endpoint always goes to the Endpoint Pool. There is no fallback to a general-purpose allocator if a specific pool is exhausted. Exhaustion returns `AllocationError::PoolExhausted`, and the caller handles the error explicitly (INV-SCHED-004).

### Benefits

1. **Type confusion prevention:** An object of one type cannot be reinterpreted as another type through allocator bugs, because they are in physically separate memory.
2. **Blast radius containment:** A heap overflow in one pool corrupts only objects of the same type.
3. **Predictable allocation behavior:** Fixed-size pools have O(1) allocation and deallocation via bitmap scanning.
4. **No fragmentation:** All objects in a pool are the same size, so there is no external fragmentation.

---

## 9. Stack Guard Pages

Both kernel stacks and user stacks have unmapped guard pages below the stack base. A stack overflow causes an immediate page fault rather than silent memory corruption.

### Kernel Stack Guard Pages

Each kernel thread has a dedicated kernel stack. Below each kernel stack is an unmapped guard page (4096 bytes, with the Present bit cleared in the page table entry).

If a kernel stack overflow occurs:

1. The stack pointer descends into the guard page region.
2. The hardware generates a page fault because the guard page is not present.
3. The page fault handler runs on the IST (Interrupt Stack Table) stack, not on the overflowed stack.
4. The fault handler logs the overflow to the serial console and halts the system (a kernel stack overflow is a fatal condition because kernel state may be corrupted).

### User Stack Guard Pages

Each user thread has a stack with an unmapped guard page below the stack base.

If a user stack overflow occurs:

1. The stack pointer descends into the guard page region.
2. The hardware generates a page fault.
3. The kernel's page fault handler identifies the fault as a user stack overflow (the faulting address is in the guard page region for the thread's stack).
4. The kernel terminates the thread with a stack overflow signal. Other threads and processes are unaffected.

### Guard Page Invariant

The guard page invariant (INV-MEM-007) states: stack exhaustion or overrun must fault, not corrupt silently. This is enforced by:

1. Every stack allocation includes a guard page below the stack base.
2. Guard pages are never mapped. They have the Present bit cleared.
3. No mechanism exists to remove or map over a guard page.
4. The IST mechanism ensures the kernel can handle page faults even when the kernel stack is exhausted.

### Double Fault Handling

If a page fault occurs while the kernel is already handling a page fault (e.g., the page fault handler itself overflows its stack), a double fault is generated. The double fault handler runs on a dedicated IST stack that is separate from all thread stacks. This ensures the system can still log the error and halt cleanly, rather than triple-faulting and silently rebooting (INV-X86-005).

---

## 10. Virtual Address Layout

This layout is locked per Phase 2 CONTEXT.md D-10/D-11. No phase may allocate VA regions outside this map without updating this document.

| Region | Start Address | End Address | Size | Purpose |
|---|---|---|---|---|
| User space | `0x0000_0000_0000_0000` | `0x0000_7FFF_FFFF_FFFF` | 128 TB | Canonical lower half for user processes |
| Non-canonical gap | `0x0000_8000_0000_0000` | `0xFFFF_7FFF_FFFF_FFFF` | (hardware) | Hardware-enforced unmapped hole |
| Kernel stack region | `0xFFFF_8000_0000_0000` | `0xFFFF_8000_FFFF_FFFF` | 4 GB | Per-thread kernel stacks with guard pages |
| Pool region | `0xFFFF_8001_0000_0000` | `0xFFFF_8001_FFFF_FFFF` | 4 GB | Fixed-size pool allocators (512 MB per object type) |
| Direct map | `0xFFFF_8800_0000_0000` | `0xFFFF_8800_FFFF_FFFF` | 4 GB | Physical-to-virtual 1:1 mapping |
| Kernel binary | `0xFFFF_FFFF_8010_0000` | — | Fixed | Kernel code and data (matches linker.ld) |

### Constants

The canonical constants for this layout are defined in `src/kernel/src/memory/virtual_address_layout.rs` and must be used by all kernel code referencing these addresses.

---

## 11. Fixed-Size Pool Allocators

The kernel uses fixed-size pool allocators for all kernel objects. There is no general-purpose dynamic kernel heap. No `malloc`, no `alloc::vec`, no unbounded growth.

### Boot-Time Allocation

At boot, the kernel divides physical memory into regions:

1. **Kernel code and data:** Fixed at link time. Made read-only after initialization (INV-MEM-004).
2. **Kernel object pools:** Pre-allocated from the physical allocator. Each pool is sized based on system configuration constants determined at compile time.
3. **User memory:** All remaining physical memory is available for user-process allocation via the capability system (CapMemory and CapUntyped).

### Pool Sizing Strategy

Pool sizes are determined by compile-time constants:

```rust
const MAXIMUM_THREADS: usize = 128;
const MAXIMUM_ENDPOINTS: usize = 256;
const MAXIMUM_CNODES: usize = 64;
const MAXIMUM_PAGE_TABLE_PAGES: usize = 4096;
const MAXIMUM_NOTIFICATIONS: usize = 128;
```

These constants define the maximum number of each object type that the kernel can allocate. They are deliberately conservative: the system is designed for a small number of tightly controlled processes, not for thousands of generic workloads.

### Allocation and Deallocation

Each pool uses a bitmap allocator:

1. **Allocate:** Scan the bitmap for the first clear bit. Set it. Return a pointer to the corresponding object slot. If no clear bit exists, return `AllocationError::PoolExhausted`.
2. **Deallocate:** Clear the bit corresponding to the object. Zero the object's memory before clearing the bit (INV-MEM-006, INV-OBJ-002).

Both operations are O(n) in the worst case where n is the number of bitmap words, but in practice are fast due to the small pool sizes and hardware bit-scan instructions (`BSF`/`TZCNT`).

### No Unbounded Growth

The total kernel memory footprint is fixed at boot. The kernel cannot allocate more memory during operation. If a pool is exhausted, the operation fails with an explicit error. This guarantees:

- **No kernel memory exhaustion by userspace:** A malicious userspace process cannot exhaust kernel memory by creating objects, because the pools are bounded and quota-controlled.
- **No fragmentation:** Fixed-size objects in fixed-size pools cannot fragment.
- **Predictable behavior:** The kernel's memory behavior is deterministic and independent of workload patterns.

---

## 12. Page Size Parametricity

*(Added 2026-08-02 with the Apple-primary platform decision. Enforces `INV-MEM-009`.)*

### The two page sizes

| Platform | Base page | Role |
|---|---|---|
| Apple Silicon (`T6020`) | **16 KiB** | **Primary** — the serving deployment |
| x86-64 | 4 KiB | Secondary — development, CI, attested deployments |
| QEMU `virt` aarch64 | 4 KiB | Bring-up harness only — note this differs from the real primary target |

The last row is the trap. The aarch64 bring-up harness runs at 4 KiB, so aarch64 code can pass every test
in QEMU and still be wrong on the machine it is written for. **Both page sizes must be exercised.**

### Rules

1. **No bare page-size literal outside `arch/` and `hal/`.** Page size is exposed once, from `hal/mmu.rs`.
   A `4096` in architecture-neutral memory code is a defect, enforced by grep-gate.
2. **Sizes and bounds are expressed in pages.** Pool capacities, region sizes, and stack sizes are page
   counts multiplied by the HAL constant — never byte constants that happen to be page multiples on one
   platform.
3. **Alignment derives from the HAL constant.** Region base addresses, guard-page placement, and
   direct-map offsets align to the platform page size, not to a hardcoded boundary.
4. **W^X granularity follows page size.** A 16 KiB granule makes permission boundaries coarser. Code and
   data that must differ in permissions must be separated at page granularity *on the largest supported
   page size*, or the separation silently fails on the primary platform.

### Why this is a security rule, not a portability rule

A hardcoded 4 KiB does not produce a clean failure on a 16 KiB platform. It produces **misaligned reserved
regions** (weights and KV partitions overlapping their intended bounds), **misplaced guard pages** (a
guard that no longer sits between the stack and its neighbor), and **coarser-than-intended W^X boundaries**
(a page carrying both code and writable data because the split was computed at the wrong granularity).
Each of those is an isolation failure wearing the costume of an arithmetic bug.

---

## 13. Reserved Regions: Weights and KV Cache

*(Added 2026-08-02 with the serving pivot. Enforces `INV-MEM` and `INV-SERVE-001`, `INV-SERVE-004`.)*

The served model needs a large amount of memory. The north-star's answer is explicit: **"give all
resources to the LLM" is satisfied by large fixed reserved regions, never by adding an allocator.** The no
-dynamic-kernel-heap rule (§11) is not relaxed for the inference engine — it is the reason the inference
engine gets regions instead of a heap.

### WEIGHTS_REGION

- Sized at **build time**, in pages, from the model the image is built to serve.
- Populated once by the BXW1 loader, which streams and digests as it writes.
- **Sealed read-only after load.** After sealing there is no code path that can make a weights page
  writable again. This is the "weights-never-writable-post-seal" Kani obligation.
- Never executable. Weights are data; W^X applies with no exception.

### KV_REGION

- Partitioned into **per-session slices**, disjoint by construction rather than by bookkeeping.
- A session's slice is reachable only through that session's capability. No client can name another
  client's slice — the isolation is structural, not checked at access time (`INV-SERVE-001`).
- **Zeroized on session teardown**, before the partition can be reused (`INV-SERVE-004`, §6). Residue
  visible to the next occupant would be a cross-tenant leak that never technically violated the naming
  rule.
- Fixed partition count. Session admission fails closed when partitions are exhausted; it never grows the
  region.

### The availability trade, stated

Fixed regions convert a client-driven **memory-exhaustion** attack into **capacity exhaustion**. That is
the correct security trade — a denied connection is better than a corrupted allocator — but it is a real
availability cost, and it is why per-client admission limits in `servd` are a security control rather than
tuning (`INV-SERVE-003`).

### Non-overlap

`WEIGHTS_REGION`, each `KV_REGION` partition, kernel pools, and the direct map must be provably
non-overlapping. This is a Kani obligation (P3-T2), and it is the obligation most sensitive to §12: the
proof must hold at both page sizes.

---

## 14. Security Invariants

The memory model must uphold the following invariants from `docs/security/SECURITY_INVARIANTS.md`:

| Invariant ID | Invariant Name | How the Memory Model Upholds It |
|---|---|---|
| INV-MEM-001 | Userspace cannot read arbitrary kernel memory | KPTI: kernel pages are not mapped in user page tables. |
| INV-MEM-002 | Userspace cannot write arbitrary kernel memory | KPTI: no kernel page is mapped writable in user page tables. SMAP prevents implicit kernel access to user memory. |
| INV-MEM-003 | W^X is global | Every page table mapping is validated: writable+executable is rejected as a hard error. |
| INV-MEM-004 | Kernel executable regions become immutable after init | Kernel `.text` and `.rodata` pages are remapped as read-only after boot initialization completes. |
| INV-MEM-005 | Memory ownership is explicit | Every page is in exactly one PageType at any time, tracked in the page_type_table. Every transition is auditable. |
| INV-MEM-006 | Freed memory is sanitized before reuse | Mandatory page zeroing on both allocation (to new owner) and deallocation (to free pool). |
| INV-MEM-007 | Kernel stack overrun must fault, not corrupt silently | Guard pages below every stack. IST for kernel fault handling. Double fault handler on dedicated stack. |
| INV-MEM-008 | No unchecked user pointer dereference in kernel paths | Kernel accesses user memory only through validated copy helpers with SMAP-controlled access windows. |
| INV-OBJ-002 | Object reuse cannot preserve stale authority | Object memory is zeroed on deallocation before the pool slot is marked as free. |
| INV-X86-004 | Executable permission policy is coherent | W^X is enforced identically for kernel and user mappings. NX is mandatory. |
| INV-X86-005 | Critical fault paths must remain survivable | IST stacks, double fault handler, and guard pages ensure fault handling does not depend on the overflowed stack. |
| INV-X86-006 | TLB and mapping state transitions must be coherent | CR3 swap on every user/kernel transition. INVLPG for targeted invalidation. PCID for efficient context switches. |
| INV-SCHED-004 | Exhaustion is explicit, never silent | Pool exhaustion returns `AllocationError::PoolExhausted`. No silent retry, no panic, no fallback. |

### Cross-References

- **CapMemory:** The capability type for user-owned physical memory regions is defined in `docs/architecture/CAPABILITY_MODEL.md`, Section 2. CapMemory grants map, unmap, change-permissions, grant, and split operations.
- **CapUntyped:** Raw untyped memory is retyped into CapMemory and other kernel objects through the capability system, as defined in `docs/architecture/CAPABILITY_MODEL.md`, Sections 2 and 11.
- **Page zeroing for capabilities:** Capability slot zeroing via `write_volatile` is specified in `docs/architecture/CAPABILITY_MODEL.md`, Section 7, and permitted by `docs/security/UNSAFE_CODE_POLICY.md` allowlist entry for `src/kernel/src/memory/`.
