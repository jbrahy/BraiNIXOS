# BraiNIX Security Invariants

**Status:** Mandatory · **Reconciled:** 2026-08-03 (single-platform Apple decision; supersedes the
2026-08-02 serving-pivot + Apple-primary reconciliation)

## Purpose

This document defines the security invariants BraiNIX must preserve at all times. These invariants are the backbone of the system's security model.

A feature is acceptable only if it preserves existing invariants or introduces a new invariant with explicit enforcement and evidence strategy.

An implementation detail, performance optimization, compatibility feature, or convenience abstraction must never silently weaken an invariant.

---

## Relationship to NORTH_STAR.md

[`../NORTH_STAR.md`](../NORTH_STAR.md) states **eight headline invariants** as a one-line contract each.
This document is their **enforcement decomposition**: roughly sixty fine-grained, individually checkable
rules that together discharge those eight. Both granularities are needed — the north-star's for stating
the contract, this document's for reviewing a diff.

**Authority.** `NORTH_STAR.md` wins. It is the only place a headline invariant may be introduced,
reworded, or qualified, and the only place a named exception may be recorded. If an entry below appears to
contradict it, the entry below is wrong.

| Headline (NORTH_STAR) | Decomposed here as |
|---|---|
| **INV-AUTH** | §1 `INV-AUTH-001..009`, §3 `INV-OBJ-002`, §12 `INV-FAIL-002` |
| **INV-MEM** | §2 `INV-MEM-001..009`, §5 `INV-SCHED-004` |
| **INV-IPC** | §4 `INV-IPC-001..006` |
| **INV-BOOT** | §7 `INV-BOOT-001..008`, **`INV-BOOT-AS-001..003`**, §11 `INV-BUILD-001..004` |
| **INV-SERVE** | **§13 `INV-SERVE-001..006`**, **§15 `INV-PARSE-001..004`** |
| **INV-MODEL** | **§14 `INV-MODEL-001..004`** |
| **INV-AUDIT** | §9 `INV-AUD-001..003` |
| **INV-GPU** | §8 `INV-DEV-001..003`, **`INV-DEV-004..006`** (DART) |

Sections in **bold** were added or extended during the 2026-08-02 reconciliation.

---

## How to Use This Document

This document should be used in four ways:

1. **Design gate** — every new subsystem or feature must identify which invariants it touches.
2. **Code review lens** — every security-critical change should be reviewed against relevant invariants.
3. **Testing traceability map** — every invariant should eventually map to tests, fuzz targets, audits, or proof work.
4. **Claim discipline** — no one should describe BraiNIX as “secure” in the abstract. They should refer to preserved invariants.

---

## Evidence Labels

Each invariant may later be associated with one or more evidence labels:

- **A** — architectural rule
- **I** — implemented in code
- **T** — tested
- **F** — fuzzed or property-tested
- **M** — model-checked
- **P** — formally proven in stated scope
- **R** — manually reviewed

The presence of an invariant in this file does not imply the invariant has yet been fully implemented or proven.

---

## Named exceptions in force

Reproduced from [`../NORTH_STAR.md`](../NORTH_STAR.md), which is authoritative. Degrading a named
invariant on any platform requires a written exception with owner sign-off recorded **there** — there is
no other mechanism, and a document claiming an exemption not on this list is drift.

| Exception | Scope | Signed | Effect |
|---|---|---|---|
| **INV-BOOT/AS** — ***superseded 2026-08-03 — now the rule*** | Apple Silicon (the only platform) | 2026-08-02 | Measurement, remote attestation, and sealing are structurally unavailable. With x86-64 dropped as a platform there is no undegraded platform for this to be an exception *to*, so it is no longer an exception: **it is what INV-BOOT means.** Retained by name here so the exception count stays checkable rather than silently dropping by one. See §7. |
| **TCB-AS** | Apple Silicon | 2026-08-02 | SecureROM, iBoot1, iBoot2, sepOS are in the TCB by force — closed, unauditable, unremovable. |
| **TCB-EXCEPTION-001** | All platforms | 2026-06-27 | Relational SQL engine in ring 0. See [`TCB_EXCEPTION_001_IN_KERNEL_SQL.md`](TCB_EXCEPTION_001_IN_KERNEL_SQL.md). |
| **TCB-AS/GPU** | Apple Silicon | 2026-08-02 — **conditional** | Running AGX requires loading Apple's opaque, DMA-capable GPU firmware, which executes **concurrently with our kernel for the life of the system**. In force now, so design and implementation may proceed; conditional on five preconditions all being green **before GPU firmware is ever loaded** (they are AS-5-T0's acceptance criteria). If any proves unsatisfiable on real hardware, the exception **self-voids and AS-5 stops**. Until all five are green, no build ships with the GPU enabled. See `INV-DEV-004..006`, `INV-SERVE-006`, `INV-PARSE-001`. |
| **Ed25519 verification stack** | All platforms | 2026-08-02 | `ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle` stay vendored **permanently, verify-only** — INV-BOOT's release signature requires curve25519 field arithmetic, and hand-rolling it would *lower* assurance. All signing paths go. The in-tree primitive set remains SHA-256, HKDF, ChaCha20, Poly1305, which are specified to be in-tree — `sha2` and `chacha20` are still vendored until that reimplementation lands. |

---

## Invariant Categories

The invariants are grouped into the following categories:

- authority and capability invariants
- memory and mapping invariants
- object lifecycle invariants
- IPC and liveness invariants
- scheduler and resource invariants
- platform and execution invariants (x86-64 and aarch64)
- boot and attestation invariants
- device isolation invariants
- audit and observability invariants
- unsafe code and assurance invariants
- build and release invariants
- failure and recovery invariants
- **serving and client isolation invariants**
- **model confinement invariants**
- **hostile-input parser invariants**

---

# 1. Authority and Capability Invariants

## INV-AUTH-001 — No ambient authority
No runnable process, thread, or service possesses authority merely by existence, identity, or namespace presence. All security-relevant actions require explicit capabilities.

**Why it matters:** Ambient authority creates hidden privilege paths and confused deputies.

**Enforcement directions:**
- no global process privilege flags
- no global “superuser” userspace role
- all kernel objects accessed via typed capabilities
- bootstrap authority must be collapsed after initialization

---

## INV-AUTH-002 — Authority is explicit and typed
Every authority token must correspond to a specific object type and rights mask. A capability for one object type must not be usable as another.

**Why it matters:** Type confusion and generic handles become privilege-escalation pathways.

**Enforcement directions:**
- distinct capability/object type tagging
- checked dispatch on object type
- no reinterpretation of raw identifiers across object classes

---

## INV-AUTH-003 — Rights are monotonic under derivation
A derived capability may preserve or reduce authority, but it must never gain rights not present in its parent.

**Why it matters:** Rights amplification defeats confinement.

**Enforcement directions:**
- derivation rules explicitly defined
- no implicit privilege expansion during transfer, copy, or mint operations
- derivation logic amenable to property checking

---

## INV-AUTH-004 — Revocation is final within defined scope
Once revocation completes for a capability lineage, the revoked authority must no longer be usable within the declared scope of revocation.

**Why it matters:** Stale authority and partial revocation are classic security failures.

**Enforcement directions:**
- explicit revocation model
- slot/object zeroization where required
- no hidden alias paths that bypass revocation
- clear definition of revocation completion

**Known gap (Phase 10, D-04):** The testable path `execute_process_exit_sequence` correctly calls `revoke_and_remove_cspace_from_table`, which zeroes all valid/revoking slots and removes the ProcessTable entry. However, the production diverging path `handle_process_exit_syscall` calls `perform_process_capability_space_teardown`, which is a stub that does nothing. This is because the ProcessTable is created on the `execute_boot_sequence` stack and is dropped when that function returns — no kernel-global ProcessTable accessor exists yet. Consequence: if a real userspace process calls sys_process_exit (syscall 7), its CSpace will not be removed. This gap is acceptable only while no real userspace threads can reach sys_process_exit. Resolution: wire the global ProcessTable accessor in the next phase and replace the stub.

---

## INV-AUTH-005 — Capabilities cannot be forged from userspace
Userspace cannot construct, guess, or coerce a valid capability through raw bit patterns, integer guessing, or namespace probing.

**Why it matters:** Capability forgery destroys the model.

**Enforcement directions:**
- kernel-mediated capability creation
- opaque userspace representation where needed
- validation against kernel-owned slot/object state
- no raw numeric object IDs accepted as authority

---

## INV-AUTH-006 — Reply authority is single-purpose
Reply-related authority may only be used for the specific reply path it was created to support, and cannot become general communication authority.

**Why it matters:** Reply confusion can produce confused deputies or hidden privilege channels.

**Enforcement directions:**
- dedicated reply objects or equivalent semantics
- one-shot or tightly scoped reply behavior
- explicit lifecycle and invalidation rules

---

## INV-AUTH-007 — Process creation cannot mint ambient privilege
Creating or spawning a process may only transfer explicitly granted authority and policy-approved bootstrap capabilities.

**Why it matters:** Spawn paths often smuggle hidden privilege.

**Enforcement directions:**
- userspace spawn policy isolated from kernel mechanism
- explicit initial cap set
- compile-time and/or signed runtime policy
- no hidden inheritance of unrelated global rights

---

## INV-AUTH-008 — Cross-domain authority flow is auditable
Any transfer of authority between security domains must be explicit, attributable, and subject to logging or observable policy.

**Why it matters:** Security review requires traceable privilege flow.

**Enforcement directions:**
- transfer operations as distinct events
- optional audit hooks for sensitive transfers
- clear domain accounting

---

## INV-AUTH-009 — Administrative authority is a capability, not a shell
Administration is a second session *type* on the same authenticated transport, distinguished from a
client session by capability and by nothing else. An admin session holds `CapAdmin` (capability 14,
alongside `Serve=11`, `Model=12`, `Gpu=13`) and may invoke only a fixed, enumerated verb set —
enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. The verb set is frozen at
accept and cannot be widened by anything the session says afterwards. `CapAdmin` does not imply
`CapServe`, and `CapServe` never derives `CapAdmin`.

**Why it matters:** A general-purpose remote shell is ambient authority wearing an admin badge — it can
do whatever the process hosting it can do, which is precisely the property the capability model exists to
forbid. An enumerated verb set is reviewable; "run this command" is not. Administration is explicitly not
a shell, and the serial console — not a network path — is the break-glass channel.

**Enforcement directions:**
- `CapAdmin` is a distinct capability type, neither derived from nor derivable to `CapServe` (INV-AUTH-002, INV-AUTH-003)
- the verb table is a compile-time enumeration; no verb dispatches to a general command interpreter
- a verb needing authority the set does not cover requires a new named capability, never a widened `CapAdmin`
- admin session establishment, every verb invoked, and every denial are observable to `auditd` (INV-AUTH-008, INV-SERVE-005)

**Related:** INV-SERVE-001 — an admin session is still a session, and still cannot name another
session's state. Introduced 2026-08-02 with the admin-channel decision.

---

# 2. Memory and Mapping Invariants

## INV-MEM-001 — Userspace cannot read arbitrary kernel memory
No userspace mapping or access path may expose arbitrary kernel memory contents.

**Why it matters:** Kernel memory disclosure accelerates exploitation and leaks secrets.

**Enforcement directions:**
- separate kernel/user mappings
- no direct kernel-object aliasing into userspace
- checked copy or message transfer semantics
- KPTI or equivalent where policy requires

---

## INV-MEM-002 — Userspace cannot write arbitrary kernel memory
No userspace mapping or syscall path may permit arbitrary modification of kernel-owned memory.

**Why it matters:** Kernel integrity loss is total compromise.

**Enforcement directions:**
- strict map authority checks
- no writable kernel aliases
- pointer provenance discipline
- hardened copy paths

---

## INV-MEM-003 — W^X is global
Memory may not be simultaneously writable and executable.

**Why it matters:** W^X reduces code-injection flexibility and is foundational hygiene.

**Enforcement directions:**
- page permission policy
- loader enforcement
- no runtime code generation in the trusted core

---

## INV-MEM-004 — Kernel executable regions become immutable after init
Kernel `.text` and immutable data regions become read-only after boot finalization.

**Why it matters:** Late mutation expands exploit surfaces and hidden state changes.

**Enforcement directions:**
- boot finalization step
- strict separation of mutable init state from permanent executable state
- post-init permission lock-down

---

## INV-MEM-005 — Memory ownership is explicit
Every page or memory object is in exactly one well-defined ownership state at a given time.

**Why it matters:** Ambiguous ownership causes aliasing, reuse, and isolation failures.

**Enforcement directions:**
- typed page state
- object lifecycle transitions
- no “floating” pages without tracked owner/state
- explicit transitions on allocate/map/unmap/free/lend

---

## INV-MEM-006 — Freed memory is sanitized before reuse
Freed user pages, kernel objects, and sensitive buffers must be sanitized according to policy before reuse.

**Why it matters:** Reuse without sanitation leaks secrets and enables stale-state exploitation.

**Enforcement directions:**
- zeroization or object-specific sanitization
- required on all free/recycle paths
- verified in tests for representative object classes

---

## INV-MEM-007 — Kernel stack overrun must fault, not corrupt silently
Stack exhaustion or overrun must be detected through guard pages or equivalent mechanisms.

**Why it matters:** Silent stack corruption is catastrophic in kernel mode.

**Enforcement directions:**
- guard pages
- separate critical-fault stacks where needed
- bounded stack usage review for low-level paths

---

## INV-MEM-008 — No unchecked user pointer dereference in kernel paths
The kernel may not trust raw userspace pointers without validation, ownership checks, and boundary checks.

**Why it matters:** Copy boundary bugs are a dominant exploitation vector.

**Enforcement directions:**
- centralized checked access helpers
- explicit copyin/copyout discipline
- no ad hoc unsafe pointer dereference from syscall code

---

## INV-MEM-009 — Page size is a platform parameter, never an assumption
No memory code outside `arch/` may assume a specific base page size. The platform uses **16 KiB** base pages; the frozen x86-64 reference uses **4 KiB**. Region sizing, alignment, guard-page placement, and W^X granularity must all derive from the platform's page-size constant. *(Restated 2026-08-03: the HAL is cancelled, so the constant's home is the aarch64 MMU code rather than `hal/mmu.rs`. The obligation is unchanged.)*

**Why it matters:** A hardcoded page size does not fail loudly — it silently misaligns reserved regions, misplaces guard pages, and can make W^X enforcement coarser than intended. That is an isolation failure wearing the costume of a portability bug. **With one platform the risk inverts and does not shrink:** a hardcoded **16 KiB** is now the likelier defect, and the QEMU `virt` harness that would have caught the 4 KiB direction was cancelled with Phase 4.

**Enforcement directions:**
- page size exposed once, from the aarch64 MMU module; no bare page-size literal in architecture-neutral memory code
- grep-gate against bare page-size literals — `4096` **and** `16384` — outside `arch/`
- `WEIGHTS_REGION` and `KV_REGION` sizing expressed in pages, not bytes
- with no 4 KiB harness left, the frozen x86-64 reference build is the only remaining second data point, and review is the primary control

**Related:** INV-MEM-003, INV-MEM-007. Introduced 2026-08-02 with the Apple-primary decision.

---

# 3. Object Lifecycle Invariants

## INV-OBJ-001 — Every kernel object has a defined lifecycle
Objects must have defined creation, live, transfer, revocation, and destruction states.

**Why it matters:** Security bugs cluster at lifecycle edges.

**Enforcement directions:**
- state machine per object type
- invalid transitions rejected
- destruction order rules documented

---

## INV-OBJ-002 — Object reuse cannot preserve stale authority or stale data
Reused slots or objects must not inherit authority bindings, metadata, or sensitive contents from prior occupants.

**Why it matters:** Stale slot reuse is a classic source of privilege bugs.

**Enforcement directions:**
- slot zeroization
- generation counters or equivalent where appropriate
- destruction-time cleanup
- no raw handle recycling without revalidation

---

## INV-OBJ-003 — Object identity cannot be confused across types or generations
An object reference from one lifecycle generation must not silently target a later object occupying the same storage.

**Why it matters:** Type and generation confusion undermine safety checks.

**Enforcement directions:**
- type tags
- generation/version checks where needed
- strict slot/object coupling

---

# 4. IPC and Liveness Invariants

## INV-IPC-001 — IPC is explicit and kernel-mediated
All control-plane inter-process communication must occur through explicit kernel-mediated endpoints or tightly governed alternatives.

**Why it matters:** Hidden channels bypass review and policy.

**Enforcement directions:**
- endpoint objects
- no ambient namespace messaging
- transfer rules embedded in kernel validation

---

## INV-IPC-002 — IPC cannot amplify rights
A message send, receive, or reply cannot create new authority beyond explicitly transferred capabilities and allowed metadata.

**Why it matters:** IPC is a natural place for privilege confusion.

**Enforcement directions:**
- atomic capability transfer rules
- no implicit inheritance during IPC
- endpoint and reply semantics separated

---

## INV-IPC-003 — Waiting is bounded or explicitly policy-controlled
A caller may not be blocked indefinitely by default. Blocking behavior must be bounded, cancelable, or deliberately policy-controlled.

**Why it matters:** Infinite waits become availability attacks and hidden deadlocks.

**Enforcement directions:**
- mandatory timeout support or explicit no-timeout policy annotations
- cancellation semantics
- scheduler visibility into blocked states

---

## INV-IPC-004 — Reply paths cannot be hijacked
A reply must only be deliverable to the original intended waiting context or its explicitly defined replacement.

**Why it matters:** Reply hijacking becomes a confused-deputy channel.

**Enforcement directions:**
- reply-object validity checks
- one-shot semantics where practical
- invalidation after completion or cancellation

---

## INV-IPC-005 — IPC state transitions are race-safe within defined concurrency assumptions
Concurrent operations must not expose partially updated endpoint, reply, or transfer state.

**Why it matters:** Partial state transitions produce exploitable edge cases.

**Enforcement directions:**
- atomic state transitions where required
- lock discipline or lock-free proof burden
- interruption/preemption-aware state design

---

## INV-IPC-006 — Performance optimizations must not introduce ambient sharing
If memory lending or zero-copy paths are added later, they must preserve explicit ownership, revocation, and type safety.

**Why it matters:** Performance shortcuts often erode security boundaries.

**Enforcement directions:**
- borrowed-memory object type
- explicit return/revoke semantics
- no permanent untracked shared mappings

---

# 5. Scheduler and Resource Invariants

## INV-SCHED-001 — One domain cannot silently consume another domain's budget
CPU time, message buffers, kernel objects, and related resources must be quota-accounted per domain according to policy.

**Why it matters:** Resource exhaustion is a security issue, not just a performance issue.

**Enforcement directions:**
- per-domain quotas
- rejection on exhaustion
- explicit accounting on transfer or creation
- auditability for quota breaches

---

## INV-SCHED-002 — Priority inversion must be bounded
Blocking relationships must not allow unbounded starvation of higher-priority work by lower-priority holders.

**Why it matters:** Priority inversion becomes denial-of-service.

**Enforcement directions:**
- priority inheritance or equivalent mechanism
- bounded blocking analysis
- hostile-load testing

---

## INV-SCHED-003 — Timeout processing is deterministic and safe
Timeout expiry must not race with wakeup, reply, or cancellation in a way that corrupts scheduler or IPC state.

**Why it matters:** Timeouts often become double-completion bugs.

**Enforcement directions:**
- state machine design for timeout vs. completion
- deterministic ordering rules
- tests for near-boundary timing behavior

---

## INV-SCHED-004 — Exhaustion is explicit, never silent
Pool exhaustion, quota exhaustion, or scheduler admission failure must return a defined fault or error path.

**Why it matters:** Silent fallback hides broken assumptions and weakens trust.

**Enforcement directions:**
- explicit error codes
- no unbounded allocation fallback
- no hidden privilege-based bypasses for normal services

---

# 6. Platform and Execution Invariants

**Reconciled 2026-08-03: there is one platform.** x86-64 was dropped as a platform; the x86-64 code stays
in tree and stays building as the **frozen reference implementation** the aarch64 port is written against,
and is deleted only when aarch64 replaces it. Every obligation below is discharged on **aarch64 / Apple**.
The x86-64 column is retained because the reference implementation is the thing the aarch64 work is read
against — it is **frozen reference, not scheduled**, and nothing is required to keep working there beyond
continuing to compile.

| Property | x86-64 mechanism *(frozen reference, not scheduled)* | aarch64 / Apple mechanism *(the platform)* |
|---|---|---|
| Kernel cannot execute user code | SMEP | PXN |
| Kernel cannot implicitly read/write user memory | SMAP | PAN |
| Control-flow integrity | IBT / ENDBR64 | PAC / BTI |
| Hardware entropy | RDRAND | RNDR |
| No-execute mapping | NX bit | XN / UXN |
| IOMMU | VT-d | **DART** (many instances — see §8) |
| Interrupt controller | APIC | **AIC** (FIQ split — see `INV-ARM-005`) |

## 6a. x86-64 — *frozen reference, not scheduled*

**Reconciled 2026-08-03.** x86-64 is no longer a platform. `INV-X86-001..006` and `INV-FAULT-001..003`
below are **not deleted and not weakened**: they remain the invariants the in-tree x86-64 reference
implementation is held to, and it is still expected to compile and to hold them. What changed is that
**nothing is scheduled against them** — no release, deployment, or assurance claim rests on this
architecture, and no new work is planned here. They are retained because deleting the invariants of code
that is still in the tree would leave that code unaccountable, which is the opposite of the point.

## INV-X86-001 — Only supported x86-64 execution modes are used
BraiNIX operates only in documented 64-bit modes and does not depend on legacy mode behavior beyond controlled bootstrap transitions.

**Why it matters:** Legacy compatibility expands poorly-audited state space.

---

## INV-X86-002 — User code cannot execute through kernel-controlled privilege paths
The kernel must not execute user-controlled code or treat user memory as trusted executable content.

**Why it matters:** This is a direct kernel-compromise path.

**Enforcement directions:**
- SMEP
- strict entry/exit discipline
- no user-controlled executable aliases in kernel context

---

## INV-X86-003 — User memory cannot be accessed implicitly from kernel paths where blocked by policy
Kernel access to user memory must be explicit and controlled.

**Why it matters:** Unintended user-memory access expands attack surface.

**Enforcement directions:**
- SMAP
- scoped user-memory access helpers
- copy boundary discipline

---

## INV-X86-004 — Executable permission policy is coherent across kernel and userspace
NX and W^X requirements must remain consistent across all mappings.

**Why it matters:** Inconsistent execute policy becomes a bypass channel.

---

## INV-X86-005 — Critical fault paths must remain survivable enough to fail closed
Double-fault, page-fault, general-protection, NMI, and machine-check handling must not rely on fragile shared state when avoidable.

**Why it matters:** Fault-handling code is highly privileged and failure-prone.

**Enforcement directions:**
- dedicated stacks where appropriate
- minimal handlers
- clear panic vs. recover policy

---

## INV-X86-006 — TLB and mapping state transitions must be coherent
Mapping changes must become visible in a defined, correct way across cores and execution contexts.

**Why it matters:** Stale translation state breaks isolation.

**Enforcement directions:**
- explicit invalidation rules
- SMP coherence policy
- tests or proofs for representative mapping transitions

---

## INV-FAULT-001 — Double-fault handler runs on a dedicated IST stack
The double-fault IDT entry must be registered with a non-zero IST index pointing to a stack distinct from the interrupted thread's stack. This ensures that a stack-overflow-induced double fault can be caught rather than silently producing a triple fault.

**Why it matters:** Without a dedicated stack, a stack overrun that triggers a double fault will triple-fault immediately, giving the kernel no chance to log or recover. The IST mechanism provides a known-good stack at fault entry.

**Enforcement directions:**
- TSS IST[0] initialized with a valid dedicated 4096-byte stack before GDT load
- double-fault IDT entry configured with `set_stack_index` pointing to IST[0]
- observable via `DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX_IS_SET` atomic flag

**Evidence:** test_double_fault_handler_is_registered_on_separate_interrupt_stack_table_entry

---

## INV-FAULT-002 — All accessible CPU exception vectors have registered handlers
Every CPU exception vector that the x86_64 crate exposes (vectors 0–8, 10–14, 16–21, 28–30) must have an explicit handler registered in the IDT. No accessible vector may be left as an implicit triple-fault path.

**Why it matters:** Unhandled exception vectors produce triple faults with no diagnostic output, making debugging impossible and creating unpredictable system behavior under fault conditions.

**Enforcement directions:**
- all named IDT fields in `InterruptDescriptorTable` registered before `IDT.load()`
- vectors 9, 15, 22–27, 31 are reserved/private in the x86_64 crate and cannot be registered; this is documented
- `load_interrupt_descriptor_table` registers all accessible vectors before enabling interrupts

**Evidence:** test_all_accessible_exception_vectors_have_handlers

---

## INV-FAULT-003 — Fault handlers halt the processor with interrupts disabled
All CPU exception handlers must terminate by disabling interrupts (`cli`) before issuing `hlt`, looping indefinitely. This prevents an interrupt from firing during fault handling and causing a recursive fault or undefined re-entry.

**Why it matters:** If an interrupt fires after a fatal fault but before `hlt`, the interrupt handler may encounter corrupted state. Disabling interrupts first ensures a clean halt with no re-entry risk.

**Enforcement directions:**
- `halt_processor_loop` in `interrupt_descriptor_table.rs` issues `cli` then `hlt` in a loop
- panic handler in `main.rs` issues `cli` then `hlt` in a loop
- no fault handler may return to caller; all must call a diverging halt path

**Evidence:** test_panic_handler_disables_interrupts_before_halt; QEMU integration test observes halt after fault injection

---

## 6b. aarch64 and Apple Silicon

Introduced 2026-08-02. These govern the **primary** platform and are therefore not "future work" — they
are the ones most in need of proof artifacts.

## INV-ARM-001 — Only supported aarch64 exception levels are used
The kernel runs at EL1 with userspace at EL0. Entry from firmware may occur at EL2; the transition to EL1 is explicit and one-way. No dependence on EL3 (Apple Silicon has none) or on PSCI (likewise absent).

**Why it matters:** Exception-level confusion is the aarch64 analogue of x86 legacy-mode confusion, with the added hazard that Apple's entry state is undocumented.

**Enforcement directions:**
- assume nothing about inherited MMU, cache, or translation state at firmware handoff; re-establish our own immediately
- explicit EL2→EL1 transition with documented register state
- secondary CPUs released via the platform's own reset-vector mechanism, never PSCI

---

## INV-ARM-002 — PAN and PXN are enabled and equivalent to SMAP/SMEP
Kernel execution of user-mapped code is prevented (PXN), and implicit kernel access to user memory is prevented (PAN). Explicit, scoped accessor helpers are the only path.

**Why it matters:** These discharge the same obligations as `INV-X86-002` and `INV-X86-003`, and they are now the *only* place those obligations are discharged in shipping code. Missing them means the obligation is not met anywhere — there is no second platform where it still holds.

---

## INV-ARM-003 — PAC/BTI control-flow integrity is enabled where available
Pointer authentication and branch-target identification are enabled on cores that implement them, discharging the obligation `INV-X86-004` covers via IBT/ENDBR64.

---

## INV-ARM-004 — Entropy comes from RNDR with an explicit failure path
`RNDR`/`RNDRRS` may legitimately fail. A failed read is an explicit error that blocks cryptographic operation start (`INV-BOOT-005`), never a silent fallback to a weaker source.

---

## INV-ARM-005 — Interrupt-controller abstraction survives the AIC's shape
The interrupt-controller abstraction must express the Apple Interrupt Controller honestly rather than forcing it into a GIC-shaped API. *(Restated 2026-08-03: the HAL is cancelled, so this is the AIC backend's own interface rather than a `hal/interrupts` trait. The rule is unchanged, and with no GIC backend left the pressure to GIC-shape the API is gone — the obligation now reads as "do not inherit GIC assumptions from habit.")*

- a single packed **event word** read replaces the GIC ack/EOI register pair
- per-CPU timers and some other sources arrive as **FIQ**, entirely outside the controller — the trait needs a notion of CPU-local sources the controller does not own
- IPIs go through implementation-defined system registers, not a controller doorbell
- the AIC revision is selected from ADT compatible strings at runtime, and an **unknown string fails closed**

**Why it matters:** An interrupt abstraction that quietly assumes "all interrupts flow through the controller" will mis-handle the FIQ timer path on the primary platform — and timer handling is where scheduler and liveness invariants are enforced.

---

# 7. Boot and Attestation Invariants

**Restated 2026-08-03 for a single platform.** [`../NORTH_STAR.md`](../NORTH_STAR.md) is authoritative and
now states INV-BOOT as exactly four clauses, everywhere and always: a **reproducible build**, an **Ed25519
release signature**, **iBoot-verified payload integrity** under the machine's Secure-Enclave-held local
policy, and a **self-reported software measurement log** that is a debugging aid and never evidence.
**Remote attestation, sealing, and runtime-chain measurement are permanently unavailable — not deferred,
not scheduled, not achievable by any later phase.** There is no TPM on the only supported platform and none
can be added.

`INV-BOOT-AS-001..003` below therefore stopped being the Apple-specific consequences of an exception and
became the boot rules, full stop. They are unchanged in wording and strengthened in reach: what used to
constrain "Apple Silicon code paths" now constrains every code path there is.

## INV-BOOT-001 — Production security claims require a trusted production boot path
No production-grade security claim may be made without the required measured boot and hardware assumptions being satisfied.

**Why it matters:** Root of trust begins before the kernel.

---

## INV-BOOT-002 — Development-mode attestation cannot be presented as production trust
Virtual TPM or emulated measurement flow may be used for testing only.

**Why it matters:** Mode confusion produces false assurance.

---

## INV-BOOT-003 — Dev and prod cryptographic material remain separate
Development keys, test roots, and production roots must never overlap.

**Why it matters:** Shared trust anchors collapse environment separation.

---

## INV-BOOT-004 — Rollback policy is explicit
The system must define whether and how older kernels, configurations, or policy bundles are permitted.

**Why it matters:** Rollback is a common way to bypass later hardening.

---

## INV-BOOT-005 — Entropy initialization is explicit and conservative
The kernel must define when cryptographic operations may begin and what minimum seeding conditions are required.

**Why it matters:** Early-boot randomness mistakes have long-lived consequences.

---

## INV-BOOT-006 — Key material is enrolled at runtime, never built in
Client pre-shared keys and admin keys are enrolled while the system is running and persisted by the
kernel's credential store (`src/kernel/src/boot/credential_store.rs`) — to ANS2 NVMe on Apple Silicon from
AS-4a. (The virtio-blk path is the frozen x86-64 reference, not a scheduled target.) Enrollment happens
over the admin channel (`CapAdmin`, INV-AUTH-009) or over the serial console, and nowhere else.

**The store is plaintext at rest, permanently** *(owner ruling 2026-08-02, Apple half; made unconditional
2026-08-03 when the sealing half died with the x86-64 platform).* Sealing binds a secret to a measured boot
state; the only supported platform has neither the measurement nor the hardware to bind against, so there
is no sealed-at-rest design to schedule and none is planned. iBoot2's device-local policy protects the
*payload* at rest and seals nothing of ours. The consequence is stated rather than softened: **anyone who
obtains the disk obtains every client and admin pre-shared key**, and combined with the absent forward
secrecy of `INV-BOOT-007` that retroactively decrypts every session recorded from that machine.

**Enforcement directions (at rest):**
- no code, log line, protocol field, or release note may describe the credential store as sealed or
  encrypted at rest (`INV-BOOT-AS-001`)
- the release notes state the plaintext-at-rest exposure plainly

**Why it matters:** Runtime enrollment is what makes `INV-BUILD-004` achievable rather than aspirational:
the published image can be byte-identical for every deployment precisely because it carries no
deployment's secrets. It also makes revocation real — a key that was compiled in cannot be revoked
without a rebuild.

**Enforcement directions:**
- the credential store is the only writer of key material to persistent storage
- enrollment and revocation are attributable events (INV-AUTH-008)
- a key that fails to persist fails the enrollment; there is no in-memory-only "temporarily enrolled" state
- the key format is a property of the store, not of the backing device

---

## INV-BOOT-007 — Session keys ratchet forward and the old chain key is deleted
Session key *n* is derived from chain key *n* by HKDF-SHA256; the chain then advances and chain key *n* is
zeroized. No component retains a chain key it has advanced past. This buys forward secrecy from symmetric
primitives alone — the serving transport holds no asymmetric key and needs none.

**Why it matters, with its present cost stated plainly:** **until the ratchet ships there is
no forward secrecy.** A disclosed pre-shared key retroactively decrypts every recorded session. That is
the current state of the system, not a hypothetical future risk, and it is why the ratchet is an
invariant rather than an enhancement.

**Enforcement directions:**
- derivation and advance-with-zeroization are one operation; no path derives a session key without advancing
- chain-key storage is sanitized on advance and again on session teardown (INV-MEM-006, INV-SERVE-004)
- a recorded-traffic test: material captured after an advance must not decrypt records sealed before it

---

## INV-BOOT-008 — The break-glass admin key is serial-provisioned and never network-rotatable
The break-glass admin pre-shared key is provisioned over the serial console only. No admin verb, and no
path reachable over the network, may revoke or replace it.

**Why it matters:** Every other key can be replaced over the admin channel — rotation is not a verb of its
own, it is `enroll-key` followed by `revoke-key` (INV-AUTH-009's set is exactly six and is frozen) — which
means a compromised admin session could otherwise replace all of them and lock the owner out of the
owner's own machine permanently. The break-glass key is the floor under that failure: physical access
wins. The cost is stated too — it is a long-lived key that cannot be replaced remotely, so its disclosure
requires physical presence to repair.

**Enforcement directions:**
- `enroll-key` and `revoke-key` both reject the break-glass key identity, and the rejection is not configurable
- the serial provisioning path is compiled in unconditionally and is not gated by any network state
- **Related:** INV-AUTH-009, INV-BOOT-006, INV-FAIL-003.

---

## The boot posture: INV-BOOT-AS-001..003 *(formerly the INV-BOOT/AS exception)*

Recorded in [`../NORTH_STAR.md`](../NORTH_STAR.md); these are its enforcement consequences. **This is the
only platform**, so these are not edge cases and no longer a degradation *relative to* anything — they
describe the assurance level of the product, everywhere. INV-BOOT/AS is listed in the ledger above as
*superseded — now the rule*.

## INV-BOOT-AS-001 — Attestation claims are forbidden
No BraiNIX component, release note, log line, protocol field, or document may assert remote attestation, sealing, or hardware-anchored measurement. There is no TPM, and the Secure Enclave exposes no PCR-style extend/quote/seal interface to third-party software.

**Why it matters:** A false attestation claim is worse than no attestation, because a client will rely on it. This invariant is the guard against the strongest temptation created by the platform decisions of 2026-08-02 and 2026-08-03 — and the temptation is larger now, because there is no longer a second platform to which an attested deployment could honestly be pointed.

**Enforcement directions:**
- the BSP protocol must not offer an attestation field that cannot be populated honestly — and none can be
- grep-gate on attestation vocabulary across the whole tree, not merely Apple Silicon code paths
- release notes state the posture explicitly on every build

---

## INV-BOOT-AS-002 — The software measurement log is never presented as evidence
The kernel may hash what it loads and record a log. That log is **self-reported**: a kernel compromised early can produce any log it likes. It may be used for operational debugging and accidental-corruption detection. It may not be used as evidence against an attacker, exported as an attestation, or described as a measurement.

**Why it matters:** This is the specific mechanism by which a degraded platform gets quietly re-described as an attested one.

---

## INV-BOOT-AS-003 — Payload integrity is Apple's root, and is labeled as such
iBoot2 verifies the Image4-wrapped payload against a Secure-Enclave-held, **device-local** policy at every boot. This is real, hardware-rooted integrity for the payload at rest — and it proves nothing to a remote party, is keyed to one machine, and is not our trust root.

**Why it matters:** Overstating this is the second-most-likely way the platform's assurance gets misrepresented. Document it as what it is: tamper-resistance at rest, not attestation.

**Related:** TCB-AS — SecureROM, iBoot1, iBoot2, and sepOS are in the TCB by force and cannot be audited or removed.

---

# 8. Device Isolation Invariants

## INV-DEV-001 — Devices do not imply universal memory authority
Owning a device-facing capability must not automatically grant unrestricted system memory access.

**Why it matters:** Device code is historically dangerous.

**Enforcement directions:**
- IOMMU-backed policy
- per-device memory windows
- minimal device object rights

---

## INV-DEV-002 — Each device service receives least privilege
A device-handling userspace process receives only the authority required for that device and its bounded operating model.

**Why it matters:** Overprivileged drivers become whole-system hazards.

---

## INV-DEV-003 — Interrupt authority is explicit
Interrupt delivery and binding must be capability-controlled and attributable.

**Why it matters:** Interrupt abuse can become privilege or availability abuse.

---

## INV-DEV-004 — Every IOMMU instance defaults to deny-all
On a platform with multiple IOMMU instances, **every** discovered instance is configured deny-all before any device is permitted to issue a transaction. There is no "not yet configured" state in which a device can DMA.

**Why it matters:** Apple's DART is not one translation unit like VT-d — it is dozens of small per-device-cluster instances scattered across the SoC and discovered from the Apple Device Tree. A single instance left unconfigured is a complete DMA escape, and the failure is silent. Deny-all-by-default converts "we forgot one" from a breach into a device that does not work.

**Enforcement directions:**
- enumerate every DART instance from the ADT and program deny-all before device bring-up
- no code path that maps a window before the instance has been explicitly initialized
- a device whose IOMMU instance is unknown does not get to run

---

## INV-DEV-005 — An unrecognized IOMMU variant fails closed
DART PTE formats and register layouts differ across SoC generations. An unrecognized ADT compatible string, or a variant whose PTE layout we have not implemented, halts bring-up for that device. It never falls back to a permissive or "best guess" configuration.

**Why it matters:** A guessed PTE layout that happens not to fault is indistinguishable from a working one until a device DMAs somewhere it should not. Guessing at IOMMU configuration is guessing at isolation.

---

## INV-DEV-006 — A driver cannot widen its own DMA window
The IOMMU trait exposes no operation by which a driver can enlarge, relocate, or add to its own translation window. Window changes are made by the capability-bounded authority that granted the window, never by its holder.

**Why it matters:** This is the structural control behind INV-GPU, and it applies now — every DMA-capable device driver on the primary platform (NVMe, PCIe, Ethernet) depends on it long before any GPU work begins.

**Evidence:** Kani proof that no trait method widens a window; DMA fault injection.

---

# 9. Audit and Observability Invariants

## INV-AUD-001 — Security-relevant events are observable
Key authority changes, faults, revocations, quota failures, and mode transitions must be observable according to policy.

**Why it matters:** Unobservable security state is hard to trust or debug.

---

## INV-AUD-002 — Audit consumers do not become omnipotent
The component that reads or exports audit data must not automatically gain broad system authority.

**Why it matters:** Audit pipelines can accidentally become privileged chokepoints.

---

## INV-AUD-003 — Audit pressure is bounded
Audit generation must not be able to crash or silently destabilize the system through unbounded backpressure.

**Why it matters:** Observability can itself become a denial-of-service vector.

---

# 10. Unsafe Code and Assurance Invariants

## INV-UNSAFE-001 — Every unsafe block has a local soundness contract
Each unsafe block or module must document:
- assumptions
- ownership rules
- aliasing expectations
- synchronization expectations
- what would make it unsound

**Why it matters:** Unannotated unsafe code is opaque risk.

---

## INV-UNSAFE-002 — Unsafe scope is minimized
Unsafe code must be concentrated in low-level modules and not spread casually across policy-heavy kernel code.

**Why it matters:** Wide unsafe distribution kills auditability.

---

## INV-UNSAFE-003 — Unsafe growth is reviewed as a security event
Increasing the unsafe surface requires explicit review.

**Why it matters:** Security erosion often happens gradually.

---

## INV-UNSAFE-004 — Assurance claims are traceable
A claim of testing, model checking, or proof must name the exact invariant or subsystem scope it covers.

**Why it matters:** Vague assurance language leads to false confidence.

---

# 11. Build and Release Invariants

## INV-BUILD-001 — Shipped artifacts correspond to reviewed inputs
Release artifacts must trace to reviewed source, dependencies, toolchain versions, and build parameters.

**Why it matters:** Runtime security is irrelevant if the shipped binary is not what was reviewed.

---

## INV-BUILD-002 — Toolchain and dependency drift is controlled
Compiler and dependency changes must be explicit and reviewable.

**Why it matters:** Drift can silently invalidate prior security assumptions.

---

## INV-BUILD-003 — Release signing authority is narrowly controlled
The ability to publish trusted BraiNIX artifacts must be limited and auditable.

**Why it matters:** Release-sign compromise defeats the rest of the chain.

---

## INV-BUILD-004 — No secret ever enters a build artifact
No key, key seed, or other secret is compiled into a released image or produced as a build output. Client
and admin keys are enrolled at runtime and persisted by the kernel's credential store (`INV-BOOT-006`).

**Why it matters:** A compile-time secret is structurally incompatible with INV-BOOT's reproducible-build
clause. Either the published payload contains the secret, or the deployed payload differs from the
published one — and reproducibility that describes an image nobody runs is not reproducibility.

**Enforcement directions:**
- grep-gate against key, seed, and PSK literals in the build tree
- `CLIENT_KEY_SEED` in `src/kernel/src/ssh/client_identity.rs` is an acknowledged development seed and is no longer the model; it does not ship
- the reproducibility check runs against the artifact that is actually deployed, not a variant of it

---

# 12. Failure and Recovery Invariants

## INV-FAIL-001 — Failure modes are defined
Critical failure conditions must have explicit policy: panic, halt, reboot, isolate, or degrade.

**Why it matters:** Undefined failure behavior often becomes unsafe behavior.

---

## INV-FAIL-002 — Recovery must not mint hidden authority
Restarting a service, handling a timeout, or recovering from failure must not grant new power unless explicitly authorized.

**Why it matters:** Recovery paths are common privilege-escalation seams.

---

## INV-FAIL-003 — Secure degradation is preferred to silent insecurity
If a required security property cannot be maintained, the system must fail closed or enter a clearly documented degraded mode.

**Why it matters:** Silent insecure fallback destroys confidence.

---

# 13. Serving and Client Isolation Invariants

Introduced 2026-08-02. Decomposes the headline **INV-SERVE**. The inbound serving path is the largest
attack surface BraiNIX controls, and these invariants are what make multi-client serving defensible.

## INV-SERVE-001 — A client cannot name another client's objects
No session capability may reference another session's state, KV partition, or weights view. Cross-naming is not merely rejected at use time — it is unrepresentable, because the capability was never granted.

**Why it matters:** Cross-tenant breach is the primary failure this design exists to prevent. Rejecting at use time leaves the reference existing; not granting it leaves nothing to reject.

**Enforcement directions:**
- per-client capability set frozen at session grant
- KV partitions disjoint by construction, not by bookkeeping
- two-concurrent-session integration test asserting denial

---

## INV-SERVE-002 — No allocation is ever driven by client-supplied sizes
A length, count, or offset arriving from a client may be used to *validate* against a fixed bound. It may never be used to size an allocation, extend a pool, or select a growth factor.

**Why it matters:** This is the mechanism that converts a remote memory-exhaustion attack into a bounded capacity limit. It is also the single easiest invariant to violate accidentally in parser code.

---

## INV-SERVE-003 — Admission is bounded per client
`servd` enforces per-client admission limits on concurrent sessions and in-flight requests.

**Why it matters:** Fixed pools convert client-driven memory DoS into *capacity* exhaustion. That is the correct security trade, but it is a genuine availability loss: without per-client limits, one client can consume the whole fixed pool and deny every other client. Admission limits are load-bearing, not a nicety.

---

## INV-SERVE-004 — Session teardown is complete
Ending a session releases its capabilities, zeroizes its KV partition, and removes its session-table row. No residue may be observable by the next occupant of that partition.

**Why it matters:** Cross-tenant leakage through reused KV memory would defeat INV-SERVE-001 without ever violating it directly. **Related:** INV-MEM-006, INV-OBJ-002.

---

## INV-SERVE-005 — Serving state is observable to the auditor and to no one else
Connection, authentication, capability-grant, and request/response boundary events are visible to `auditd`. Visibility grants no authority — see §9.

---

## INV-SERVE-006 — GPU residency is single-tenant, and weights are the only permanent mapping
Where an accelerator serves inference, the mapping policy into its IOMMU window is fixed:

- **Model weights are mapped read-only and permanently.** They are not client data, and there is nothing
  to unmap between sessions.
- **KV cache is mapped strictly per session** — mapped on session entry, unmapped and flushed on exit.
- **Never two tenants resident simultaneously.** The GPU time-slices between clients; one session's KV
  mapping is gone before the next session's is installed.
- **Cross-tenant batching is forbidden**, whatever throughput it would buy.

**Why it matters:** This is what keeps INV-SERVE intact with an accelerator in the path — isolation on the
GPU is the same isolation as everywhere else, paid for in throughput rather than in invariants, so no
INV-SERVE exception is needed. The cost is real and is stated rather than softened: the GPU's payoff
shrinks to prefill acceleration plus time-sliced multi-client serving, because the batching that would
make it a large concurrency win is exactly what this invariant forbids.

**Enforcement directions:**
- residency is a single-slot state in `gpud`: installing a KV mapping requires the previous one to be torn down first
- weights are mapped without write permission at bring-up and the mapping is never re-issued per session
- unmap-and-flush is part of session teardown (INV-SERVE-004), not a separate best-effort step
- no dispatch path exists that can place two sessions' tensors in one batch

**Related:** INV-SERVE-004, INV-DEV-004, INV-DEV-006, and TCB-AS/GPU precondition 4 in
[`../NORTH_STAR.md`](../NORTH_STAR.md). Introduced 2026-08-02 with the GPU tenant-mapping decision.

---

# 14. Model Confinement Invariants

Introduced 2026-08-02. Decomposes the headline **INV-MODEL**. The served model is central to the product
and central to nothing in the TCB's authority.

## INV-MODEL-001 — The model's capability set is exactly three things
`inferd` holds `{Model, its serving endpoint, its own KV slice}`. Not spawn. Not kernel mutation. Not network. Not another session. The manifest is frozen at launch.

**Why it matters:** Confinement must be **structural, not behavioral**. The model physically cannot name a capability it was not granted, so no prompt — however sophisticated — can cause it to use one. Confinement that depended on the model's judgment would be no confinement at all.

**Evidence:** manifest audit; the diff must show zero capabilities beyond the three.

### The `modeld` manifest — the principal that holds what `inferd` must not

*(Specified 2026-08-03 by owner decision. **This is not a new invariant** — it introduces no identifier and
adds no rule. It records the manifest that makes `INV-MODEL-001` and `INV-MODEL-002` satisfiable at the
same time. **`modeld` does not exist**: it is planned as ROADMAP P3-T3a and specified in
[`../architecture/BXW1-weight-format.md`](../architecture/BXW1-weight-format.md) §10.0.)*

`INV-MODEL-001` grants `inferd` three capabilities and none of them is storage, so `inferd` structurally
cannot read the weight blob. Some principal must, and it is to be **`modeld`**: a one-shot server that
runs **before `inferd` launches**, verifies the blob's signature and every per-tensor digest, populates
`WEIGHTS_REGION`, seals it read-only, and **exits**.

Its manifest is to be exactly three capabilities, frozen at launch:

| Capability | Why it is necessary |
|---|---|
| `CapEndpoint` to the storage server (`devd-ans2`) | The blob and the tokenizer vocabulary blob are read from storage. This is precisely the authority `INV-MODEL-001` withholds from `inferd`. |
| `CapMemory` over `WEIGHTS_REGION` — **writable, never executable** | The region must be written before it can be sealed. Held **exclusively** while writable (`INV-MEM-005`); W^X applies with no exception (`INV-MEM-003`). |
| `CapEndpoint` to `auditd`, send-only | One attributable event per load attempt (`INV-AUD-001`, `INV-SERVE-005`), carrying no weight bytes. |

And **not**: `CapServe`, `CapModel`, `CapAdmin`, any network capability, any spawn authority, any session
or KV slice. `modeld` accepts no connection, is unreachable from any client session, and cannot release a
seal — unsealing belongs to the kernel and to a generation that has been destroyed.

**Lifetime is half of the confinement.** Because `modeld` exits before the first request is served, the
storage capability and the writable-weights capability exist in **no running process** while the system is
serving.

**The rejected alternative, recorded so it is not re-proposed as new.** Granting `inferd` a fourth
capability so it could read the blob itself was rejected: it degrades `INV-MODEL-001` — a named invariant
whose entire content is the number three — and would require written owner sign-off in
[`../NORTH_STAR.md`](../NORTH_STAR.md)'s exceptions ledger. It also widens the wrong component. `inferd` is
long-lived, reachable through `servd`, and adversarially prompted by design, so storage authority in its
manifest would be reachable for the life of the system by exactly the party `INV-MODEL-001` exists to
contain. A separate principal, bounded in **scope** and in **lifetime**, is the capability-native answer.

**Evidence:** manifest audit, twice — `modeld`'s diff shows exactly the three capabilities above, and
`inferd`'s diff is unchanged at three. `modeld`'s proof tier is in §16.

---

## INV-MODEL-002 — Weights are integrity-checked before first use
The BXW1 loader verifies a per-tensor digest against a known value before any weight byte is used, and fails closed on a malformed, truncated, or oversized blob.

**Anchoring, stated plainly (2026-08-03):** the digest is anchored **only** to the self-reported software measurement log. It detects corruption and accidental substitution; it does **not** detect an attacker who already controls the kernel (`INV-BOOT-AS-002`). There is no hardware quote to anchor it to and no platform on which there would be.

**Planned, not built (2026-08-03 owner decision):** the weights are to become a **separately signed artifact** — their own Ed25519 signature over the whole-blob digest, verified by the existing verify-only stack before the region is sealed ([`../architecture/BXW1-weight-format.md`](../architecture/BXW1-weight-format.md) §9.2, [`../operations/RELEASE_AND_SIGNING_POLICY.md`](../operations/RELEASE_AND_SIGNING_POLICY.md) §11). They are deliberately **not** folded into the release signature: that would make the published kernel image model-specific and weaken INV-BOOT's reproducible-build clause, the one clause that still holds in full on the only platform. The two signatures are independent — compromise of one does not imply the other. **Nothing signs or verifies a weight blob today**, and the sentence above about anchoring is the current state.

---

## INV-MODEL-003 — Model output is untrusted input everywhere it lands
Tokens the model emits are hostile bytes. Any consumer — operator console, log, audit record, or serving response framing — treats them as such. In particular, no consumer interprets in-band control sequences from model output.

**Why it matters:** The model is the one component that is simultaneously inside the system and adversary-influenced by design.

---

## INV-MODEL-004 — Confinement is tested adversarially, not asserted
A prompt-injection corpus is run as a CI regression bar. The passing condition is **zero escalations under any input**, not a rate.

**Why it matters:** "Every claim is falsifiable." An asserted confinement with no adversarial test is not enforced.

---

# 15. Hostile-Input Parser Invariants

Introduced 2026-08-02. Not a headline invariant — a discipline that INV-SERVE, INV-MODEL, and INV-MEM
jointly impose. Listed separately because it is the most frequently violated rule in the tree and the
easiest to check in review.

## INV-PARSE-001 — Every parser of foreign data is `no_std`, zero-allocation, and fail-closed
"Foreign data" means anything the project did not produce: network bytes, disk bytes, device responses, **and firmware-supplied structures**. Every offset, length, and count is bounds-checked against its containing region. Malformed input denies the operation; it never proceeds best-effort.

## INV-PARSE-002 — Every such parser ships a fuzz target *and* a Kani harness
Both. A fuzz target finds what the harness did not model; a harness proves what fuzzing cannot exhaust. One without the other does not satisfy the **Full tier** gate in §16, which replaces the uniform per-component gate previously stated in [`../ROADMAP.md`](../ROADMAP.md).

The set, current and planned:

| Parser | Input source | Task |
|---|---|---|
| BSP request decoder | Remote clients | P2-T3 |
| Transport handshake FSM | Remote clients | P2-T2 |
| BXW1 weight loader | Disk | P3-T3 |
| Tokenizer vocab blob | Disk | P3-T5 |
| **Apple Device Tree** | **Firmware** | **AS-0** |
| **boot-args structure** | **Firmware** | **AS-0-T4** |
| GPU completion parser | Device | **AS-5-T3** *(Phase 5 was the discrete-x86-64-GPU phase and is cancelled with that platform; the AGX parser is the one that ships)* |

## INV-PARSE-003 — Firmware-supplied data is hostile input
The Apple Device Tree and boot-args come from software we did not write, cannot audit, and cannot replace, and they are parsed **earlier and with more authority** than anything from the network. They receive exactly the treatment network bytes receive.

**Why it matters:** Intuition resists this — firmware feels like part of the machine. On the primary platform it is unaudited third-party code inside our TCB by force (TCB-AS), and its output reaches our most privileged parsing context. An ADT claiming an absurd child count must deny, not allocate.

## INV-PARSE-004 — Disagreeing sources fail the boot closed
Where two firmware sources describe the same fact — boot-args and the ADT both reporting memory ranges — disagreement halts the boot. There is no precedence rule, because picking a winner means trusting one unaudited source over another.

---

# 16. Proof Tier Assignment

Introduced 2026-08-02 by owner decision. **The proof gate is tiered by TCB proximity**, replacing the
uniform per-component gate that demanded the same six artifacts from every component regardless of what a
compromise of it could reach.

- **Full tier — all ~~six~~ five artifacts:** invariant mapping, fuzz target, Kani harness,
  ~~Prusti contracts,~~ security audit report, and no-regression bars.
- **Reduced tier — tests and a security audit report only.** No Kani~~, no Prusti~~.

> **Prusti was removed from the artifact list on 2026-08-12** (owner decision), reducing Full tier from
> six artifacts to five. Recorded rather than silently edited, because this is a signed criterion and the
> count is quoted elsewhere.
>
> **Why.** The single Prusti artifact in the tree, `src/brainix-ipc-core/`, had **never executed**, and
> could not have: its annotations gated on `feature = "prusti"` while its manifest declared no
> `[features]` section, and the CI action required a `prusti-contracts` dependency that was deliberately
> absent. Beyond that it verified a **hand-written copy** of three IPC ideas that nothing in the tree
> depended on and the kernel never called, and the copy's contracts were **tautologies** — each of the
> form *"a function that returns `Ok` exactly when P holds, returns `Ok` only when P holds"*, true by
> construction and independent of what the kernel does.
>
> So no Full-tier component has ever satisfied this artifact, and the list asserted otherwise. Prusti also
> cannot target the real `no_std` kernel paths, which is why the shim existed at all.
>
> **What replaced it.** `src/ipc-verify/`, five Kani harnesses over the **real** `perform_rendezvous`
> covering INV-IPC-002, INV-IPC-005, and INV-AUTH-003. Kani already verifies real kernel code elsewhere in
> this tree, so the obligation moved to a tool that demonstrably works here rather than being dropped.
>
> **What is now openly uncovered:** INV-IPC-003's blocking, queueing, and timeout-rollback paths.
> `perform_rendezvous` is the transfer step and never blocks, so those remain covered by unit tests only.
> That gap was previously masked by the claim that Prusti covered it.

**The rule.** Full tier covers the TCB, every parser of hostile input, and all crypto. Reduced tier covers
capability-bounded servers whose compromise is contained by the capability model. The justification is the
project's own principle: **IOMMU confinement, not driver correctness, is the control.** Proof effort moves
to the confinement, because a proof that no consumer can widen a DMA window (`INV-DEV-006`) buys more
assurance than a proof of any single driver — it holds for every driver, including the ones not written
yet.

Three corollaries decide the arguable cases:

- **A hostile-input parser is Full tier wherever it lives.** Confinement bounds what a compromised
  component can *reach*; it does not make a parser's bugs safe. A Full-tier parser inside a Reduced-tier
  server does not inherit the server's tier. Every Reduced-tier row below that has such a parser says so.
- **A proof's tier follows the thing being proven, not the thing being protected.** The `INV-DEV-006`
  no-widening proof is a Full-tier obligation of the DART backend's IOMMU trait, not of `gpud`.
- **An artifact that cannot be produced is a stated gap, never a downgrade.** Components are tiered by
  the risk they carry, not by the assurance that is convenient to produce for them — vendored code
  included. Where a Full-tier component cannot ship one of the six artifacts, its row names the missing
  artifact and the reason. There is no third tier for "Full but hard," because an omission is
  unfalsifiable and a named gap is not.

**This is a rule, not a per-component judgment call.** Tier is read off the table below at design time. The
table itself is audited at each phase gate; moving a component between tiers is an edit to this document
with owner sign-off, never a decision taken while implementing. Components not yet written are listed at
their planned tier — the tier is fixed before the code is, which is the point. A component absent from the
table is not thereby Reduced tier; it is **unassessed**, and assessing it is a phase-gate obligation.

| Component | Tier | Why |
|---|---|---|
| Kernel core | **Full** | TCB. Nothing contains it; a compromise is unbounded by definition. |
| Capability subsystem | **Full** | TCB, and it *is* the containment every Reduced-tier assignment below relies on. |
| IPC | **Full** | TCB. The only authorized channel between domains and the place rights transfer (`INV-IPC-002`). |
| Context switch | **Full** | TCB. An error here leaks register and address-space state across every boundary at once. |
| ~~HAL MMU~~ → **aarch64 MMU** | **Full** | TCB. W^X and kernel/user separation are its output (`INV-MEM-003`, `INV-MEM-009`). *Renamed 2026-08-03: the HAL is cancelled, so the obligation attaches to the aarch64 MMU directly. Tier, obligation, and artifacts are unchanged — only the home is.* |
| ~~HAL IOMMU~~ → **DART backend / its IOMMU trait** | **Full** | TCB, and the confinement the Reduced tier is justified by. Carries the `INV-DEV-006` no-widening proof. *Renamed 2026-08-03 for the same reason; the proof is unchanged and remains an obligation of the confinement, not of `gpud`.* |
| x86-64 arch code (`arch/x86_64*`, `e1000`, `virtio_blk`, `pci`, the x86 boot path) | *(unassessed — frozen reference)* | **Frozen reference, not scheduled** (2026-08-03). It stays in tree and keeps building as the implementation the aarch64 port is read against, and no release or assurance claim rests on it. It is deliberately **not** assigned a tier: assigning one would imply scheduled proof work, and assessing it is not a phase-gate obligation because nothing ships from it. It is deleted when aarch64 replaces it. |
| In-kernel SQL engine (TCB-EXCEPTION-001) | **Full** | TCB by exception — ring 0, kernel address space — and it parses attacker-controlled B-tree and WAL pages *inside* the TCB. The size of the resulting Full-tier obligation is part of what that exception costs, and is one more reason the P2-T7 reframing is the point to re-examine ring-0 residency. |
| Crypto primitives (SHA-256, HKDF, ChaCha20, Poly1305) | **Full** | Handle key material; a silent defect still produces plausible output, so tests alone cannot find it. |
| Ed25519 verification stack (`ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle`) | **Full** | Crypto, and it decides whether a **forged release signature** is accepted — INV-BOOT's trust anchor. Assigned by risk, not by producibility: as permanently vendored code it can carry the invariant mapping, a fuzz target on the verify entry point, an audit report, and no-regression bars, but **Kani and Prusti cannot be produced for it** — the code is not ours to annotate and the group-operation and verification-equation layers are beyond harness scope. `fiat-crypto`'s field arithmetic is machine-verified upstream against a formal specification, which covers the field layer only; above it the gap is real and is stated rather than tiered away. |
| Credential store | **Full** | In-kernel and holds every client and admin secret (`INV-BOOT-006..008`, `INV-BUILD-004`). |
| Transport handshake FSM and record layer | **Full** | Parses remote bytes *before* the peer is authenticated — the earliest hostile-input surface in the serving path. |
| BSP request parser | **Full** | Hostile input from remote clients (`INV-PARSE-001`). |
| ADT parser | **Full** | Hostile input from firmware, parsed earlier and with more authority than anything from the network (`INV-PARSE-003`). |
| boot-args parser | **Full** | Same firmware source, same reasoning, same treatment. |
| BXW1 weight loader | **Full** | Hostile input from disk, and the integrity gate for the weights themselves (`INV-MODEL-002`). |
| `modeld` | **Full** | *(Assigned 2026-08-03, before the code exists — which is the point of this table.)* The server that hosts the BXW1 loader above, so the parser's tier is its host's floor by the first corollary. It is Full tier in its own right as well: it is the only principal holding storage authority and a **writable** `WEIGHTS_REGION` capability, so a compromise between the copy and the seal substitutes the model every session then reads, and the confinement that justifies a Reduced tier elsewhere is exactly what it is outside of. Bounded lifetime shortens the window; it does not shrink the blast radius. |
| Tokenizer vocab parser | **Full** | Hostile input from disk, consumed before any request is served. |
| GPU completion-record parser | **Full** | Written by Apple's opaque GPU firmware, which the north star treats as hostile; TCB-AS/GPU precondition 3. |
| RTKit mailbox | **Full** | Arguable, since it sits inside a confined driver — but it parses firmware-supplied message and endpoint structures, and the parser's tier wins over its host's. |
| `servd` | **Full** | Arguable, since it is an ordinary userspace server — but it terminates the transport, holds session keys, and *mints* every per-session capability, so its compromise crosses all tenants at once and nothing above it contains that. |
| `inferd` | Reduced | The archetypal confined tenant: exactly three capabilities, frozen at launch (`INV-MODEL-001`). Its embedded BXW1 and tokenizer parsers are Full tier in their own right. |
| `auditd` | Reduced | Holds no spawn, kernel-mutation, or network capability; its compromise costs visibility, never privilege (`INV-AUD-002`). It stores model-derived and client-derived bytes but interprets none of them (`INV-MODEL-003`), so it owns no parser. |
| `devd-nic` | Reduced | Capability-bounded, DMA confined by the IOMMU. Any hostile-input parser it embeds is Full tier separately. |
| `devd-ans2` | Reduced | Same containment: a compromised storage server reaches only its own IOMMU window. Its device-response decoders are the NVMe driver's, tiered in the row below. |
| ANS2 NVMe driver | Reduced | Arguable, since it drives DMA — but that DMA is exactly what `INV-DEV-006` confines, and that proof is Full tier. Its decoders for device responses — completion queue entries, identify structures — are hostile-input parsers (`INV-PARSE-001`) and are Full tier separately. |
| `gpud` | Reduced | Confining the GPU is DART's job (TCB-AS/GPU precondition 2), not the driver's. Proving `gpud` correct instead of proving the confinement would invert the rule. Both parsers it hosts — GPU completion records and the RTKit mailbox — are Full tier in the rows above. |
| PCIe driver | Reduced | Capability-bounded; enumeration and config-space access are bounded by the granted window. Its config-space and capability-chain walkers are hostile-input parsers and are Full tier separately — a malicious device can present a cyclic capability list, and the walker must terminate and deny rather than loop. |


> **2026-08-13 — a Kani harness exists is not a Kani harness runs.** Recorded here rather than silently
> edited, because §15's `INV-PARSE-002` and the Full-tier artifact list above are both read as claims
> about what CI enforces.
>
> Measured on an M2 Pro with a 700-second cap per harness, **eight harnesses across two Full-tier
> components return no verdict**: in `adt-verify`, the two over the 96-byte nested blob
> (`adt_traversal_terminates_on_all_inputs`, `adt_path_resolution_never_panics_on_an_arbitrary_path`);
> in `transport-crypto-verify`, the three record harnesses over `open`/`seal` and the three ratchet
> harnesses that run an advance. They are the harnesses that drive a hash, an AEAD, or a 96-byte
> symbolic buffer, and Kani's cost on those is dominated by symbolic execution rather than by the
> unwind bound, so tightening the bound does not reach them.
>
> Each is now behind a `long-proofs` cargo feature, off by default, so CI runs the proofs that finish
> — five in `adt-verify`, four in `transport-crypto-verify`, plus the BSP, IPC and capability sets in
> full. The excluded harnesses stay in the tree, with their measurements, and are run deliberately with
> a budget.
>
> **The gap, stated as a gap:** no proof of the ADT child iterator, the depth counter, path resolution,
> or of `RecordOpener::open` and `RecordSealer::seal` runs on a pull request. Those paths are held by
> tests, RFC known-answer vectors and fuzz targets until the cost problem is solved. This is the same
> ruling the Prusti note above applies -- an artifact that cannot be produced is a stated gap, never a
> downgrade -- extended to an artifact that exists but cannot be *run*.

---

# Traceability Guidance

Each subsystem specification should include an “invariant impact” section naming the invariants it must preserve.

Example:

- Memory allocator changes → INV-MEM-005, INV-MEM-006, INV-MEM-009, INV-SCHED-004
- Capability subsystem changes → INV-AUTH-002, 003, 004, 005 and INV-OBJ-002
- New device support → INV-DEV-001..006 and INV-X86-006 / INV-ARM-005 where DMA or interrupt mapping is involved
- Serving path changes → INV-SERVE-001..006, INV-PARSE-001, 002
- Inference engine changes → INV-MODEL-001..004, INV-MEM-009
- Apple Silicon platform work → INV-ARM-001..005, INV-PARSE-003, 004, INV-DEV-004, 005
- Anything touching boot or release → INV-BOOT-001..008, INV-BOOT-AS-001..003, INV-BUILD-001..004
- Key handling, enrollment, or the admin channel → INV-AUTH-009, INV-BOOT-006..008, INV-BUILD-004

---

# Unsafe Review Template

Every unsafe module should carry a review block similar to this:

## Module
`module_name`

## Unsafe purpose
Why unsafe is required here.

## Trusted assumptions
What must already be true for this unsafe block/module to remain sound.

## Aliasing/ownership rules
What references or memory regions may coexist.

## Concurrency rules
What synchronization or preemption rules are assumed.

## Failure mode
What happens if assumptions are violated.

## Related invariants
Which invariants this code helps preserve or could violate.

## Evidence
Tests, fuzzing, model checking, or manual review performed.

---

# Final Rule

BraiNIX security is not defined by “Rust,” “microkernel,” “formal methods,” or “platform hardening” in isolation. It is defined by whether these invariants remain true under attack, under failure, and under future feature growth.

If an invariant is weakened, security is weakened, even if the code still compiles and the system still boots.

Two corollaries, added 2026-08-02:

**A weakened invariant is written down or it is a lie.** The Apple-primary decision cost real assurance — remote attestation and sealing are gone. That was recorded as INV-BOOT/AS with owner sign-off, restated in §7, and guarded by INV-BOOT-AS-001..003. **On 2026-08-03 the single-platform decision removed the last hedge:** the exception became the rule, the credential store became unconditionally plaintext at rest, and the sentence "deployments that need attestation run x86-64" was deleted rather than repointed, because that platform no longer exists. The failure mode this discipline prevents is not the loss itself; it is the loss being quietly forgotten and BraiNIX later described as though it could attest. It cannot, and it never will.

**Serving inverted the threat picture, and the invariants moved with it.** BraiNIX now accepts connections from hostile remote clients and runs a model that adversaries prompt directly. §13, §14, and §15 exist because the old invariant set — written for an internal-only microkernel — did not cover any of that. An invariant set that lags the system's actual attack surface provides confidence, not security.