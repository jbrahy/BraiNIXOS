# BraiNIX Security Invariants

**Status:** Mandatory · **Reconciled:** 2026-08-02 (serving pivot + Apple-primary platform decision)

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
| **INV-AUTH** | §1 `INV-AUTH-001..008`, §3 `INV-OBJ-002`, §12 `INV-FAIL-002` |
| **INV-MEM** | §2 `INV-MEM-001..009`, §5 `INV-SCHED-004` |
| **INV-IPC** | §4 `INV-IPC-001..006` |
| **INV-BOOT** | §7 `INV-BOOT-001..005`, **`INV-BOOT-AS-001..003`**, §11 `INV-BUILD-001..003` |
| **INV-SERVE** | **§13 `INV-SERVE-001..005`**, **§15 `INV-PARSE-001..004`** |
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
| **INV-BOOT/AS** | Apple Silicon | 2026-08-02 | Measurement, remote attestation, and sealing are structurally unavailable. See §7. |
| **TCB-AS** | Apple Silicon | 2026-08-02 | SecureROM, iBoot1, iBoot2, sepOS are in the TCB by force — closed, unauditable, unremovable. |
| **TCB-EXCEPTION-001** | All platforms | 2026-06-27 | Relational SQL engine in ring 0. See [`TCB_EXCEPTION_001_IN_KERNEL_SQL.md`](TCB_EXCEPTION_001_IN_KERNEL_SQL.md). |

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

## INV-MEM-009 — Page size is a HAL parameter, never an assumption
No memory code outside the HAL may assume a specific base page size. Apple Silicon uses **16 KiB** base pages; x86-64 uses **4 KiB**. Region sizing, alignment, guard-page placement, and W^X granularity must all derive from the HAL's page-size constant.

**Why it matters:** A hardcoded 4 KiB that reaches the primary platform does not fail loudly — it silently misaligns reserved regions, misplaces guard pages, and can make W^X enforcement coarser than intended. That is an isolation failure wearing the costume of a portability bug.

**Enforcement directions:**
- page size exposed once, from `hal/mmu.rs`; no literal `4096` in architecture-neutral memory code
- grep-gate against bare page-size literals outside `arch/` and `hal/`
- `WEIGHTS_REGION` and `KV_REGION` sizing expressed in pages, not bytes
- MMU and reserved-region code tested at both page sizes (QEMU `virt` at 4 KiB, Apple at 16 KiB)

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

Platform-specific invariants are stated per architecture. **Both supported platforms must satisfy the
equivalent property**; only the mechanism differs. A property available on one platform and absent on the
other is a named exception (see §7), not a silent asymmetry.

| Property | x86-64 mechanism | aarch64 / Apple mechanism |
|---|---|---|
| Kernel cannot execute user code | SMEP | PXN |
| Kernel cannot implicitly read/write user memory | SMAP | PAN |
| Control-flow integrity | IBT / ENDBR64 | PAC / BTI |
| Hardware entropy | RDRAND | RNDR |
| No-execute mapping | NX bit | XN / UXN |
| IOMMU | VT-d | **DART** (many instances — see §8) |
| Interrupt controller | APIC | **AIC** (FIQ split — see `INV-ARM-005`) |

## 6a. x86-64

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

**Why it matters:** These discharge the same obligations as `INV-X86-002` and `INV-X86-003` on the primary platform. Missing them means the primary platform is *weaker* than the secondary one.

---

## INV-ARM-003 — PAC/BTI control-flow integrity is enabled where available
Pointer authentication and branch-target identification are enabled on cores that implement them, discharging the obligation `INV-X86-004` covers via IBT/ENDBR64.

---

## INV-ARM-004 — Entropy comes from RNDR with an explicit failure path
`RNDR`/`RNDRRS` may legitimately fail. A failed read is an explicit error that blocks cryptographic operation start (`INV-BOOT-005`), never a silent fallback to a weaker source.

---

## INV-ARM-005 — Interrupt-controller abstraction survives the AIC's shape
The `hal/interrupts` trait must express the Apple Interrupt Controller honestly rather than forcing it into a GIC-shaped API:

- a single packed **event word** read replaces the GIC ack/EOI register pair
- per-CPU timers and some other sources arrive as **FIQ**, entirely outside the controller — the trait needs a notion of CPU-local sources the controller does not own
- IPIs go through implementation-defined system registers, not a controller doorbell
- the AIC revision is selected from ADT compatible strings at runtime, and an **unknown string fails closed**

**Why it matters:** An interrupt abstraction that quietly assumes "all interrupts flow through the controller" will mis-handle the FIQ timer path on the primary platform — and timer handling is where scheduler and liveness invariants are enforced.

---

# 7. Boot and Attestation Invariants

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

## Apple Silicon: INV-BOOT/AS

The exception is recorded in [`../NORTH_STAR.md`](../NORTH_STAR.md); these are its enforcement
consequences. **This is the primary platform**, so these are not edge cases — they describe the assurance
level of the shipping product.

## INV-BOOT-AS-001 — Attestation claims are forbidden on Apple Silicon
No BraiNIX component, release note, log line, protocol field, or document may assert remote attestation, sealing, or hardware-anchored measurement on Apple Silicon. There is no TPM, and the Secure Enclave exposes no PCR-style extend/quote/seal interface to third-party software.

**Why it matters:** A false attestation claim is worse than no attestation, because a client will rely on it. This invariant is the guard against the strongest temptation created by the 2026-08-02 decision.

**Enforcement directions:**
- the BSP protocol must not offer an attestation field the primary platform cannot populate honestly
- grep-gate on attestation vocabulary in Apple Silicon code paths
- release notes for Apple Silicon builds state the degradation explicitly

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

# 14. Model Confinement Invariants

Introduced 2026-08-02. Decomposes the headline **INV-MODEL**. The served model is central to the product
and central to nothing in the TCB's authority.

## INV-MODEL-001 — The model's capability set is exactly three things
`inferd` holds `{Model, its serving endpoint, its own KV slice}`. Not spawn. Not kernel mutation. Not network. Not another session. The manifest is frozen at launch.

**Why it matters:** Confinement must be **structural, not behavioral**. The model physically cannot name a capability it was not granted, so no prompt — however sophisticated — can cause it to use one. Confinement that depended on the model's judgment would be no confinement at all.

**Evidence:** manifest audit; the diff must show zero capabilities beyond the three.

---

## INV-MODEL-002 — Weights are integrity-checked before first use
The BXW1 loader verifies a per-tensor digest against a known value before any weight byte is used, and fails closed on a malformed, truncated, or oversized blob.

**Platform note:** on x86-64 the digest is anchored to a hardware quote. On Apple Silicon it is anchored only to the software measurement log, so it detects corruption and accidental substitution but **not** an attacker who already controls the kernel (`INV-BOOT-AS-002`).

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
Both. A fuzz target finds what the harness did not model; a harness proves what fuzzing cannot exhaust. One without the other does not satisfy the per-component gate in [`../ROADMAP.md`](../ROADMAP.md).

The set, current and planned:

| Parser | Input source | Task |
|---|---|---|
| BSP request decoder | Remote clients | P2-T3 |
| Transport handshake FSM | Remote clients | P2-T2 |
| BXW1 weight loader | Disk | P3-T3 |
| Tokenizer vocab blob | Disk | P3-T5 |
| **Apple Device Tree** | **Firmware** | **AS-0** |
| **boot-args structure** | **Firmware** | **AS-0-T4** |
| GPU completion parser | Device | Phase 5 (deferred) |

## INV-PARSE-003 — Firmware-supplied data is hostile input
The Apple Device Tree and boot-args come from software we did not write, cannot audit, and cannot replace, and they are parsed **earlier and with more authority** than anything from the network. They receive exactly the treatment network bytes receive.

**Why it matters:** Intuition resists this — firmware feels like part of the machine. On the primary platform it is unaudited third-party code inside our TCB by force (TCB-AS), and its output reaches our most privileged parsing context. An ADT claiming an absurd child count must deny, not allocate.

## INV-PARSE-004 — Disagreeing sources fail the boot closed
Where two firmware sources describe the same fact — boot-args and the ADT both reporting memory ranges — disagreement halts the boot. There is no precedence rule, because picking a winner means trusting one unaudited source over another.

---

# Traceability Guidance

Each subsystem specification should include an “invariant impact” section naming the invariants it must preserve.

Example:

- Memory allocator changes → INV-MEM-005, INV-MEM-006, INV-MEM-009, INV-SCHED-004
- Capability subsystem changes → INV-AUTH-002, 003, 004, 005 and INV-OBJ-002
- New device support → INV-DEV-001..006 and INV-X86-006 / INV-ARM-005 where DMA or interrupt mapping is involved
- Serving path changes → INV-SERVE-001..005, INV-PARSE-001, 002
- Inference engine changes → INV-MODEL-001..004, INV-MEM-009
- Apple Silicon platform work → INV-ARM-001..005, INV-PARSE-003, 004, INV-DEV-004, 005
- Anything touching boot or release → INV-BOOT-001..005, INV-BOOT-AS-001..003, INV-BUILD-001..003

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

**A weakened invariant is written down or it is a lie.** The Apple-primary decision cost real assurance — remote attestation and sealing are gone on the platform the product ships on. That is recorded as INV-BOOT/AS with owner sign-off, restated in §7, and guarded by INV-BOOT-AS-001..003. The failure mode this discipline prevents is not the loss itself; it is the loss being quietly forgotten and the platform later described as though it were attested.

**Serving inverted the threat picture, and the invariants moved with it.** BraiNIX now accepts connections from hostile remote clients and runs a model that adversaries prompt directly. §13, §14, and §15 exist because the old invariant set — written for an internal-only microkernel — did not cover any of that. An invariant set that lags the system's actual attack surface provides confidence, not security.