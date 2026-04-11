# Brainix Security Invariants

## Purpose

This document defines the security invariants Brainix must preserve at all times. These invariants are the backbone of the system's security model.

A feature is acceptable only if it preserves existing invariants or introduces a new invariant with explicit enforcement and evidence strategy.

An implementation detail, performance optimization, compatibility feature, or convenience abstraction must never silently weaken an invariant.

---

## How to Use This Document

This document should be used in four ways:

1. **Design gate** — every new subsystem or feature must identify which invariants it touches.
2. **Code review lens** — every security-critical change should be reviewed against relevant invariants.
3. **Testing traceability map** — every invariant should eventually map to tests, fuzz targets, audits, or proof work.
4. **Claim discipline** — no one should describe Brainix as “secure” in the abstract. They should refer to preserved invariants.

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

## Invariant Categories

The invariants are grouped into the following categories:

- authority and capability invariants
- memory and mapping invariants
- object lifecycle invariants
- IPC and liveness invariants
- scheduler and resource invariants
- x86 platform and execution invariants
- boot and attestation invariants
- device isolation invariants
- audit and observability invariants
- unsafe code and assurance invariants
- build and release invariants
- failure and recovery invariants

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

# 6. x86 Platform and Execution Invariants

## INV-X86-001 — Only supported x86-64 execution modes are used
Brainix operates only in documented 64-bit modes and does not depend on legacy mode behavior beyond controlled bootstrap transitions.

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
The ability to publish trusted Brainix artifacts must be limited and auditable.

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

# Traceability Guidance

Each subsystem specification should include an “invariant impact” section naming the invariants it must preserve.

Example:

- Memory allocator changes → INV-MEM-005, INV-MEM-006, INV-SCHED-004
- Capability subsystem changes → INV-AUTH-002, 003, 004, 005 and INV-OBJ-002
- New device support → INV-DEV-001, 002, 003 and INV-X86-006 where DMA or interrupt mapping is involved

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

Brainix security is not defined by “Rust,” “microkernel,” “formal methods,” or “x86 hardening” in isolation. It is defined by whether these invariants remain true under attack, under failure, and under future feature growth.

If an invariant is weakened, security is weakened, even if the code still compiles and the system still boots.