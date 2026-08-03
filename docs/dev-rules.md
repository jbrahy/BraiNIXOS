> # ⛔ SUPERSEDED — do not use as guidance
>
> **Superseded by [`../PROJECT_RULES.md`](../PROJECT_RULES.md) on 2026-08-02.**
>
> This is a near-duplicate copy of the project rules — note that its own first heading says
> `PROJECT_RULES.md`. Two copies of the mandatory rules is precisely the drift this reconciliation
> exists to remove. The root [`PROJECT_RULES.md`](../PROJECT_RULES.md) is authoritative and current;
> this copy is from 2026-04-14 and predates both the serving pivot and the Apple-primary decision.
>
> Retained unedited as a historical record. See [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md).

---

# BraiNIX Project Rules *(historical — superseded)*
## Non-Negotiable Rules for an Ultra-Secure x86-64 Microkernel System

Version: 1.0  
Status: Mandatory  
Applies To: Architecture, kernel code, userspace services, build pipeline, CI, deployment, documentation, verification, and operational governance

---

## 1. Purpose

This document defines the mandatory rules that govern the BraiNIX project.

These rules exist to maximize practical security for a high-assurance x86-64 microkernel operating system written in Rust. They are not suggestions, preferences, or aspirational guidelines. They are project-level constraints that must be followed unless a rule is explicitly replaced by a stricter one.

No engineering convenience, compatibility target, schedule pressure, or short-term implementation shortcut may override these rules without an explicit documented security exception approved at the project-governance level.

---

## 2. Interpretation Rules

The following words have strict meaning in this document:

- **Must** means required with no silent exceptions.
- **Must not** means prohibited.
- **Should** means expected by default and may be deviated from only with written justification.
- **May** means allowed if it does not violate a stronger rule.
- **Trusted Computing Base (TCB)** means all components that must behave correctly for a stated security guarantee to hold.
- **Development mode** means QEMU, containerized, emulated, CI, or otherwise non-production execution.
- **Production mode** means supported bare-metal x86-64 execution with the required hardware and verified boot assumptions.
- **Security domain** means a unit of isolation whose compromise must not automatically compromise another domain.

If any implementation, milestone, or subsystem conflicts with these rules, the rules win.

---

## 3. Core Security Constitution

1. Security must be structural, not probabilistic.
2. The kernel must remain as small as possible.
3. No ambient authority may exist anywhere in the system.
4. Every privilege must be explicit, typed, bounded, and revocable.
5. Compatibility must never outrank security.
6. Complexity must be treated as a vulnerability source.
7. Development-mode guarantees must never be represented as production guarantees.
8. Unsafe code must be minimized, isolated, documented, and reviewed as security-critical.
9. All major security claims must map to documented invariants, code, and tests.
10. When uncertainty exists, the system must fail closed.

---

## 4. Foundational Project Rules

### Rule 4.1 — Structural Security Only
Core security guarantees must not depend on secrecy of addresses, hidden implementation details, undocumented behavior, or attacker ignorance.

Defense-in-depth mitigations such as randomization may be used, but they must not be the basis of the primary security model.

### Rule 4.2 — Minimal Trusted Kernel
Only code that absolutely must run in ring 0 may run in ring 0.

Anything that can safely live outside the kernel must be moved into isolated userspace.

### Rule 4.3 — No Ambient Authority
No process, thread, service, or subsystem may gain access to objects or actions through identity, inheritance, global process state, or implicit privilege.

All authority must flow through explicit capabilities or equivalently explicit, typed, auditable authority tokens.

### Rule 4.4 — Security Before Compatibility
POSIX compatibility, legacy Unix semantics, convenience APIs, developer familiarity, and ecosystem expectations must not weaken the capability model, isolation boundaries, or kernel minimalism.

### Rule 4.5 — No Marketing Claims Beyond Proof Scope
The project must not claim equivalence with any formally verified operating system unless it can name the exact proof scope and supporting evidence.

Ambitious goals may be stated as goals, but not as established fact.

---

## 5. Trust Boundary Rules

### Rule 5.1 — TCB Must Be Explicit
The project must maintain a written Trusted Computing Base document.

Every major security claim must identify:
- what is trusted
- what is not trusted
- what assumptions are required
- what breaks the claim

### Rule 5.2 — Development and Production Must Be Separated
Development mode and production mode must be documented as different trust environments.

Development mode may include:
- QEMU
- Docker or other containers
- CI runners
- virtual TPMs
- host operating systems
- emulator device models

These components must not be silently treated as trustworthy in any production-strength security claim.

### Rule 5.3 — Host and Hypervisor Reality Must Be Acknowledged
If BraiNIX runs as a guest, then the host kernel, hypervisor, emulator, and runtime beneath it are part of the effective trust story.

The project must never imply that guest-kernel guarantees are equal to hardware-rooted production guarantees.

### Rule 5.4 — Out-of-Scope Areas Must Be Written Down
Every threat model revision must include an explicit out-of-scope section.

Unstated scope boundaries are prohibited.

---

## 6. Architecture Rules

### Rule 6.1 — x86-64 Only
The secure baseline targets x86-64 only.

No 32-bit support, no legacy compatibility burden, and no architecture expansion may be added until the x86-64 secure baseline is complete and stable.

### Rule 6.2 — Microkernel Discipline
The kernel must only include:
- low-level memory management
- capability enforcement
- scheduling primitives
- interrupt and exception handling
- IPC primitives
- minimal boot-critical mechanisms

Drivers, networking, storage policy, audit consumers, and high-level services must remain out of the kernel unless a documented security review proves kernel residency is necessary.

### Rule 6.3 — No Shared Memory by Default
Control flow between components must use kernel-mediated IPC.

Shared-memory-style data transfer may only be introduced if it is:
- capability-governed
- explicitly bounded
- auditable
- revocable
- documented with ownership and lifetime semantics

There must be no ambient or informal shared memory.

### Rule 6.4 — Small ABI Surface
The syscall surface must remain minimal, stable, typed, and security-reviewed.

No syscall may exist solely for compatibility convenience.

---

## 7. Capability Rules

### Rule 7.1 — Capabilities Are the Only Authority Mechanism
Authority must be represented exclusively through explicit capabilities or equivalently strict typed authority objects.

No hidden privilege channel may exist.

### Rule 7.2 — No Rights Amplification
Transfer, duplication, delegation, derivation, or serialization of authority must never increase rights.

All such operations must be monotonic with respect to authority.

### Rule 7.3 — Revocation Must Be Real
When a capability is revoked, all derived forms, aliases, cached references, and child authorities must become unusable according to the defined revocation semantics.

Revocation must not be cosmetic.

### Rule 7.4 — Slots Must Be Sanitized
Capability slots, metadata, and derived references must be cleared or reset safely on revoke, free, and reuse.

### Rule 7.5 — Capability State Must Be Quota-Controlled
Cap slots, derivation trees, related kernel objects, and associated metadata must be bounded per security domain.

No tenant may allocate authority state without limit.

### Rule 7.6 — Keep the Trusted Core Simple
Advanced authority features that increase semantic complexity, such as temporal capabilities, must not enter the trusted core until the simpler capability model is stable, verified, and clearly justified.

---

## 8. Memory and Isolation Rules

### Rule 8.1 — W^X Is Mandatory
No page may be writable and executable at the same time.

No exception may be introduced for convenience, JIT behavior, tests, or tooling.

### Rule 8.2 — Kernel Memory Must Not Be Exposed to Userspace
Kernel memory must not be directly writable or executable from user contexts.

Kernel mapping policy must prevent casual or broad user visibility into privileged memory.

### Rule 8.3 — Typed Ownership Must Be Enforced
Memory must be tracked by ownership and type.

At minimum, the system must distinguish:
- kernel-owned pages
- user-owned pages
- device/DMA-exposed memory
- IPC/message or loan buffers
- free pages

### Rule 8.4 — No Unbounded Dynamic Kernel Heap
The kernel must avoid general-purpose unbounded heap behavior.

Bounded pools, fixed-size allocators, or equivalent controlled allocation strategies are required.

### Rule 8.5 — Exhaustion Behavior Must Be Defined
Allocation failure, quota exhaustion, and resource saturation must be handled explicitly.

No subsystem may rely on silent fallback, implicit overcommit, or best-effort privileged recovery.

### Rule 8.6 — Sanitize on Reuse
All freed pages, object memory, IPC buffers, stacks, and other sensitive memory must be sanitized before reuse.

### Rule 8.7 — Stack Protection Is Mandatory
Kernel stacks must use guard pages.

Critical fault paths should use separate known-good stacks where architecture support and design require it.

---

## 9. Unsafe Rust and Implementation Rules

### Rule 9.1 — Rust Reduces Risk but Does Not Prove Security
The project must never treat Rust as a substitute for invariants, review, or system design rigor.

### Rule 9.2 — Unsafe Code Must Be Budgeted
Unsafe code is a tracked risk surface.

Unsafe growth must be measured and reviewed as a security event.

### Rule 9.3 — Unsafe Must Be Isolated
Unsafe code must be confined to the smallest practical modules, especially for:
- page tables
- interrupt state
- CPU registers and MSRs
- boot code
- memory-mapped I/O
- FFI boundaries

### Rule 9.4 — Every Unsafe Block Needs a Contract
Each unsafe block must document:
- assumptions
- ownership requirements
- aliasing constraints
- preconditions
- postconditions
- what makes it unsound

### Rule 9.5 — Trusted Parsers Must Be Defensive
Boot structures, executable loading, IPC decoding, and structured input that crosses trust boundaries must be bounded and validated.

Unchecked parsing in trusted code is prohibited.

### Rule 9.6 — Panic Handling Must Be Defined
Panics in privileged code must produce deterministic, documented failure behavior.

Undefined continuation after corruption or invariant violation is prohibited.

---

## 10. IPC and Liveness Rules

### Rule 10.1 — IPC Must Be Explicit and Typed
IPC endpoints, message shapes, transfer rights, and failure semantics must be explicitly defined.

### Rule 10.2 — Blocking Must Be Bounded
No IPC operation may block forever.

Timeout or equivalent bounded-wait semantics are mandatory.

### Rule 10.3 — Reply Authority Must Be Non-Forgeable
Reply objects or reply capabilities must be narrow, single-purpose, and unforgeable.

### Rule 10.4 — Cancellation Must Exist
The system must define what happens when one party:
- crashes
- times out
- is killed
- is restarted
- loses authority mid-exchange

### Rule 10.5 — Deadlock Risk Must Be Managed Structurally
The project must not rely solely on developer discipline to prevent call-cycle deadlocks.

Deadlock-prone patterns must be forbidden, mechanically constrained, or validated.

### Rule 10.6 — High-Privilege Services Must Not Become Hostage Points
A service must not be able to indefinitely trap callers or accumulate unbounded dependency chains.

---

## 11. Scheduling and Availability Rules

### Rule 11.1 — Availability Is Part of Security
Denial of service, starvation, resource monopoly, and dependency lockup are security concerns.

### Rule 11.2 — Every Important Resource Must Be Quota-Enforced
The following must be bounded per security domain where applicable:
- CPU time
- memory
- cap slots
- IPC buffers
- audit storage
- kernel objects
- scheduling objects
- endpoint pressure

### Rule 11.3 — Priority Inversion Must Be Controlled
If priority inheritance or equivalent mechanisms are used, their semantics must be correct, bounded, and documented.

### Rule 11.4 — Pool Exhaustion Must Fail Closed
One compromised process or domain must not be able to exhaust system-wide privileged resources in ways that corrupt other domains.

### Rule 11.5 — SMT Isolation Must Be Enforced for High-Assurance Mode
Where simultaneous multithreading creates cross-domain leakage risk, sibling hyperthreads must not schedule mutually untrusted security domains.

---

## 12. x86-64 Hardware Security Rules

### Rule 12.1 — Long Mode Only
The secure baseline assumes 64-bit long mode only.

### Rule 12.2 — NX Is Mandatory
Non-executable data enforcement is required.

### Rule 12.3 — SMEP Is Mandatory in Production
Kernel execution of user-controlled pages must be blocked.

### Rule 12.4 — SMAP Is Mandatory in Production
Kernel access to user mappings must be deliberate and tightly controlled.

### Rule 12.5 — CET/IBT Must Be Used Where Supported
Control-flow hardening available in supported hardware should be enabled and documented.

Unsupported features must be documented honestly.

### Rule 12.6 — Kernel Code Must Become Read-Only After Init
Kernel text and read-only data must be write-protected after initialization.

### Rule 12.7 — IOMMU Is Required for Production Device Isolation
Process isolation for device servers is not sufficient if DMA can bypass memory controls.

### Rule 12.8 — Microcode and Mitigation Baselines Must Be Versioned
The production security baseline must define supported CPU generations, required microcode state, and required mitigation settings.

### Rule 12.9 — Side-Channel Policy Must Be Explicit
If the system claims mitigation for specific speculative-execution or side-channel classes, it must list:
- which classes are covered
- which are partially covered
- which are out of scope

---

## 13. Boot, Attestation, and Update Rules

### Rule 13.1 — Measured Boot Claims Are Production-Only
Virtual TPM or emulated attestation in development mode is for testing flows, not for establishing production trust.

### Rule 13.2 — Dev and Prod Keys Must Be Separate
No signing, provisioning, or attestation key material may be shared between development and production trust domains.

### Rule 13.3 — Privileged Components Must Be Authenticated
Bootloader, kernel, and any privileged early userspace components must be authenticated in production mode.

### Rule 13.4 — Rollback Is an Attack
The project must treat rollback to older signed but vulnerable states as a security failure.

Update design must include rollback resistance or policy-based rollback control.

### Rule 13.5 — Entropy Policy Must Be Based on Cryptographic Need
The project must define how secure randomness is achieved and maintained.

It must not reduce the randomness story to blind trust in a single source.

### Rule 13.6 — Recovery Must Be Secure
Recovery, maintenance, rescue boot, and update paths must be governed by the same trust standards as normal boot where they can affect privileged state.

---

## 14. Userspace Service Rules

### Rule 14.1 — Least Privilege at Start
Every service must begin with the minimum capabilities required and no more.

### Rule 14.2 — Bootstrap Authority Must Be Shed Early
The bootstrap environment must not remain as an all-powerful runtime control point.

### Rule 14.3 — Spawning Must Be Controlled
Process creation and service instantiation authority must be narrow, auditable, and policy-constrained.

### Rule 14.4 — Device Isolation Must Be Preserved
Where practical, each device class or device instance must have its own isolation boundary.

### Rule 14.5 — Network Stack Layers Must Stay Separated
Networking components should remain split by responsibility so compromise of one layer does not automatically grant full stack control.

### Rule 14.6 — Audit Consumers Must Not Rewrite History
Audit systems must preserve append-only or otherwise non-rewritable security history according to role and policy.

---

## 15. Build, Supply Chain, and CI Rules

### Rule 15.1 — Builds Must Be Reproducible
Trusted builds must be reproducible and independent of transient external network state.

### Rule 15.2 — Dependencies Must Be Pinned and Justified
Every compiler version, nightly pin, crate, and build dependency must be intentionally selected and documented.

### Rule 15.3 — Supply Chain Controls Are Mandatory
Dependency vetting, auditing, denial policies, and vendoring must be enforced in CI.

### Rule 15.4 — Verification Toolchains Must Be Isolated Cleanly
If different analyzers require different pinned environments, those environments must be isolated cleanly rather than weakening build repeatability.

### Rule 15.5 — Security Checks Must Block Merges
Security regressions in CI must prevent protected-branch merges.

### Rule 15.6 — Temporary Bypasses Are Security Debt
Any bypass, allowlist, ignored check, or temporary exception must be documented, time-bounded, and visible.

---

## 16. Verification, Testing, and Assurance Rules

### Rule 16.1 — Every Core Subsystem Needs an Assurance Strategy
Every major subsystem must have one or more of:
- proofs
- model checking
- property testing
- fuzzing
- invariant-driven tests
- manual review requirements

### Rule 16.2 — Proof Scope Must Be Honest
Formal verification of one subsystem must not be described as full-system proof.

### Rule 16.3 — Security Bugs Must Produce Permanent Regression Tests
Every confirmed security bug must yield a lasting regression test where technically possible.

### Rule 16.4 — Fuzz the Boundaries
The project must aggressively fuzz:
- syscall input handling
- bootloader handoff parsing
- IPC payload handling
- executable loading
- service protocol boundaries
- later, network-facing parsers and transports

### Rule 16.5 — Invariants Must Be Testable
The kernel invariants document must be referenced by tests, reviews, and milestone acceptance criteria.

---

## 17. Documentation and Governance Rules

### Rule 17.1 — The Threat Model Must Be Living
The threat model must be updated before major design changes land, not after incidents.

### Rule 17.2 — Security Claims Must Map to Artifacts
Every meaningful security claim must trace to:
- a design document
- code or configuration
- a test, proof, or validation artifact

### Rule 17.3 — Missing Documentation Is a Security Issue
If a subsystem affects trust, privilege, isolation, or recovery and lacks documentation, it is incomplete.

### Rule 17.4 — Complexity Requires Justification
Any feature that expands the TCB, semantic surface, unsafe surface, or privilege model must clear a high bar and include a security rationale.

### Rule 17.5 — Exceptions Must Be Visible
Any exception to these rules must be:
- explicit
- documented
- justified
- approved
- time-bounded
- reviewed for removal

Silent exceptions are prohibited.

---

## 18. Prohibited Patterns

The following patterns are prohibited unless a stricter approved mechanism replaces them:

- hidden global privilege
- root-like universal authority
- unbounded kernel allocation
- unchecked trusted parsing
- writable and executable memory
- undocumented unsafe code
- permanent dev-mode bypasses
- unbounded blocking IPC
- silent fallback after critical security failure
- production claims based on virtualized development environments
- oversized kernel residency for convenience
- compatibility shims that weaken security boundaries
- unreviewed privileged debugging paths
- undocumented recovery modes

---

## 19. Security Exception Process

A deviation from these rules requires a written security exception that includes:
- the exact rule being deviated from
- why the deviation is necessary
- what risk it introduces
- why safer alternatives were rejected
- what compensating controls exist
- how long the exception remains active
- what conditions will remove it

No exception is valid unless it is written down and approved.

---

## 20. Merge Gate Summary

A change must not merge if it does any of the following:
- expands kernel scope without security review
- introduces undocumented unsafe code
- weakens capability semantics
- weakens privilege boundaries
- bypasses quota controls
- adds unbounded blocking behavior
- weakens build reproducibility
- disables required CI checks
- changes trust assumptions without updating the threat model
- introduces new privileged behavior without test coverage or explicit acceptance criteria

---

## 21. One-Page Project Constitution

If the whole project must be summarized in the fewest possible rules, use these:

1. Keep the kernel tiny.
2. Allow no ambient authority.
3. Make every privilege explicit.
4. Make every boundary typed, bounded, and revocable.
5. Keep unsafe code tiny and documented.
6. Separate development claims from production claims.
7. Quota everything important.
8. Fail closed on ambiguity.
9. Verify every important invariant.
10. Never let convenience outrank security.

---

## 22. Final Rule

If a design choice makes BraiNIX easier to build but harder to trust, the design choice is wrong unless it is explicitly approved as a temporary, documented, and removable compromise.

Security is not an add-on layer for this project. Security is the project.
