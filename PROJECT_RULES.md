# BraiNIX Project Rules
## Non-Negotiable Rules for a Secure Multi-Architecture LLM Inference Serving System

Version: 2.0
Status: Mandatory
Reconciled: 2026-08-02 (serving pivot + Apple-primary platform decision)
Applies To: Architecture, kernel code, userspace services, platform backends, build pipeline, CI, deployment, documentation, verification, and operational governance

**Authority.** These rules are subordinate to [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md), which is the
project contract, and to [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Where a rule here conflicts with
either, they win. Invariants and named exceptions are stated in the north-star and nowhere else. See
[`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md).

---

## 1. Purpose

This document defines the mandatory rules that govern the BraiNIX project.

These rules exist to maximize practical security for a high-assurance microkernel written in Rust whose
purpose is to **serve LLM inference to remote network clients**. They are not suggestions, preferences, or
aspirational guidelines. They are project-level constraints that must be followed unless a rule is
explicitly replaced by a stricter one.

No engineering convenience, compatibility target, schedule pressure, throughput goal, or short-term
implementation shortcut may override these rules without an explicit documented security exception
approved at the project-governance level.

**Two decisions of 2026-08-02 shape everything below.** The primary platform is **Apple Silicon** (Mac
mini M2, `Mac14,3`, SoC `T8112`), with x86-64 retained as the secondary and **attested** platform; and
**INV-BOOT/AS** is signed off, meaning remote attestation and sealing are permanently unavailable on the
platform the product ships on. Rules 6.1, 12.0, 13.0, and §24–§26 exist because of these.

---

## 2. Interpretation Rules

The following words have strict meaning in this document:

- **Must** means required with no silent exceptions.
- **Must not** means prohibited.
- **Should** means expected by default and may be deviated from only with written justification.
- **May** means allowed if it does not violate a stronger rule.
- **Trusted Computing Base (TCB)** means all components that must behave correctly for a stated security guarantee to hold.
- **Development mode** means QEMU, containerized, emulated, CI, or otherwise non-production execution.
- **Production mode** means supported bare-metal execution on a supported platform with the required hardware and verified boot assumptions. Two production platforms exist, at **different assurance levels**: Apple Silicon (primary, **not attested** — INV-BOOT/AS) and x86-64 (secondary, **attested**). "Production" alone is therefore no longer sufficient to describe a deployment's assurance; the platform must be named.
- **Security domain** means a unit of isolation whose compromise must not automatically compromise another domain.
- **Confined tenant** means a component granted compute and memory but no authority — specifically the served model, which is central to the product and central to nothing in the TCB's authority.

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

### Rule 6.1 — Two Supported Architectures, One HAL
*(Replaced 2026-08-02. Formerly "x86-64 Only".)*

BraiNIX supports exactly two architectures:

| Platform | Role |
|---|---|
| **aarch64 / Apple Silicon** — Mac mini M2 (`Mac14,3`, `T8112`) | **Primary.** The serving deployment. CPU-only inference. **Not attested** (INV-BOOT/AS). |
| **x86-64** | Secondary. Development, CI, and the **attested** deployment target — the only platform where INV-BOOT holds in full. |

No 32-bit support and no legacy compatibility burden. A third architecture may not be added without owner
sign-off.

Both are **compile-time backends behind one hardware abstraction layer** (`hal/`), never runtime dispatch.
Architecture-neutral code — the serving protocol, the request parser, the tokenizer, the tensor kernels,
the transformer — must contain no platform assumption. In particular, **page size is a HAL parameter**:
Apple Silicon uses 16 KiB base pages and x86-64 uses 4 KiB, and a hardcoded page size in neutral code is a
security defect (INV-MEM-009), not a portability nit.

`arch/` is **single-owner** during HAL extraction. Two concurrent refactors there are a guaranteed merge
disaster and are prohibited.

### Rule 6.1a — Reference-Only External Work
Reverse-engineering documentation produced by third parties — principally the Asahi Linux project, which
is the only public source for Apple Device Tree, AIC, DART, RTKit, and ANS2 details — may be **read and
reimplemented from understanding**. No code may be copied, adapted, or vendored from those projects,
**regardless of their license** (m1n1 is MIT; the Asahi kernel is GPL-2.0; the no-vendoring rule forbids
both).

Where only source documents a behavior, one person writes a **specification** — register map, sequence
description — and a different implementation session codes from that specification. Running m1n1 as a lab
instrument on a development machine is permitted: that is using a tool, not incorporating code.

This is a real, accepted cost. It means re-deriving results that specialists spent years producing, and it
re-imposes that cost on every future SoC generation.

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

## 12. Hardware Security Rules

### Rule 12.0 — Both Platforms Must Satisfy the Equivalent Property
*(Added 2026-08-02.)*

The hardware-security rules below were written for x86-64. **Each states an obligation, not a mechanism.**
The primary platform must discharge every one of them; only the mechanism differs. A property present on
the secondary platform and absent on the primary is a **named exception requiring owner sign-off**, never
a silent asymmetry — the primary platform must not be the weaker one by accident.

| Obligation | x86-64 | aarch64 / Apple |
|---|---|---|
| Kernel cannot execute user code (12.3) | SMEP | PXN |
| Kernel cannot implicitly touch user memory (12.4) | SMAP | PAN |
| Control-flow integrity (12.5) | CET / IBT / ENDBR64 | PAC / BTI |
| No-execute mappings (12.2) | NX | XN / UXN |
| Hardware entropy (13.5) | RDRAND | RNDR — **with an explicit failure path**; `RNDR` may legitimately fail and must never fall back silently |
| IOMMU required in production (12.7) | VT-d | **DART** — dozens of per-device instances, **each deny-all by default**; unknown variant fails closed |
| Interrupt controller | APIC | **AIC** — packed event word, FIQ timer path outside the controller, implementation-defined IPIs |

Two Apple-specific obligations with no x86-64 analogue:

- **Assume nothing at firmware handoff.** MMU, cache, and translation state at the iBoot handoff are
  undocumented and have changed across releases. Re-establish our own page tables, vectors, and stack
  immediately; inherit nothing.
- **Firmware-supplied structures are hostile input.** The Apple Device Tree and boot-args are parsed
  earlier and with more authority than any network byte, and receive the same fail-closed, bounds-checked,
  zero-allocation, fuzzed, Kani-checked treatment (Rule 9.5, INV-PARSE-003).

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

### Rule 13.0 — No Attestation Claims on Apple Silicon
*(Added 2026-08-02. Enforces INV-BOOT/AS.)*

Apple Silicon has no TPM and none can be added; the Secure Enclave exposes no PCR-style
extend/quote/seal interface to third-party software. On the **primary** platform, therefore:

**Permitted claims.** Reproducible build. Ed25519 release signature. Payload-at-rest integrity, described
accurately as *"iBoot2 verifies the Image4 payload against a Secure-Enclave-held, device-local policy"* —
which is Apple's trust root, keyed to one machine, attesting nothing to anyone.

**Prohibited claims — in code, protocol fields, logs, release notes, marketing, and documentation.**
Remote attestation. Sealing. Hardware-anchored measurement. Any phrasing implying a remote party can
verify the running boot state.

The software measurement log is for operational debugging and accidental-corruption detection **only**. It
is self-reported: a kernel compromised early can produce any log it likes. It must never be exported as an
attestation or described as a measurement.

The BSP serving protocol must not define an attestation field the primary platform cannot populate
honestly. Deployments requiring attestation run x86-64. This interacts directly with Rule 4.5 — no
marketing claims beyond proof scope — and is the single most likely place for that rule to be violated.

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
11. Treat the model as a tenant, never an authority — and every byte from a client, a disk, or firmware as hostile.
12. Never claim more assurance than the platform can deliver.

---

## 22. Final Rule

If a design choice makes BraiNIX easier to build but harder to trust, the design choice is wrong unless it is explicitly approved as a temporary, documented, and removable compromise.

Security is not an add-on layer for this project. Security is the project.

---

## 23. Coding Standards Rules

These rules govern all BraiNIX-authored source code. They exist to make the codebase readable, auditable, and independently testable. See `CODE_STANDARDS.md` for the full specification with examples.

### Rule 23.1 — Full-Word Names Only

No abbreviation, acronym-as-name, contraction, or truncation may be used in any BraiNIX-authored identifier (variable, function, method, type, field, constant, module, or lifetime name). Every name must use complete English words.

Examples of prohibited names: `cap`, `idt`, `gdt`, `tss`, `pma`, `mem`, `addr`, `buf`, `ptr`, `idx`, `len`, `num`, `err`, `res`, `tmp`, `i`, `n`.

Exception: names exported by external crates are used as-is; the rule applies only to names BraiNIX authors define.

### Rule 23.2 — Maximum Six Lines Per Function Body

No function or method body may contain more than six lines of executable code. The line count excludes the signature, opening/closing braces on their own line, blank lines, and doc comment lines.

Any logic that would push a function past six lines must be extracted into a named helper function. The helper's name is an opportunity to make a concept explicit and testable.

### Rule 23.3 — Mandatory Extraction of Duplicated Patterns

Any logic pattern that appears two or more times anywhere in the codebase must be extracted into a named helper function. Inline duplication is a code defect treated equivalently to a failing test.

The extracted function must be named after what the pattern does, not after where it was found.

### Rule 23.4 — Explicit Sequential Code Over Compact Abstractions

When there is a trade-off between a compact expression and an explicit multi-step sequence, choose the explicit sequence. A security reviewer must be able to read each step without mentally expanding abstractions.

A 10-line explicit sequence is preferred over a 2-line iterator chain when the 10-line version is easier to audit and test step-by-step.

### Rule 23.5 — Security-Critical Functions Must Document Their Invariant

Every function that directly enforces a security invariant must carry a doc comment that:

1. Names the invariant it enforces using the ID from `docs/security/SECURITY_INVARIANTS.md`
2. Names the test that verifies correct behavior

This makes the connection between code, invariants, and tests traceable by inspection.

---

## 24. Serving Rules

*(Added 2026-08-02. BraiNIX accepts connections from hostile remote clients — a posture reversal these
rules exist to govern. Enforces INV-SERVE.)*

### Rule 24.1 — One Inbound Path
There is exactly one authenticated, capability-gated inbound serving path. Additional listening sockets,
debug ports, or management channels may not be added to a production configuration. The early-boot serial
console on Apple Silicon is a development interface: it is unauthenticated, it grants whoever holds the
cable physical-access authority, and it must not be present in production.

### Rule 24.2 — Client Sessions Are Mutually Unnameable
A client's capability set is frozen at session grant and cannot name another session's state, KV
partition, or weights view. Cross-naming is unrepresentable, not merely rejected — an unrepresentable
reference cannot be leaked by a bug in the rejection path.

### Rule 24.3 — No Allocation From Client-Supplied Sizes
A client-supplied length, count, or offset may be used to *validate* against a fixed bound. It may never
size an allocation, extend a pool, or select a growth factor. This rule is what converts remote memory
exhaustion into bounded capacity exhaustion.

### Rule 24.4 — Admission Limits Are Load-Bearing
`servd` must enforce per-client limits on concurrent sessions and in-flight requests. Fixed pools make
fail-closed correct for security but impose a real availability cost: without per-client limits, one
client consumes the pool and denies every other. Treat admission limits as a security control, not tuning.

### Rule 24.5 — Session Teardown Is Complete
Ending a session releases its capabilities, zeroizes its KV partition, and removes its session-table row.
No residue may be observable by the next occupant.

### Rule 24.6 — The Legacy SSH Server Is Scheduled for Deletion
`boot/ssh_bridge.rs` holds `static mut` session state on a single-core cooperative path. It is exactly
what this threat model forbids at scale and is the weakest point in the tree. It is replaced at P2-T6 and
must not be extended, hardened in place, or built upon in the meantime.

---

## 25. Model Confinement Rules

*(Added 2026-08-02. Enforces INV-MODEL.)*

### Rule 25.1 — The Model Holds Exactly Three Capabilities
`inferd` holds `{Model, its serving endpoint, its own KV slice}`. Not spawn, not kernel mutation, not
network, not another session. The manifest is frozen at launch, and any diff adding a capability is a
security review, not a routine change.

### Rule 25.2 — Confinement Is Structural, Never Behavioral
The model must be **unable to name** the capabilities it lacks. No confinement may rest on the model's
judgment, alignment, training, or resistance to injection. Confinement that depends on the model behaving
well is not confinement.

### Rule 25.3 — Model Output Is Hostile Input Everywhere It Lands
Emitted tokens are untrusted bytes for every consumer — operator console, log, audit record, response
framing. No consumer may interpret in-band control sequences from model output.

### Rule 25.4 — Weights Are Verified Before Use, and the Anchor Is Stated
The loader checks a per-tensor digest before any weight byte is used and fails closed on malformed,
truncated, or oversized input. On x86-64 the digest is anchored to a hardware quote; **on Apple Silicon it
is anchored only to the software measurement log**, so it detects corruption but not an attacker who
already controls the kernel. Documentation must not blur the two.

### Rule 25.5 — Confinement Is Tested Adversarially
A prompt-injection corpus runs as a CI regression bar. The passing condition is **zero escalations under
any input** — not a rate, not a percentage.

---

## 26. Rule Precedence and Reconciliation

*(Added 2026-08-02.)*

### Rule 26.1 — One Statement Per Invariant
Invariants and named exceptions are stated in [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md) and nowhere else.
This document, `docs/security/SECURITY_INVARIANTS.md`, and every architecture spec may decompose or
restate them — never introduce, reword, or qualify one. A qualification existing only in a subordinate
document is a bug to be reported.

### Rule 26.2 — Three Exceptions Are In Force
**INV-BOOT/AS** and **TCB-AS** (2026-08-02) and **TCB-EXCEPTION-001** (in-kernel SQL, 2026-06-27). There
are no others. Any document, comment, or commit message claiming an exemption not on this list is drift.

### Rule 26.3 — Roadmap and Status Live In-Tree
Phasing and status are maintained in [`docs/ROADMAP.md`](docs/ROADMAP.md). Planning files outside the
repository are not authoritative and must not be relied on for scope decisions.

### Rule 26.4 — Archived Documents Are Not Edited for Consistency
Historical records — `.planning/planning-keep/**`, `docs/superpowers/**`, and documents marked SUPERSEDED
— describe what was true when written. They carry a status banner and are otherwise left as-written.
Rewriting them to match current reality destroys the record. See
[`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md).
