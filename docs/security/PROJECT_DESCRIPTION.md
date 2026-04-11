# Brainix — High-Assurance Microkernel for x86-64

## Executive Summary

Brainix is a **high-assurance microkernel operating system for x86-64**, written in Rust, with a design goal of making security properties **structural, explicit, and reviewable** rather than probabilistic or obscurity-dependent.

Its core philosophy is simple:

> **Authority must be explicit. Isolation must be structural. Security claims must be bounded by a named trust model.**

Brainix does not attempt to be a general-purpose Unix clone. It does not prioritize POSIX compatibility, broad driver support, or legacy assumptions. It is an intentionally constrained operating system architecture designed for **high-assurance environments**, **security-sensitive research**, and **controlled deployments** where minimizing ambient authority and tightening the trusted computing base matter more than compatibility.

Brainix began from a strong initial concept: a Rust `no_std` microkernel, capability-based access control, synchronous IPC, no ambient authority, no POSIX ABI, x86-64 focus, formal verification targets, and hardware-backed attestation. This revised project description preserves those strengths while making the security model more precise, deployment claims more honest, and implementation priorities more defensible.

---

## Mission

Build a small, auditable, security-first x86-64 operating system kernel and supporting userspace that:

- minimizes code executing in ring 0
- eliminates ambient authority
- enforces access through typed capabilities
- restricts communication to explicit IPC or tightly controlled memory lending
- uses x86-64 hardware isolation features aggressively
- separates development-mode experimentation from production-mode trust claims
- treats every strong security claim as traceable to an explicit invariant, mechanism, and evidence source

---

## Guiding Security Principles

### 1. Security properties must be structural
Security must come from architecture, invariants, and explicit authority handling. Randomization and mitigations may be used as **defense in depth**, but the system's core security claims must remain valid even if the attacker knows the design and layout.

### 2. No ambient authority
No process, service, or subsystem receives power merely by existing. Every access to memory, endpoints, device handles, interrupt bindings, scheduling tokens, or mapping rights must flow through an explicit capability.

### 3. Minimize ring-0 code
Only the code that absolutely must run in the kernel may execute in the kernel. All other policy and service logic belongs in isolated userspace servers.

### 4. The trust boundary must be named
Security claims are only valid within the declared trust model. Development-mode execution under QEMU, Docker, or `swtpm` does not provide the same trust properties as a bare-metal measured-boot deployment.

### 5. Unsafe Rust is a managed hazard, not a waiver
Rust improves baseline memory safety, but Rust alone does not make a kernel safe. Every `unsafe` block must be tightly bounded, documented, reviewed, and treated as a security-critical boundary.

### 6. Assurance claims must be scoped
Brainix may pursue seL4-style assurance goals, but it must not imply whole-system proof when only specific subsystems have been modeled, checked, or verified.

---

## Primary Goals

### Security Goals
- Prevent privilege escalation by compromised userspace services.
- Prevent authority forgery or amplification.
- Preserve kernel memory isolation from userspace.
- Limit blast radius when a service is compromised.
- Maintain object-type integrity and revocation correctness.
- Resist common x86-64 exploitation patterns through both architecture and hardware hardening.
- Make denial-of-service behavior bounded, visible, and policy-controlled rather than accidental.

### Engineering Goals
- Keep the kernel small, analyzable, and amenable to property checking.
- Maintain reproducible, offline-capable builds.
- Constrain supply-chain risk using vendoring and dependency review tooling.
- Build a phased architecture that can be validated incrementally.
- Separate “bootstraps in QEMU” from “secure production deployment.”

### Assurance Goals
- Define kernel invariants before feature growth.
- Associate every major subsystem with test, fuzz, proof, or review expectations.
- Track unsafe code growth as a security metric.
- Use formal methods selectively where they provide leverage.

---

## Explicit Non-Goals

Brainix is **not** trying to be any of the following in its first serious secure implementation:

- a POSIX-compatible Unix replacement
- a Linux-compatible ABI layer
- a desktop operating system
- a broad hardware-compatibility platform
- a legacy BIOS or 32-bit system
- a “secure because Rust” marketing project
- a production hypervisor
- a hotplug-heavy or device-rich platform
- a general-purpose driver zoo

Non-goals exist to protect the project's security intent. Every compatibility layer or convenience feature increases attack surface, state complexity, and proof burden.

---

## Supported Architecture

### Initial Platform
- **CPU architecture:** x86-64 only
- **Execution mode:** long mode only
- **Kernel language:** Rust `no_std`
- **Initial development target:** QEMU-based guest environment
- **Production target:** supported x86-64 bare metal with measured boot and IOMMU

### Unsupported Initial Targets
- x86 32-bit
- ARM
- RISC-V
- BIOS/real-mode compatibility beyond minimal boot transitions
- multi-platform abstraction layers that dilute x86-specific hardening

Restricting the project to x86-64 early makes the hardening story sharper and prevents portability from overriding security rigor.

---

## Deployment Modes

## Development Mode

Development mode exists to allow rapid bring-up, CI, fuzzing, and model validation. It may use:

- QEMU
- multiboot2 or equivalent bootstrap path
- containerized build/test runners
- `swtpm`
- virtualized device models

In development mode, Brainix should be treated as a **guest security target**, not the root of trust.

### Development Mode Security Boundary
The following are **outside** Brainix's trust boundary in development mode:

- host operating system
- container runtime
- QEMU and emulator device model
- virtual TPM implementation
- CI runner environment
- hypervisor and host firmware

### What Development Mode Can Prove
Development mode can support:
- correctness testing
- integration testing
- early hardening validation
- syscall/IPC fuzzing
- kernel invariant instrumentation
- guest-kernel crash and fault analysis
- attestation-flow rehearsal

### What Development Mode Cannot Honestly Claim
Development mode cannot honestly claim:
- hardware-rooted trust
- host compromise resistance
- emulator escape resistance
- real DMA isolation
- production-grade attestation guarantees
- full platform-side side-channel control

---

## Production Mode

Production mode is the only mode in which strong system-level Brainix security claims apply.

### Production Mode Requirements
- x86-64 hardware in supported configuration
- measured boot
- TPM 2.0
- IOMMU enabled
- NX enforced
- SMEP enabled
- SMAP enabled
- CET/IBT enabled where supported
- supported microcode baseline
- approved boot chain
- Brainix-specific production keying and signing policy

### Production Mode Policy
- The kernel must refuse to start in “secure production mode” unless required platform capabilities are present.
- Development and production keys must be fully separated.
- Production attestation claims must be based on real hardware roots of trust, not virtual substitutes.

---

## Trusted Computing Base

The Trusted Computing Base must be stated explicitly for every deployment mode.

## TCB in Production Mode
The production TCB includes:

- CPU and memory hardware
- platform firmware and measured boot chain up to the Brainix bootloader
- Brainix bootloader
- Brainix kernel
- minimal device initialization code required before isolated device services take over
- TPM
- attestation verifier and key infrastructure
- offline build/signing process

## TCB in Development Mode
The development TCB additionally includes:

- host OS
- container runtime
- QEMU
- `swtpm`
- CI infrastructure
- all host-side orchestration components

No document, presentation, or claim should collapse these two models into one.

---

## Threat Model Summary

Brainix is designed to resist two primary classes of attacker:

### External attacker
An attacker attempting to exploit a network-exposed service, malformed input path, parser, or protocol handler to gain unauthorized code execution or memory access.

### Internal attacker
An attacker who already controls a service or process in userspace and is trying to:
- escape containment
- elevate privilege
- forge access
- retain access after revocation
- interfere with unrelated security domains
- trigger scheduler or IPC pathologies
- exhaust shared resources to affect other domains

Brainix does **not** assume “one bug means total compromise.” The architecture must constrain compromised processes by default.

---

## Core Architecture

## 1. Microkernel Core
The kernel includes only the mechanisms that must execute in ring 0, such as:

- syscall entry/exit
- capability validation and object access mediation
- memory mapping primitives
- scheduler core
- synchronous IPC machinery
- interrupt dispatch and minimal low-level hardware control
- fault handling
- low-level attestation and boot-state measurement hooks as required

Anything above this belongs in userspace.

## 2. Userspace Services
Userspace services are isolated processes with minimal capabilities. Expected examples include:

- `spawnd` — process creation under strict policy
- `auditd` — audit record consumer with limited authority
- `linkd` — link-layer service
- `ipd` — IP-layer service
- `transportd` — transport service
- per-device services
- future storage or filesystem services
- policy services that should never live in the kernel

No long-lived omnipotent init process should remain at runtime. Bootstrap authority must collapse after system initialization.

## 3. Capability Model
Every object is accessed via a typed capability. Objects include:

- memory regions
- pages
- page-table mapping rights
- IPC endpoints
- reply objects
- scheduler control tokens
- interrupt bindings
- device handles
- audit handles
- process control objects

Capabilities must obey:
- no rights amplification
- no type confusion
- explicit derivation
- explicit transfer
- explicit revocation semantics
- quota-aware allocation and retention

## 4. IPC Model
The default control path is synchronous rendezvous IPC. The IPC system must preserve:

- explicit sender/receiver synchronization
- bounded waiting
- clear timeout semantics
- unforgeable reply behavior
- no hidden authority transfer
- capability-transfer safety
- schedulability under hostile participants

Pure message passing is preferred. If later performance work introduces memory lending, it must still be capability-governed, bounded, revocable, and non-ambient.

---

## Memory and Isolation Model

### Design Goals
- prevent user access to kernel memory
- prevent writable-executable memory
- prevent accidental cross-object reuse leaks
- provide deterministic allocation behavior
- bound resource exhaustion effects

### Key Properties
- typed physical page ownership
- bounded kernel allocators
- no general-purpose unbounded kernel heap
- page sanitation before reuse
- kernel stack guard pages
- KPTI or equivalent separation where required by threat model
- distinct object classes for kernel memory, user memory, device memory, and loaned buffers
- explicit map/unmap authority

### Kernel Memory Policy
- kernel `.text` and `.rodata` become immutable after init
- kernel mappings are never exposed directly to userspace
- all memory reuse paths are zeroizing or otherwise sanitizing according to object class
- allocation failure is explicit and handled, never silently retried through unsafe fallback

---

## Scheduler and Resource Governance

Brainix must treat availability as part of security.

### Required Capabilities
- fixed-priority preemptive scheduling
- priority inheritance where blocking can cause inversion
- bounded CPU budgets
- per-domain quotas for:
  - capability slots
  - kernel objects
  - message buffers
  - memory consumption
  - audit record pressure
  - endpoint usage

### Isolation Requirements
- one hostile domain must not starve unrelated domains beyond declared policy
- timeout and cancellation behavior must be explicit
- critical services must have restart behavior that does not mint new authority
- SMT sibling execution across hostile domains must be prohibited or tightly controlled in production deployments where leakage matters

---

## x86-64 Hardening Strategy

Brainix is x86-64 specific at first, so x86 hardening must be treated as a first-class design pillar.

### Mandatory Production Features
- NX
- SMEP
- SMAP
- CET/IBT where supported
- IOMMU for device isolation
- write-protected kernel text and read-only data after init
- W^X enforcement
- explicit TLB invalidation rules
- guard pages and structured fault handling
- separate stacks for critical fault/interrupt paths where required

### Side-Channel Policy
Brainix addresses selected x86 classes explicitly but does **not** claim blanket side-channel immunity.

The system should document:
- which transient execution attacks are specifically mitigated
- which cache, TLB, branch, or timing side channels remain in scope, partially addressed, or out of scope
- whether SMT is disabled, partitioned, or policy-constrained
- what assumptions are required about microcode and firmware

---

## Boot, Measurement, and Attestation

### Boot Principles
- secure claims begin only after a trusted boot path
- development boot and production boot are distinct concepts
- production boot requires measured state
- versioning and rollback policy must be explicit

### Attestation Policy
- dev attestation using `swtpm` is allowed only for flow testing
- production attestation requires actual hardware-backed trust
- dev and prod keys must never overlap
- network service admission rules may depend on attestation in production, but this must not be misrepresented in dev mode

### Entropy Policy
Security depends on cryptographically sufficient seeded randomness, not on any single mechanism alone. The design must define:
- initial entropy sources
- mixing and seeding policy
- DRBG strategy
- degraded-mode handling
- behavior before full initialization

---

## Build and Supply-Chain Security

The build system is part of the security model.

### Requirements
- pinned Rust toolchain
- vendored dependencies
- reproducible or strongly deterministic builds where practical
- offline-capable builds
- dependency review and deny-list tooling
- vulnerability scanning
- artifact signing
- provenance documentation

### CI Goals
- build verification
- unit tests
- integration tests
- guest boot tests
- static checks
- dependency checks
- fuzz smoke tests or corpus validation
- selected model checking or proof runs

The CI environment itself is not trusted in development mode, but it must still be hardened because it influences release integrity.

---

## Formal Methods and Assurance Strategy

Brainix uses layered assurance rather than a single silver bullet.

### Methods
- unit testing
- integration testing
- property-based testing
- fuzzing
- static review
- unsafe boundary audits
- selective model checking
- selective proof-oriented tooling

### Expected Scope
Examples of good early proof or model-check targets:
- capability rights monotonicity
- revocation termination and completeness properties
- endpoint and reply-object state transitions
- bounds safety in object and slot lookup
- selected IPC invariants

### Claim Discipline
Every strong claim should be labeled as one of:
- architectural goal
- implemented behavior
- tested behavior
- model-checked property
- proven property

This prevents overclaiming.

---

## Assurance-Critical Documentation Set

The minimum documentation set for serious security work includes:

- `PROJECT_DESCRIPTION.md`
- `THREAT_MODEL.md`
- `SECURITY_INVARIANTS.md`
- unsafe code policy
- release and signing policy
- platform support matrix
- incident and failure-mode policy
- attestation protocol document
- change-control rules for security-critical modules

---

## High-Level Phasing

## Phase 0 — Security Baseline
- trust model
- TCB definition
- threat model
- invariants
- unsafe policy
- release and signing policy

## Phase 1 — Boot and Minimal Kernel
- long-mode entry
- page tables
- serial logging
- panic handling
- structured traps and faults
- deterministic guest boot in QEMU

## Phase 2 — Memory Core
- typed pages
- W^X
- sanitation-on-reuse
- bounded allocators
- guard pages
- kernel/user separation

## Phase 3 — Capability Core
- typed objects
- capability slots
- derivation rules
- transfer rules
- revocation rules
- quota accounting

## Phase 4 — IPC Core
- synchronous rendezvous
- reply-object discipline
- timeout/cancellation
- atomic capability transfer
- liveness instrumentation

## Phase 5 — Scheduler and Quotas
- fixed priority
- inheritance
- budget accounting
- anti-starvation handling
- hostile-domain pressure testing

## Phase 6 — x86 Production Hardening
- SMEP
- SMAP
- NX
- CET/IBT
- IOMMU policy
- production boot and measurement
- immutable kernel text/data after init

## Phase 7 — Minimal Trusted Userspace
- process spawning policy
- audit path
- one device path
- authority collapse after bootstrap

## Phase 8 — Network Stack
- decomposition into isolated services
- network fuzzing
- least-privilege buffer ownership
- attacker-driven containment testing

---

## Success Criteria

Brainix should not be called “secure” merely because it boots, compiles, or uses Rust. A serious security milestone should require:

- explicit trust boundary
- named invariants
- measurable unsafe boundary discipline
- bounded resource handling
- least-privilege userspace
- hardening enabled and tested
- documented failure modes
- proof/test evidence for critical claims
- clean separation between dev-mode and production-mode guarantees

---

## Major Risks

The major risks to the project are not primarily syntax or language mistakes. They are:

- overclaiming assurance
- unclear trust boundaries
- liveness problems in synchronous IPC
- resource exhaustion edge cases
- authority leaks in spawn, reply, or delegation paths
- unsafe code creeping into too many modules
- boot and attestation complexity outrunning core kernel assurance
- device isolation claims without IOMMU-backed enforcement
- assuming virtualized dev behavior matches production trust

---

## Strategic Recommendation

Brainix should be developed as a **narrow, disciplined, security-first kernel program**, not as a feature race. The fastest path to a credible system is:

1. document the security model rigorously
2. keep the trusted core small
3. make x86 assumptions explicit
4. prove or test critical invariants early
5. delay complexity that weakens auditability

If the project maintains that discipline, it can become a genuinely compelling high-assurance kernel architecture rather than just another Rust OS experiment.