# Brainix Threat Model

## Purpose

This document defines the security boundaries, protected assets, attacker classes, trusted computing base, attack surfaces, in-scope threats, out-of-scope threats, required mitigations, and residual risks for Brainix.

It exists to prevent three common failures:

1. **unclear trust boundaries**
2. **overstated security claims**
3. **features being added without security traceability**

This is a living security-control document. Any change that affects privileged code, authority flow, measurement, device isolation, scheduler policy, or unsafe code boundaries must be reviewed against this threat model.

---

## Document Goals

This threat model answers the following questions:

- What is Brainix protecting?
- From whom?
- Under what assumptions?
- Which components are trusted?
- Which deployment modes support which claims?
- Which threats are mitigated, partially mitigated, or explicitly out of scope?
- What evidence is required before a security claim can be elevated?

---

## System Summary

Brainix is a Rust `no_std` x86-64 microkernel using explicit capabilities, minimal syscall surface, and synchronous IPC as the primary control path. It rejects ambient authority and rejects POSIX compatibility as a design requirement. It is developed initially in virtualized environments but only makes strong system-level claims in appropriately hardened bare-metal production mode.

---

## Protected Assets

The following assets are considered security-relevant.

### A1. Kernel code integrity
Kernel code must not be modified after boot finalization.

### A2. Kernel control-flow integrity
Control flow must not be redirected by userspace or corrupted object state.

### A3. Kernel memory confidentiality
Userspace must not be able to read arbitrary kernel memory.

### A4. Kernel memory integrity
Userspace must not be able to write arbitrary kernel memory.

### A5. Capability integrity
Capabilities must not be forged, confused, revived after revocation, or amplified.

### A6. Object-type integrity
A capability or object reference for one type must not be usable as another type.

### A7. Authority boundaries
A compromised service must not automatically gain the authority of peer services, the kernel, or the bootstrapping domain.

### A8. Process isolation
One userspace process must not access or interfere with another without explicit capability and policy allowance.

### A9. IPC correctness
Message passing must not become an authority-bypass or stuck-state primitive.

### A10. Scheduler fairness within policy
A malicious process must not starve unrelated security domains beyond explicitly configured policy.

### A11. Device isolation
A compromised userspace device service must not gain arbitrary memory access.

### A12. Measurement integrity
Production attestation and measured-boot state must not be spoofed or confused with development-mode substitutes.

### A13. Audit integrity
Audit records must not be silently forged, erased, or reordered without detection.

### A14. Build and release integrity
The software artifact shipped as Brainix must match reviewed and approved source inputs.

### A15. Entropy and key material
Bootstrapping randomness and cryptographic material must not be exposed, replayed, or initialized unsafely.

---

## Security Objectives

Brainix must satisfy the following objectives.

### O1. Prevent privilege escalation from compromised userspace to kernel
### O2. Prevent unauthorized authority acquisition
### O3. Bound the blast radius of compromised services
### O4. Prevent hidden authority paths and confused deputies
### O5. Preserve memory ownership and sanitation invariants
### O6. Preserve liveness under hostile participants, or fail in bounded, documented ways
### O7. Make production trust claims only when the deployment mode supports them
### O8. Make residual risk explicit

---

## Deployment Modes and Trust Assumptions

## Development Mode

Development mode includes QEMU, containerized build/test environments, and optionally virtual TPMs such as `swtpm`.

### Trusted in Development Mode
The following must be treated as trusted for the purpose of guest execution:
- host kernel
- container runtime
- QEMU
- emulator device model
- host firmware/hypervisor as applicable
- virtual TPM stack
- CI runner and orchestration environment

### Security Value of Development Mode
Development mode can support:
- testing
- fuzzing
- behavioral validation
- guest-kernel crash analysis
- early proof target instrumentation
- attestation-flow rehearsal

### Security Limits of Development Mode
Development mode cannot justify claims of:
- production hardware trust
- secure DMA isolation
- secure host resistance
- trustworthy virtual attestation
- strong protection from emulator or runtime compromise

## Production Mode

Production mode requires:
- supported x86-64 hardware
- measured boot
- TPM 2.0
- IOMMU enabled
- production signing policy
- required mitigation baseline
- platform features such as NX, SMEP, SMAP, and where supported CET/IBT

Only in this mode may strong Brainix system-security claims be made.

---

## Trusted Computing Base

## Production TCB
- CPU and physical memory hardware
- firmware and boot chain up to the Brainix bootloader
- Brainix bootloader
- Brainix kernel
- minimal pre-userspace hardware initialization
- TPM
- production attestation verifier and trust anchors
- build, signing, and release process

## Development TCB
Everything in the production TCB, plus:
- host OS
- container runtime
- QEMU
- virtual TPM
- CI infrastructure
- local dev machine or runner platform

---

## Attacker Classes

## T1. External network attacker
Capabilities:
- can send arbitrary malformed or hostile network traffic
- can attempt protocol exploitation
- can target service parsers and state machines
- can trigger high-rate load or resource pressure

Goal examples:
- code execution in a network service
- persistence in a service
- privilege escalation through service compromise
- containment escape

## T2. Compromised userspace service
Capabilities:
- arbitrary code execution inside one isolated service
- ability to abuse any capabilities granted to that service
- ability to send hostile IPC messages
- ability to consume allowed quotas aggressively

Goal examples:
- kernel exploitation
- authority amplification
- unauthorized memory access
- scheduler abuse
- confused deputy attacks against privileged services

## T3. Malicious or buggy device-facing service
Capabilities:
- malformed interaction with device register interfaces exposed to it
- malformed DMA setup requests if such authority exists
- denial-of-service against peers

Goal examples:
- obtain broader memory visibility
- trigger kernel bugs through device paths
- violate device isolation rules

## T4. Supply-chain attacker
Capabilities:
- compromise a dependency
- tamper with build or CI steps
- introduce malicious code via tooling or release path

Goal examples:
- implant malicious behavior before runtime
- subvert review or provenance
- bypass source-level security expectations

## T5. Insider with code contribution path
Capabilities:
- submit code that weakens invariants
- increase unsafe surface
- blur trust boundaries
- bypass review pressure by complexity

Goal examples:
- make later exploitation easier
- hide authority leaks
- weaken revocation or object rules

## T6. Local hostile tenant in multi-domain deployment
Capabilities:
- high-rate IPC or object creation
- timing observation
- quota exhaustion attempts
- priority inversion attempts
- side-channel probing within practical limits

Goal examples:
- deny service to another domain
- infer behavior from shared resource contention
- exploit scheduler or IPC weaknesses

## T7. Host/hypervisor attacker in development mode
Capabilities:
- full control of container/runtime/QEMU
- ability to tamper with emulated devices, timing, or attestation artifacts
- ability to inspect guest memory

This attacker is **out of scope for protection by Brainix in development mode** and must be documented as such.

---

## Attack Surfaces

### S1. Boot path
- bootloader handoff
- memory map parsing
- early page table setup
- MSR initialization
- interrupt descriptor setup
- production measurement and handoff state

### S2. Syscall boundary
- register-based argument handling
- object lookup
- access validation
- copyin/copyout or equivalent message transfer logic
- entry/exit state restoration

### S3. Capability subsystem
- slot lookup
- derivation
- duplication
- transfer
- revocation
- quota accounting
- object-type dispatch

### S4. Memory management
- page allocation/free
- mapping/unmapping
- page-table mutation
- TLB invalidation
- reuse sanitation
- kernel/user boundary enforcement

### S5. IPC subsystem
- endpoint lookup
- rendezvous rules
- timeout handling
- reply-object lifecycle
- capability transfer during IPC
- cancellation
- deadlock/liveness edges

### S6. Scheduler
- priority transitions
- budget accounting
- wakeup ordering
- inheritance
- timeout expiry
- fairness under pressure

### S7. Interrupt and fault handling
- page faults
- general protection faults
- double faults
- NMI
- machine check
- interrupt stack transitions

### S8. Device isolation path
- device capability issuance
- MMIO mapping rights
- interrupt routing
- DMA/IOMMU rules
- per-device service boundaries

### S9. Attestation and measurement
- key handling
- PCR policy
- quote generation
- verifier acceptance logic
- dev/prod mode confusion
- rollback or replay edges

### S10. Audit path
- record generation
- buffering
- ordering
- write-once storage assumptions
- consumer privilege separation

### S11. Build and supply chain
- dependencies
- compiler/toolchain pinning
- vendoring
- signing
- artifact promotion
- release reproducibility

---

## Trust Assumptions

The following assumptions must hold for Brainix claims to remain valid in production mode:

### TA1
The CPU implements required architectural security features correctly enough for documented mitigations to function.

### TA2
The measured-boot chain is configured correctly and not bypassed.

### TA3
Required production features are present and enabled.

### TA4
The IOMMU is active and correctly configured when device isolation claims depend on it.

### TA5
Production signing keys are protected and not mixed with development keys.

### TA6
The build and release pipeline enforces artifact integrity.

### TA7
The documented TCB is not already compromised before Brainix takes control.

If any trust assumption is false, the corresponding security claim must be downgraded.

---

## In-Scope Threats

The following threats are explicitly in scope.

### Memory corruption and privilege escalation
- kernel memory corruption from malformed syscalls or IPC
- page-table manipulation bugs
- object lifecycle reuse bugs
- stack corruption
- type confusion through object dispatch

### Authority errors
- capability forging
- rights amplification
- incomplete revocation
- stale authority reuse
- confused deputy via privileged service misuse

### Scheduler and IPC abuse
- deadlock
- livelock
- starvation
- priority inversion
- quota bypass through message flow or wakeup behavior

### Device and DMA abuse
- unauthorized device memory access
- over-broad MMIO mapping
- interrupt routing abuse
- DMA escaping service boundaries when isolation is weak

### Attestation and boot abuse
- dev/prod confusion
- rollback
- replay
- quote misuse
- assuming virtual TPM flow equals hardware trust

### Resource exhaustion
- cap-slot exhaustion
- endpoint exhaustion
- object pool exhaustion
- audit buffer exhaustion
- memory pressure attacks
- CPU budget exhaustion

### Supply-chain compromise
- malicious dependency
- review bypass via pinned but harmful artifacts
- release artifact mismatch

### Selected side-channel and x86 exploitation threats
- user-to-kernel misuse of execution permissions
- speculative/transient execution classes explicitly named in platform policy
- sibling-thread cross-domain leakage where SMT policy is not strict enough

---

## Out-of-Scope Threats

These threats are explicitly outside the protection boundary unless later added.

- hostile host or hypervisor in development mode
- malicious SMM or firmware compromise
- physical invasive attacks
- unsupported side-channel classes not specifically documented as mitigated
- arbitrary hardware backdoors
- production use on unsupported CPUs or unsupported mitigation baselines
- DMA protection without IOMMU
- legacy device stacks that have not been included in the trusted design
- social engineering or operational misuse of keys outside the documented key policy

Being out of scope does **not** mean unimportant. It means Brainix does not currently claim to defeat that threat.

---

## Threat Categories and Required Mitigations

## C1. Kernel memory compromise

**Threats**
- invalid user pointer handling
- unsafe aliasing
- out-of-bounds access
- uninitialized reuse
- page-table bugs

**Required mitigations**
- minimal syscall ABI
- strict copy boundary validation
- bounded allocators
- page and object sanitation
- W^X
- KPTI or equivalent where required
- guard pages
- structured fault handling
- unsafe code review discipline
- fuzzing and property testing around boundary code

## C2. Capability failure

**Threats**
- forged capabilities
- rights amplification
- stale slot reuse
- incomplete revocation
- type confusion

**Required mitigations**
- typed capability representation
- slot zeroization
- explicit derivation rules
- monotonic rights rules
- revocation tree correctness
- per-domain quotas
- model checking or proof targets for critical rules

## C3. IPC abuse

**Threats**
- deadlock
- reply confusion
- indefinite blocking
- unauthorized capability transfer
- starvation via endpoint pressure

**Required mitigations**
- synchronous rendezvous discipline
- non-forgeable reply objects or equivalent
- mandatory timeouts
- cancellation policy
- bounded wait semantics
- scheduler-integrated budget consequences
- liveness testing

## C4. Scheduler abuse

**Threats**
- priority inversion
- cross-domain starvation
- budget theft
- wakeup-order manipulation

**Required mitigations**
- priority inheritance
- explicit budget accounting
- per-domain quotas
- deterministic timeout processing
- hostile-load testing

## C5. Device escape

**Threats**
- MMIO overexposure
- interrupt misbinding
- DMA escape
- driver/server authority sprawl

**Required mitigations**
- per-device isolation
- minimal device capabilities
- IOMMU enforcement
- explicit device-memory object types
- no global device authority

## C6. Attestation confusion

**Threats**
- replayed quote
- rollback
- dev/prod key overlap
- false trust in virtual TPM
- verifier policy mismatch

**Required mitigations**
- separate key hierarchies
- production-only trust claims
- verifier policy documentation
- monotonic version or rollback protections
- explicit dev-mode disclaimers

## C7. Supply-chain compromise

**Threats**
- dependency poisoning
- compiler/toolchain drift
- CI tampering
- release mismatch

**Required mitigations**
- pinned toolchain
- vendoring
- dependency review tools
- offline-capable builds
- signed release artifacts
- provenance and reproducibility checks

---

## x86-64-Specific Threat Considerations

### Execution permission abuse
Mitigated through:
- NX
- W^X
- immutable kernel text and read-only data after init

### User-kernel boundary abuse
Mitigated through:
- SMEP
- SMAP
- strict mapping rules
- no direct kernel object aliasing

### Control-flow redirection
Mitigated through:
- CET/IBT where supported
- reduced indirect control-flow exposure
- limited function-pointer usage across trust boundaries

### Transient execution concerns
Documented and bounded through:
- mitigation baseline policy
- microcode support requirements
- SMT isolation or scheduling restrictions where leakage matters

### DMA concerns
Mitigated only where:
- IOMMU is enabled
- device service authority is minimal
- DMA policy is explicit

---

## Residual Risks

Even after mitigation, the following residual risks remain and must be documented honestly.

### R1. Unsafe boundary defects
Rust reduces classes of bugs but cannot eliminate errors in unsafe code, architectural state handling, page-table logic, or low-level x86 initialization.

### R2. Partial proof coverage
Selective formal verification improves confidence in chosen subsystems but does not prove the whole system.

### R3. Complex liveness behavior
Synchronous IPC plus priorities plus budgets can still hide subtle availability failures.

### R4. x86 microarchitectural complexity
Some side-channel risks may remain partially mitigated or out of scope.

### R5. Build/release compromise
If key management or artifact promotion fails, runtime security may be irrelevant.

### R6. Device complexity
Real hardware integration is often where narrow kernels accumulate risk.

---

## Security Claim Levels

Every security statement in Brainix documentation should use one of these labels:

- **Goal** — intended design objective
- **Implemented** — present in code
- **Tested** — covered by repeatable testing
- **Model-checked** — explored with bounded formal tooling
- **Proven** — supported by explicit proof within named scope

No document should use “guaranteed,” “verified,” or “formally secure” without naming which level applies and to what scope.

---

## Threat Review Triggers

This threat model must be revisited when any of the following occur:

- new syscall added
- new kernel object type added
- new unsafe module added
- scheduler semantics changed
- IPC semantics changed
- revocation semantics changed
- attestation flow changed
- device class added
- shared-memory or memory-lending mechanism added
- new production CPU family supported
- new release/signing flow adopted

---

## Open Questions to Track

- What exact boot path is trusted in production?
- What is the first supported CPU and microcode baseline?
- What are the final reply-object semantics?
- What minimum IOMMU policy is required?
- What is the audit storage model?
- Which side channels are explicitly mitigated in v1?
- Will SMT be disabled or partitioned in production?
- What update and rollback format will be used?
- How are critical userspace services restarted safely?

---

## Final Security Posture Statement

Brainix is designed to provide strong structural isolation, explicit authority handling, and narrow privilege boundaries for x86-64 systems. It is not secure because it is written in Rust alone, nor because it uses a microkernel alone, nor because it uses modern mitigations alone. It is secure only to the extent that:

- the trust boundary is correct
- capabilities are enforced correctly
- unsafe boundaries are tightly controlled
- resource exhaustion is bounded
- the boot and measurement model is honest
- the deployment mode supports the claimed guarantees