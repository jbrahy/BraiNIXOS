# BraiNIX north-star

Trust boundary, attacker model, and verification posture live in THREAT_MODEL.md. Phasing and current
status live in ROADMAP.md. This document is the timeless target and the rules that defend it.

**Authority.** This document outranks every other document in the tree. Where any other file disagrees
with it, this file wins and the other file is drift to be fixed. See DOCUMENTATION_MAP.md.

## The destination

BraiNIX is a minimal, capability-based, security-first microkernel whose purpose is to **serve LLM
inference securely to remote network clients**. It is written end to end in Rust, and its dependency
closure is itself: zero external code, with every byte that runs — from boot stub through kernel,
network stack, inference engine, device drivers, libraries, and crypto primitives — in-tree, audited,
and reproducibly built from source the project owns. The external crates still vendored today are
tracked debt against this rule, not exceptions to it.

The security invariants are the product, not an obstacle to it. "Secure" is the word that separates
BraiNIX from a commodity inference server: the same capability model, W^X memory discipline, minimal
named TCB, and measured boot that a hardened microkernel demands are turned outward to protect a
network-facing inference service against hostile clients, hostile prompts, and model-weight compromise.
On that base sit three subsystems: a **secure serving path** that authenticates remote clients and
mediates every request through capabilities; an **in-tree inference engine** that runs the served model
with all available compute devoted to it within fixed, reserved regions; and an **observe-only LLM
security auditor** that continuously checks the running serving stack against its documented invariants.

## Target platforms

**Primary: Apple Silicon (aarch64).** The reference deployment is a Mac mini M2 Pro (`Mac14,12`, SoC
`T6020`, 32 GB unified memory). Unified-memory bandwidth makes M-series CPUs a credible CPU-inference
platform, and 32 GB is real serving capacity. Owner decision, 2026-08-02.

**Secondary: x86-64.** Retained as the **attested** platform — the only target where INV-BOOT holds in
full (see INV-BOOT/AS below). Any deployment whose threat model requires remote attestation or sealing
runs on x86-64, not on Apple Silicon. x86-64 also remains the development and CI target, and the
platform against which the HAL traits are first proven.

Both are backends behind one hardware abstraction layer (`docs/architecture/HAL.md`). Architecture-
neutral subsystems — the serving protocol, the request parser, the tokenizer, the tensor kernels, the
transformer — are written once and are not permitted to acquire platform assumptions.

## Performance is a goal, not a leftover

**On the primary platform, BraiNIX serves as fast as the hardware allows.** Owner decision, 2026-08-02.
The reference machine is bought and sized for inference, and a secure inference server nobody can afford
to use has not delivered its security to anyone. Throughput is a product requirement, ranked below the
invariants and above everything else.

This is a deliberate strengthening of the tradeoff rule below, which previously named throughput as a
thing principles beat. Principles still beat it — but "we did not optimize because security" is no longer
a sufficient answer. Every layer is expected to be fast *within* the invariants, and slowness must be
justified by a named invariant, not by vague caution.

**Inference on this machine is memory-bandwidth-bound, not compute-bound.** Single-stream decode reads
essentially the whole weight set per token, so the ceiling is (model bytes) ÷ (memory bandwidth), and
every design decision should be judged against that arithmetic first. This has a sharp consequence:
**the biggest wins are in bytes moved, not instructions executed.** Quantization, weight layout, cache
blocking, and avoiding copies dominate; micro-optimizing arithmetic does not.

### In-bounds performance work — expected, not merely permitted

- **All cores.** SMP scheduling across performance and efficiency cores, with the inference engine sized
  to the performance cores. Any remaining single-core cooperative path is a performance defect as well as
  a scaling one.
- **SIMD.** NEON in the tensor kernels, via the userspace FP/SIMD enablement (P3-T0). The kernel stays
  soft-float; the inference engine must not.
- **Quantization.** Q8 first, lower precision where quality permits. This is the highest-leverage lever
  available, because it directly divides the bandwidth-bound ceiling.
- **Zero-copy within the capability model.** Copies avoided by *not making them* — passing a capability
  to an already-placed buffer — never by introducing shared mutable memory.
- **Large reserved regions.** 32 GB of unified memory is the reason this machine was chosen. Weights and
  KV-cache regions should be sized generously; that is exactly what fixed regions are for.
- **Cache-aware kernel design.** Blocking, tiling, and layout chosen for the actual cache hierarchy.

### Out of bounds without written sign-off

Performance work that requires any of these crosses a hard line and needs an owner exception:

- A dynamic kernel heap or a growable arena (INV-MEM).
- Shared-memory IPC or async queues, however much faster the datapath would be (INV-IPC).
- Any W^X exception, including JIT-compiled kernels for tensor operations (INV-MEM).
- Weakening client isolation or session confinement to share caches or batch across tenants (INV-SERVE).
- Ambient authority granted to the inference engine to avoid capability checks (INV-AUTH, INV-MODEL).

### The GPU is in scope

**Owner ruling, 2026-08-02: performance means GPU and CPU at maximum.** Apple's AGX GPU moves from
non-goal to goal. The machine's full compute — performance cores, efficiency cores, NEON, and the
integrated GPU — is devoted to serving the model.

The honest technical picture, so expectations match physics:

- For **single-stream decode**, the GPU shares the same unified memory bus as the CPU. It does not raise
  the bandwidth-bound ceiling; the gain is real but bounded, and quantization matters more.
- For **prefill** (compute-bound) and for **serving multiple clients concurrently**, the GPU is a large
  win — and concurrency is precisely what a serving product needs. This is where the investment pays.
- The cost is the **single largest reverse-engineering effort on the platform**, larger than the entire
  storage-and-network driver chain, and it must be written clean-room from published documentation.

### TCB-AS/GPU — pending exception, requires sign-off

Running AGX has a security consequence that the CPU-only design did not have, and it is recorded here
because it touches a hard line rather than merely a schedule.

**The AGX GPU is firmware-driven.** Using it requires loading and running an Apple-signed, closed,
unauditable firmware blob on a coprocessor that has **DMA access to system memory**. That is a third
forced addition to the trusted set on the primary platform, alongside TCB-AS — and unlike SecureROM and
iBoot, this one runs *concurrently with our kernel*, for the entire life of the system, driven by data
derived from client requests.

The control is **DART**, not firmware correctness: the GPU's DMA is confined by IOMMU mappings the GPU
driver cannot widen (INV-GPU, `INV-DEV-006`), every DART instance fronting the GPU defaults to deny-all
(`INV-DEV-004`), and `gpud` is an ordinary capability-bounded server holding only `CapGpu`. The GPU
firmware is treated as hostile: its completion records and any data it writes back are parsed with the
same fail-closed discipline as network bytes (`INV-PARSE-001`).

**This exception is not yet signed.** Until it is, AGX work may proceed on design and on the DART
confinement that must precede it, but no build ships with the GPU enabled. INV-GPU is no longer deferred
on the primary platform; it is the invariant that makes this exception survivable, and it must be
enforced and proven *before* firmware is loaded, not after.

## First principles

These decide every tradeoff. When they conflict with convenience, the principle wins unless the owner
signs off otherwise in writing. Throughput is not convenience: see *Performance is a goal* above — it is
a product requirement that ranks below the invariants and above everything else.

- Least authority. Nothing holds a capability it does not need, and no capability is ambient. Authority
  is named, granted, and revocable. A remote client is granted only its own session.
- Fail closed. Absence of an explicit grant is denial. A malformed request, an oversized or corrupt
  model blob, a firmware-supplied structure that fails a bounds check, an error path that cannot prove
  safety — all deny the operation.
- Structure over secrecy. Security is a property of the design, enforced by the capability model, the
  type system, or a machine-checked proof. Nothing rests on an attacker not knowing something.
- Minimize and name the trust. The set of components that can violate security is small, written down,
  and justified. Anything not in it — every remote client, every network byte, every prompt, every byte
  of firmware-supplied data, the served model's outputs — is treated as hostile.
- Every claim is falsifiable. A property that is asserted but not checked does not count as enforced.
  Where a platform makes a property unachievable, the loss is written down, not papered over.

## Invariants

The contract. Each is named, documented, and individually checkable. Verification and
consequences-of-compromise are in THREAT_MODEL.md.

- **INV-AUTH**: no ambient authority; every server's capability set is frozen at launch and capabilities
  are unforgeable.
- **INV-MEM**: W^X holds for every page, always; no dynamic kernel heap, fixed-size pools only. Model
  weights and KV-cache live in fixed, reserved regions sized at build time — never a growing allocator.
- **INV-IPC**: inter-process communication is synchronous rendezvous only; no shared-memory IPC and no
  async queues exist in tree.
- **INV-BOOT**: every release is measured into the TPM, reproducibly built, and Ed25519-signed, with
  predicted PCRs published before the artifact ships. **Holds in full on x86-64 only** — see INV-BOOT/AS.
- **INV-SERVE**: inbound clients are mutually isolated; no client can name a capability to another
  client's session, weights view, or KV state. The network request decoder is a fail-closed hostile-input
  parser; a malformed or over-length request denies, never grows a pool.
- **INV-MODEL**: the served model is a confined tenant, never a trusted authority. Its weights are
  integrity-checked before use (a corrupt or oversized blob fails closed); it cannot escalate, cannot
  read other clients' sessions or other processes, and cannot reach the network except through the
  capability-mediated serving channel. The confinement holds under adversarial prompting.
- **INV-AUDIT**: the auditor observes the serving stack and reports and does nothing else; it holds no
  spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege.
- **INV-GPU** *(active on the primary platform as of 2026-08-02)*: accelerator DMA is confined by the
  IOMMU; the GPU driver is an ordinary capability-bounded server with no ambient device authority; the
  driver cannot widen its own DMA window. With AGX in scope, this is no longer a deferred target — it is
  the control that makes running Apple's opaque GPU firmware survivable, and it must be enforced and
  proven **before** that firmware is ever loaded. On x86-64 it remains a stated target.

### INV-BOOT/AS — named exception, Apple Silicon

**Signed off by the owner, 2026-08-02.** Required by the hard-line rule below; recorded here rather than
in a subordinate document because it degrades a headline invariant on the *primary* platform.

Apple Silicon has no TPM, and none can be added — there is no LPC/SPI TPM header, and a USB TPM is not a
root of trust. The Secure Enclave is **not** a TPM substitute: it exposes no PCR-style extend/quote/seal
interface to third-party software, its protocol is proprietary and undocumented, and driving it from a
non-Apple kernel is out of scope.

On Apple Silicon, INV-BOOT is satisfied **only** in these clauses:

- **Reproducible build** — unchanged. A third party can rebuild the published payload bit-for-bit.
- **Ed25519 release signature** — unchanged. These are properties of the artifact, not the platform.
- **Boot-time payload integrity** — real and hardware-rooted, but *Apple's* root, not ours: under the
  `kmutil` local-policy flow, iBoot2 verifies the Image4-wrapped payload against a Secure-Enclave-held,
  device-local policy at every boot. A tampered on-disk payload fails to boot.
- **Software-only measurement log** — the kernel hashes what it loads (weights, servers) and records the
  log. Self-reported, and therefore worthless against an attacker who compromised the kernel early.

What is **permanently lost** on the primary platform:

- **Remote attestation.** No quote. A remote party cannot distinguish a genuine BraiNIX boot from a
  compromised one. This is the single capability that most distinguished BraiNIX from a commodity
  inference server, and on Apple Silicon it is gone.
- **Sealing.** No secrets bound to boot state. Data at rest is protected only by what the kernel does at
  runtime.
- **Runtime-chain measurement.** Detection of a divergent boot chain — the exact property INV-BOOT's
  blast-radius entry exists for — is unavailable.

Deployments requiring attestation or sealing **must** use the x86-64 target. This is not a gap that
closes later; it is structural.

### TCB-AS — unavoidable trusted components, Apple Silicon

Also a consequence of the primary-platform decision. On Apple Silicon we can never own the first
instructions: **SecureROM**, **iBoot1**, **iBoot2**, and **sepOS** are Apple-signed, immutable, and
always running. They join the trusted computing base whether we like it or not, and they are closed
source, so the dependency-closure rule ("every byte that runs is in-tree") is permanently violated on
this target by components we cannot remove, audit, or replace. A macOS stub install must remain on disk
for the paired recoveryOS and firmware volumes; "bare metal" here means "our kernel is the OS," not
"Apple software is absent." Enumerated in THREAT_MODEL.md.

## What advancing the goal means

- The dependency closure shrinks toward itself. Removing an external crate advances the goal. Adding one
  is anti-goal — the inference engine, the serving protocol, and the device drivers are written in-tree,
  not vendored. Third-party reverse-engineering work (notably Asahi Linux) is **reference-only**: we
  read published documentation and reimplement from understanding; we do not copy code, under any
  license. Where only source documents a behavior, one person writes a specification and a different
  session implements from it.
- New code lands behind an invariant. A feature that cannot be expressed as, or checked against, the
  invariants above is not ready.
- The served model earns its resources by staying confined. Give it all available compute and reserved
  memory; give it no authority. Capability first, capability always; the model is a tenant, never a
  trusted authority, no matter how central it is to the product. **"All available compute" is meant
  literally** — every core, the full SIMD width, and the whole reserved region. A confined tenant is not
  a throttled one.
- Bytes moved is the metric that matters. Because serving on this hardware is bandwidth-bound, a change
  that reduces data movement advances the goal more than a change that reduces instruction count. Measure
  against the (model bytes ÷ memory bandwidth) ceiling before optimizing anything else.
- The trusted set only ever shrinks — with TCB-AS as the one direction we cannot push. The inbound
  serving surface is the largest attack surface we control; every byte of it that can be moved out of
  the TCB or proven correct is progress. Any change that enlarges the TCB pays for itself explicitly or
  does not land.
- Firmware-supplied data is hostile input. The Apple Device Tree, boot-args, and every structure handed
  to us by iBoot get the same fail-closed, bounds-checked, fuzzed, zero-allocation parser discipline as
  network bytes.

## Hard lines (do not cross without explicit sign-off)

- No ambient authority anywhere. Capability sets are frozen at launch. A remote client's grant covers
  only its own session.
- W^X enforced globally and structurally. No page is ever writable and executable — including
  inference-engine and driver code paths.
- Synchronous rendezvous IPC only. No shared-memory IPC, no async queues.
- No dynamic kernel heap. Fixed-size pool allocators only. "Give all resources to the LLM" is satisfied
  by large fixed reserved regions for weights and KV-cache, never by adding an allocator.
- No new external crate dependencies. The standing job is to remove the ones still present (multiboot2,
  sha2, chacha20, ed25519-dalek, x86_64, bitflags, log, uefi-raw, uguid, ptr_meta), not add more. The
  inference engine, the device drivers, and every Apple Silicon platform component are in-tree.
- No copied code from reverse-engineering projects, regardless of their license. Documentation in,
  clean-room implementation out.
- The auditor never holds spawn, kernel-mutation, or network capability. The served model never reads
  another client's session or another process, and never makes a network call except through the
  capability-mediated serving channel.
- No path to security depends on attacker ignorance.
- **Degrading a named invariant on any platform requires a written, named exception with owner sign-off,
  recorded in this document.** INV-BOOT/AS and TCB-AS are the only such exceptions in force.

## Non-goals

POSIX compatibility, dynamic loading, ambient authority, telemetry or phone-home of any kind, treating
the served model or any remote client as trusted, and any security argument that rests on obscurity.

Platform-specific non-goals: the **Secure Enclave** as a security component, and any attempt to present
Apple Silicon as an attested platform.

Apple's **AGX GPU is no longer a non-goal** (owner ruling, 2026-08-02) — see *The GPU is in scope* above.
It remains the largest single body of work on the platform and carries the pending TCB-AS/GPU exception.

Performance is explicitly **not** a non-goal. Slowness requires a named invariant as its justification.

Inbound serving is a goal; it is delivered through a single authenticated, capability-gated path, not by
relaxing the confinement rules above.
