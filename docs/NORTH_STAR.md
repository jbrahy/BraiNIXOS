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

**Primary: Apple Silicon (aarch64).** The reference deployment is a Mac mini M2 (`Mac14,3`, SoC
`T8112`, 32 GB unified memory). Unified-memory bandwidth makes M-series CPUs a credible CPU-inference
platform, and 32 GB is real serving capacity. Owner decision, 2026-08-02.

**Secondary: x86-64.** Retained as the **attested** platform — the only target where INV-BOOT holds in
full (see INV-BOOT/AS below). Any deployment whose threat model requires remote attestation or sealing
runs on x86-64, not on Apple Silicon. x86-64 also remains the development and CI target, and the
platform against which the HAL traits are first proven.

Both are backends behind one hardware abstraction layer (`docs/architecture/HAL.md`). Architecture-
neutral subsystems — the serving protocol, the request parser, the tokenizer, the tensor kernels, the
transformer — are written once and are not permitted to acquire platform assumptions.

## First principles

These decide every tradeoff. When they conflict with convenience — or with throughput — the principle
wins unless the owner signs off otherwise in writing.

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
- **INV-GPU** *(deferred milestone)*: accelerator DMA is confined by the IOMMU; the GPU driver is an
  ordinary capability-bounded server with no ambient device authority. Until the GPU milestone lands,
  inference is CPU-only and this invariant is a stated target, not a shipped guarantee. Apple's AGX GPU
  is explicitly out of scope (see Non-goals).

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
  trusted authority, no matter how central it is to the product.
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

Platform-specific non-goals: Apple's **AGX GPU** (firmware-driven, the single largest reverse-engineering
effort on the platform; INV-GPU is deferred even on x86-64), the **Secure Enclave** as a security
component, and any attempt to present Apple Silicon as an attested platform.

Inbound serving is a goal; it is delivered through a single authenticated, capability-gated path, not by
relaxing the confinement rules above.
