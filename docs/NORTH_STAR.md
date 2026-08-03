# BraiNIX north-star

Trust boundary, attacker model, and verification posture live in THREAT_MODEL.md. Phasing and current
status live in ROADMAP.md. This document is the timeless target and the rules that defend it.

**Authority.** This document outranks every other document in the tree. Where any other file disagrees
with it, this file wins and the other file is drift to be fixed. See DOCUMENTATION_MAP.md.

## The destination

**What this project is.** BraiNIX is a craft project. The work is the point, and the artifact is held to
product-grade rigor because that is the only honest way to measure the craft. It is not a market claim,
and nothing in this document should be read as one. Where this file demands proof, speed, or
reproducibility, it is setting an engineering bar for the builder — not describing a business.

BraiNIX is a minimal, capability-based, security-first microkernel whose purpose is to **serve LLM
inference securely to remote network clients**. It is written end to end in Rust, and its dependency
closure is itself: zero external code, with every byte that runs — from boot stub through kernel,
network stack, inference engine, device drivers, libraries, and crypto primitives — in-tree, audited,
and reproducibly built from source the project owns. The external crates still vendored today are
tracked debt against this rule, not exceptions to it — with one permanent exception, the Ed25519
release-signature verification stack, named and justified below.

The security invariants are the product, not an obstacle to it. "Secure" is the word that separates
BraiNIX from a commodity inference server: the same capability model, W^X memory discipline, minimal
named TCB, and measured boot that a hardened microkernel demands are turned outward to protect a
network-facing inference service against hostile clients, hostile prompts, and model-weight compromise.
On that base sit three subsystems: a **secure serving path** that authenticates remote clients and
mediates every request through capabilities; an **in-tree inference engine** that runs the served model
with all available compute devoted to it within fixed, reserved regions; and an **observe-only LLM
security auditor** that continuously checks the running serving stack against its documented invariants.

## Target platform

**Apple Silicon (aarch64), and nothing else.** BraiNIX is single-architecture. The reference deployment is
a Mac mini M2 Pro (`Mac14,12`, SoC `T6020`, 32 GB unified memory). Unified-memory bandwidth makes M-series
CPUs a credible CPU-inference platform, and 32 GB is real serving capacity. Owner decision, 2026-08-02;
made the *only* platform by owner decision, 2026-08-03.

**x86-64 was dropped as a platform on 2026-08-03.** The x86-64 code stays in tree and stays building as the
**frozen reference implementation** the aarch64 port is written against — it is deleted when aarch64
replaces it, not before — but it is not a target, not a deployment, and not a fallback. There is in
particular no attested target to fall back to; see **INV-BOOT** below.

Architecture-neutral subsystems — the serving protocol, the request parser, the tokenizer, the tensor
kernels, the transformer — are written once and are not permitted to acquire platform assumptions. That
rule survives the loss of the second architecture unchanged: it is what keeps the serving path and the
inference engine host-testable on `aarch64-apple-darwin` while the platform work proceeds.

**Vocabulary.** Documents in this tree that say *"the primary platform"* mean **the only platform**. The
word is a residue of the two-platform period and carries no implication that a second one exists.

## Performance is a goal, not a leftover

**On the primary platform, BraiNIX serves as fast as the hardware allows.** Owner decision, 2026-08-02.
The reference machine was bought and sized for inference, and building it slow would be building it
wrong. Throughput is a craft standard, ranked below the invariants and above everything else.

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
- The GPU's payoff is **prefill acceleration plus time-sliced multi-client serving**. Cross-tenant
  batching is forbidden by the tenant mapping policy below, so clients take turns rather than share a
  batch: each turn is faster, but they are still turns. Single-stream decode stays bandwidth-bound and
  gains little. This is **a smaller win than this document previously claimed** — it said the GPU was a
  large win for concurrent serving, and that claim assumed batching that the isolation rules do not allow.
- The cost is the **single largest reverse-engineering effort on the platform**, larger than the entire
  storage-and-network driver chain, and it must be written clean-room from published documentation.

### TCB-AS/GPU — named exception, conditionally signed

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

**Tenant mapping policy.** Model weights are mapped into the GPU's DART window **read-only and
permanently** — they are not client data and there is nothing to unmap between sessions. KV cache is
mapped **strictly per session**: mapped on session entry, unmapped and flushed on exit, and **never two
tenants resident simultaneously**. The GPU time-slices between clients; cross-tenant batching is
forbidden, whatever it would be worth. The consequence is that **INV-SERVE is preserved intact and needs
no exception** — isolation on the GPU is the same isolation as everywhere else, paid for in throughput
rather than in invariants.

**Conditionally signed off by the owner, 2026-08-02.** The exception is in force now, so AGX design and
implementation work may proceed. It is conditional: five preconditions must all be green **before GPU
firmware is ever loaded**, and they are the acceptance criteria for AS-5-T0.

1. Every GPU-fronting DART instance defaults to deny-all.
2. A Kani proof on the **DART backend / HAL IOMMU trait** that its API surface admits no widening
   operation — proving that no consumer, `gpud` included, can widen its own DMA window (`INV-DEV-006`).
   The proof belongs to the confinement, not to the driver.
3. GPU completion records are fuzzed and Kani-checked as hostile input (`INV-PARSE-001`).
4. The tenant mapping policy above is enforced: weights read-only and permanent, KV cache per session,
   never two tenants resident.
5. No iBoot-locked DART on the GPU path — or, if one exists, its locked semantics are honestly
   represented in the HAL trait rather than papered over.

*(Naming note, 2026-08-03: the HAL is cancelled — an eleven-trait abstraction with one backend abstracts
nothing. Preconditions 2 and 5 are unchanged in substance; "the HAL IOMMU trait" now means the DART
backend's own IOMMU trait, which is where that obligation lives. The obligation moved home, not scope.)*

**If any precondition proves unsatisfiable on real hardware, this exception self-voids and AS-5 stops.**
That is the correct failure mode, not an obstacle to route around. Until all five are green, no build
ships with the GPU enabled. INV-GPU is no longer deferred on the primary platform; it is the invariant
that makes this exception survivable, and it must be enforced and proven *before* firmware is loaded,
not after.

## First principles

These decide every tradeoff. When they conflict with convenience, the principle wins unless the owner
signs off otherwise in writing. Throughput is not convenience: see *Performance is a goal* above — it is
a craft standard that ranks below the invariants and above everything else.

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
- **INV-BOOT**: every release is reproducibly built and Ed25519-signed, and its on-disk payload's integrity
  is verified at every boot by iBoot2 against the machine's Secure-Enclave-held local policy. The kernel
  records a **self-reported** software measurement log, which is a debugging aid and never evidence.
  **Remote attestation, sealing, and runtime-chain measurement are permanently unavailable** — the only
  supported platform has no TPM and none can be added. This is the whole of INV-BOOT; see *INV-BOOT is the
  Apple boot posture* below.
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
  proven **before** that firmware is ever loaded.

### INV-BOOT is the Apple boot posture — formerly the exception INV-BOOT/AS

**Signed off by the owner as an exception on 2026-08-02; promoted to the rule on 2026-08-03.** INV-BOOT/AS
was written as a named degradation of a headline invariant on the *primary* platform, on the understanding
that x86-64 remained available as the undegraded one. Decision 1 of 2026-08-03 dropped x86-64 as a
platform, so there is no undegraded platform for the exception to be an exception *to*. **What INV-BOOT/AS
described is now simply what INV-BOOT means.** It is listed in the exceptions ledger below and in every
subordinate ledger as **superseded — now the rule**, kept named so the exception count stays checkable
rather than silently dropping by one.

Apple Silicon has no TPM, and none can be added — there is no LPC/SPI TPM header, and a USB TPM is not a
root of trust. The Secure Enclave is **not** a TPM substitute: it exposes no PCR-style extend/quote/seal
interface to third-party software, its protocol is proprietary and undocumented, and driving it from a
non-Apple kernel is out of scope.

INV-BOOT is therefore satisfied **only** in these clauses, everywhere, always:

- **Reproducible build** — unchanged. A third party can rebuild the published payload bit-for-bit.
- **Ed25519 release signature** — unchanged. These are properties of the artifact, not the platform.
- **Boot-time payload integrity** — real and hardware-rooted, but *Apple's* root, not ours: under the
  `kmutil` local-policy flow, iBoot2 verifies the Image4-wrapped payload against a Secure-Enclave-held,
  device-local policy at every boot. A tampered on-disk payload fails to boot.
- **Software-only measurement log** — the kernel hashes what it loads (weights, servers) and records the
  log. Self-reported, and therefore worthless against an attacker who compromised the kernel early.

What is **permanently lost** — not deferred, not scheduled, not achievable by any later phase:

- **Remote attestation.** No quote. A remote party cannot distinguish a genuine BraiNIX boot from a
  compromised one. This is the single capability that most distinguished BraiNIX from a commodity
  inference server, and it is gone.
- **Sealing.** No secrets bound to boot state. Data at rest is protected only by what the kernel does at
  runtime, and the credential store is consequently **plaintext at rest** — see THREAT_MODEL.md.
- **Runtime-chain measurement.** Detection of a divergent boot chain — the exact property INV-BOOT's
  blast-radius entry exists for — is unavailable.

**There is nowhere to move a deployment that needs these.** The previous wording sent such deployments to
x86-64; that platform no longer exists, and the escape hatch is deleted rather than repointed. Stated
without softening: **BraiNIX cannot prove its boot state to a remote party, and never will.** A deployment
whose threat model requires remote attestation or sealing cannot be served by BraiNIX at all. That is the
honest answer, and no configuration, target, or later phase changes it.

### TCB-AS — unavoidable trusted components, Apple Silicon

Also a consequence of the primary-platform decision. On Apple Silicon we can never own the first
instructions: **SecureROM**, **iBoot1**, **iBoot2**, and **sepOS** are Apple-signed, immutable, and
always running. They join the trusted computing base whether we like it or not, and they are closed
source, so the dependency-closure rule ("every byte that runs is in-tree") is permanently violated on
this target by components we cannot remove, audit, or replace. A macOS stub install must remain on disk
for the paired recoveryOS and firmware volumes; "bare metal" here means "our kernel is the OS," not
"Apple software is absent." Enumerated in THREAT_MODEL.md.

### Named crypto exception — Ed25519 release-signature verification

**Signed off by the owner, 2026-08-02.** Recorded here rather than tracked as debt because it is
permanent and deliberate: a named hole in "every byte that runs is in-tree," not something a later phase
pays off.

The serving transport needs no asymmetric crypto — it uses pre-shared per-client keys, HKDF-SHA256
session-key derivation, and ChaCha20-Poly1305 records, and all four of those primitives are constant-time
by construction and are specified to be in-tree — `sha2` and `chacha20` are still vendored until that
reimplementation lands. INV-BOOT's release signature is the different case. Verifying an Ed25519
signature means computing `[8][s]B = [8]R + [8][k]A` over edwards25519, which requires decompressing a
point by modular square root. That is curve25519 field arithmetic, and there is no formulation of the
check that avoids it.

The verification stack — `ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle` — therefore
**stays vendored, verify-only, permanently.** All signing paths go: once the outbound SSH client is
removed, nothing in tree holds a private key or signs anything.

The rationale is correctness, not side channels. No secret enters verification, so there is no
side-channel argument for owning this code. There is a strong argument against hand-rolling it: a
point-decompression bug means accepting **forged release signatures**, and `fiat-crypto`'s field
arithmetic is machine-verified against a formal specification — a stronger correctness claim than this
project could produce by hand for the same effort. Reimplementing it would *lower* assurance, and "every
claim is falsifiable" forbids trading a machine-checked property for an unchecked one to satisfy a
different rule.

The cost, stated plainly: **wire compatibility with stock OpenSSH clients is forfeited.** OpenSSH has no
pre-shared-key mode, and the one key exchange that avoids curve arithmetic —
`diffie-hellman-group14-sha256` — requires constant-time bignum modular exponentiation, a harder
assurance problem than curve25519. Clients speak the BSP protocol or they do not connect.

## What advancing the goal means

- The dependency closure shrinks toward itself. Removing an external crate advances the goal. Adding one
  is anti-goal — the inference engine, the serving protocol, and the device drivers are written in-tree,
  not vendored. The crypto primitives are the concrete case: the in-tree set is **SHA-256, HKDF,
  ChaCha20, and Poly1305**, reimplemented from their specifications, which deletes `sha2` and `chacha20`.
  Third-party reverse-engineering work (notably Asahi Linux) is **reference-only**: we read published
  documentation and reimplement from understanding; we do not copy code, under any license. Where only
  source documents a behavior, a **two-role clean room is enforced** — a procedure, not a good intention:
  - A **spec author** role may read the reverse-engineered source. It emits nothing but fact tables —
    register offsets, struct field layouts, sequence diagrams, state machines — into
    `docs/platform-specs/`. Every spec file carries a provenance header naming its sources and a
    **firmware-version field**, because the AGX firmware ABI is versioned per macOS release and a fact
    table with no version recorded is a fact table about an unknown machine.
  - An **implementer** role is denied access to that source and works only from the spec file.
  - The honest limit, stated rather than glossed: this wall protects **code provenance, not knowledge
    provenance**. It makes copying impossible and the derivation auditable; it does not make the
    implementer's understanding independent of the source that produced the spec. We claim the first and
    do not claim the second.
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
  sha2, chacha20, `x86_64` — the crate, still vendored by the frozen reference — bitflags, log, uefi-raw,
  uguid, ptr_meta), not add more. The in-tree crypto set
  is SHA-256, HKDF, ChaCha20, and Poly1305, which deletes `sha2` and `chacha20`. The Ed25519
  *verification* stack is the one family that stays, under the named crypto exception above. The
  inference engine, the device drivers, and every Apple Silicon platform component are in-tree.
- **No secret ever enters a build artifact.** Client and admin keys are enrolled at runtime and persisted
  by the kernel's credential store; none is ever compiled in. Session keys come from a symmetric HKDF
  ratchet — session key *n* is derived from chain key *n*, the chain then advances and the old key is
  deleted — which buys forward secrecy from symmetric primitives alone. Stated plainly: **until the
  ratchet lands there is no forward secrecy**, and a disclosed pre-shared key retroactively decrypts
  every recorded session. The break-glass admin key is provisioned over the serial console and is
  **never rotatable over the network**, so a compromised admin session cannot lock the owner out. The
  reason is the reproducible-build clause of INV-BOOT: a compile-time secret means either the published
  payload contains the secret or the deployed payload differs from the published one, and
  reproducibility that describes an image nobody runs is not reproducibility.
- No copied code from reverse-engineering projects, regardless of their license. Documentation in,
  clean-room implementation out.
- The auditor never holds spawn, kernel-mutation, or network capability. The served model never reads
  another client's session or another process, and never makes a network call except through the
  capability-mediated serving channel.
- No path to security depends on attacker ignorance.
- **Degrading a named invariant requires a written, named exception with owner sign-off, recorded in this
  document.** Four are named here: **INV-BOOT/AS** — *superseded 2026-08-03, now the rule*, retained by
  name so the count stays checkable — plus TCB-AS, the conditionally signed TCB-AS/GPU, and the named
  Ed25519 verification exception. Those are the only such exceptions in force.

## Non-goals

POSIX compatibility, dynamic loading, ambient authority, a general-purpose remote shell, telemetry or
phone-home of any kind, treating the served model or any remote client as trusted, and any security
argument that rests on obscurity.

**A second architecture is a non-goal** (owner decision, 2026-08-03). BraiNIX is single-architecture
aarch64/Apple Silicon. Adding another architecture — reviving x86-64 as a target or porting to anything
else — requires reversing that decision in this document, not a build-system change. The in-tree x86-64
code is a frozen reference implementation, not a dormant target.

Platform-specific non-goals: the **Secure Enclave** as a security component, and any attempt to describe
BraiNIX as attested.

Apple's **AGX GPU is no longer a non-goal** (owner ruling, 2026-08-02) — see *The GPU is in scope* above.
It remains the largest single body of work on the platform and carries the conditionally signed
TCB-AS/GPU exception.

Performance is explicitly **not** a non-goal. Slowness requires a named invariant as its justification.

Inbound serving is a goal; it is delivered through a single authenticated, capability-gated path, not by
relaxing the confinement rules above. That one path carries two session types, distinguished by
capability and by nothing else. **Client sessions** hold `CapServe` and can only run inference. **Admin
sessions** hold `CapAdmin` and can only invoke a fixed, enumerated verb set — enroll-key, revoke-key,
load-weights, read-audit-log, restart-server, reboot. Administration is explicitly **not a
general-purpose shell**: a shell that can do anything is ambient authority under another name, which is
exactly what the capability model exists to forbid. The serial console is the break-glass path when the
network path is unusable or untrusted.
