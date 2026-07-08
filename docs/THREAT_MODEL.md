# BraiNIX threat model

Companion to NORTH_STAR.md. The north-star states the invariants as a contract. This document states who the contract defends against, what is trusted to uphold it, how each invariant is verified, and what a violation costs.

BraiNIX now **serves LLM inference to remote network clients**. That reverses the former outbound-only posture and makes the inbound serving path the largest attack surface in the system. This document is rewritten around that reality.

## Attacker model

Assumed capabilities of the adversary:

- Is a remote network client, or controls one. Supplies arbitrary inbound bytes to the serving path: connection setup, authentication attempts, and — once authenticated — arbitrary request payloads and arbitrary prompt content.
- Drives the served model with adversarial prompts, including content crafted to elicit privilege escalation, to exfiltrate another client's session or the weights, or to make the model reach outside its serving channel.
- Supplies arbitrary disk and filesystem content, including malformed model-weight blobs and session/log data.
- Fully controls any userspace process it compromises, including device-driver servers and the serving front end.
- Observes timing and any published artifact (ISO, PCR predictions, source).

Assumed not available to the adversary:

- Defeating the CPU, IOMMU, or TPM as hardware, or breaking Ed25519, SHA-256, ChaCha20, X25519, or AES-256-GCM as primitives.
- Possession of the release-signing private key.
- Physical glitching and side channels below the architectural level are out of scope for v1 and tracked separately.

## Trust boundary

In the TCB, where a single defect can break security:

- The kernel and the bootloader.
- The CPU, the IOMMU, and the TPM 2.0.
- The UEFI Secure Boot and measured-boot chain.
- The Ed25519 release-signing key.
- The in-tree model weights of the served model and the auditor.

The served model's weights are trusted deliberately and uncomfortably: they are loaded, measured, and run, and a compromised or poisoned weight set cannot be ruled out by structure. That is exactly why INV-MODEL and INV-SERVE exist — they cap the blast radius of a bad or hijacked model to a single client's session and deny it any authority, spawn, cross-session read, or network reach outside the serving channel. The model is central to the product and central to nothing in the TCB's authority.

Outside the TCB, assumed hostile:

- Every remote client, every inbound byte, every prompt, and every token the served model emits.
- Every userspace process, including the serving front end and any operator console.
- Every disk byte, including model-weight blobs and the session/log store.
- Every device driver, including the GPU driver on the deferred hardware milestone. Drivers run as ordinary servers with bounded device capabilities and no special standing.

## Per-invariant verification and blast radius

INV-AUTH. How we know: Kani proofs on the capability and IPC paths, backed by types that make a forged or widened capability unrepresentable. If violated: a process or a client gains authority it was never granted; this is full escalation and is the worst case the design exists to prevent.

INV-MEM. How we know: a structural page-table invariant plus the absence of any heap allocator in the kernel image; model weights and KV-cache occupy fixed reserved regions, not a growable allocator. If violated: W^X loss enables code injection in the affected domain; a reintroduced allocator reopens a whole class of use-after-free and allocator-corruption bugs the fixed-pool discipline forecloses.

INV-IPC. How we know: types that make a shared-memory channel or async queue unrepresentable in tree, plus proofs on the rendezvous path. If violated: shared mutable state between domains reopens TOCTOU and confused-deputy patterns the synchronous model forecloses.

INV-BOOT. How we know: published PCR predictions matched against attested values, plus a reproducible build any third party can reproduce bit for bit. If violated: an attacker can ship or boot an image that does not match its attestation; measured boot is what makes that detectable rather than silent.

INV-SERVE. How we know: the inbound request decoder is a `#![no_std]` hostile-input parser with a fuzz target and a Kani harness, fail-closed on any malformed length/offset/type tag; per-client session capabilities are frozen at grant and cannot name another session. If violated: one client reads or corrupts another client's session, weights view, or KV state — a cross-tenant breach and the primary failure the serving design defends against.

INV-MODEL. How we know: the same capability-manifest discipline as the auditor — the served model *physically cannot name* the capabilities it lacks, so no prompt can make it spawn, mutate the kernel, read another session, or reach the network outside the serving channel. Weight integrity is checked against a measured digest before first use. Backed by a confinement suite the model runtime must pass under active prompt injection with no escalation under any input. If violated: the model could act outside its session or exfiltrate across the boundary; the capability manifest is the structural backstop that a bad model cannot defeat by reasoning.

INV-AUDIT. How we know: the auditor's frozen capability manifest is the proof. It physically cannot name the capabilities it lacks, so it cannot spawn, mutate the kernel, or reach the network regardless of what its model decides. It observes the serving stack — connections, capability grants, request/response boundaries — and reports. If violated (only possible via a manifest error): audit visibility is lost; privilege is not, by construction.

INV-GPU (deferred milestone). How we know: the accelerator's DMA windows are confined by IOMMU mappings the driver cannot widen, and the driver holds only bounded device capabilities. Until the GPU milestone lands, inference is CPU-only and this is a stated target, not a shipped guarantee. If violated: a driver or device DMA escapes its window into kernel or cross-domain memory — which is why the IOMMU confinement, not driver correctness, is the control.

Standing bars, enforced in CI and never allowed to regress:

- Auditor true-positive rate above 95% on the released CTF corpus, now measured against the serving stack.
- Machine-checked coverage of kernel invariants driven toward 80%.
- Zero external dependencies in cargo metadata is the target; the current crate list is tracked debt that only decreases. The inference engine and GPU driver add none.

## Trusted path and any operator console

Under the former design the trusted path existed so a local user could consent to an internal assistant *acting on the system*. The served model does not act on the system — it answers client prompts within its confined session — so a per-action consent path is no longer the central concern. What survives is the terminal-safety rule for any operator console that renders untrusted bytes (model output, client data, filenames, disk or network bytes):

- Color and structure are decisions the trusted renderer makes about semantically-tagged output, never in-band codes interpreted from an untrusted byte stream.
- The terminal is strictly one-way. It never writes to its input under any sequence. Reflection sequences (answerback, device status report, device attributes, cursor-position report, OSC clipboard) are not implemented, so untrusted output can never forge a keystroke.
- If in-band SGR is ever allowed, it is a closed whitelist grammar implemented as a small state machine, fuzzed and Kani-checked like every other in-tree parser, with everything outside the set rendered as literal bytes.

If a future feature reintroduces a consent-gated action on the local system, it re-inherits the kernel-intercepted secure-attention-sequence design (a kernel context the console server cannot observe or forge), so any such consent rests on the kernel, not on console correctness.

## Deployment threat profile (inbound-serving · multi-client · network-facing)

This section re-ranks the general model above for the deployment BraiNIX now ships in, so design effort is spent where the residual risk concentrates. The general model remains authoritative.

**Deployment, stated:** BraiNIX is a real x86-64 ring-0 kernel. The near-term CPU-inference MVP boots under QEMU with Docker as the build/run host; the later GPU milestone requires real hardware (VFIO passthrough or bare metal) and is scoped separately. The runtime profile is **network-facing with a single authenticated, capability-gated inbound serving socket**, serving one or more remote clients whose sessions are mutually isolated. (A working **vTPM/swtpm remains a hard dependency** for measured boot, weight measurement, and sealing, and is **currently unmet** — see the architecture spec §0; until it is wired, INV-BOOT and the INV-MODEL weight-measurement anchor degrade to an honest software-only fallback.)

**What the deployment adds back (the reversed posture):**

- **Inbound network surface.** The single largest change from the prior design. A listening socket, connection setup, authentication, and post-auth request handling are all remote-attacker-reachable in or adjacent to ring 0. This surface must be minimized, moved to userspace where possible, and every parser on it fuzzed and Kani-checked before it faces real clients.
- **Multi-client isolation.** More than one remote session may exist; cross-session confused-deputy and cross-tenant read paths (INV-SERVE) are now first-order concerns.

**Dominant threats, re-ranked for this deployment (highest first):**

1. **Hostile remote clients and the inbound protocol.** The connection/auth/request path parses attacker-controlled bytes reachable from the network. It must be `#![no_std]`, fuzzed, and Kani-checked, fail-closed on any malformed length/offset/type tag, and never grow a pool from client-supplied sizes. The authenticated transport reuses only the already-vendored crypto primitives; no new crate.
2. **Hostile prompts against the served model.** Prompt injection targets the trusted-but-uncomfortable weights to escape the session. INV-MODEL + INV-SERVE cap the blast radius to the attacker's own session; the confinement is manifest-enforced and must hold under the injection suite with no escalation under any input.
3. **Model-weight provenance.** The served weights are trusted-but-huge; a poisoned or swapped blob is a supply-chain and integrity concern. Weights are measured against a known digest before use (anchored to measured boot once the vTPM gap is closed), and the loader fails closed on any malformed or oversized blob.
4. **Hostile data at rest / on disk.** Model-weight blobs and the session/log store are attacker-influenceable byte streams parsed in ring 0 or adjacent; the same `#![no_std]`, fuzzed, Kani-checked, fail-closed discipline applies.
5. **GPU DMA (deferred milestone).** On the hardware milestone, an accelerator or its driver DMAing outside its IOMMU window is a cross-domain breach; the IOMMU confinement (INV-GPU), not driver correctness, is the control.
6. **Container / host escape.** For the QEMU/Docker MVP, a QEMU or host-kernel escape is a deployment-level concern outside BraiNIX's own TCB but inside the user's risk picture (current/patched QEMU, least-privilege container). The GPU milestone's bare-metal deployment retires the container layer but adds firmware/IOMMU configuration as the equivalent concern.
