# BraiNIX threat model

Companion to NORTH_STAR.md. The north-star states the invariants as a contract. This document states who the contract defends against, what is trusted to uphold it, how each invariant is verified, and what a violation costs.

## Attacker model

Assumed capabilities of the adversary:

- Supplies arbitrary network input, arbitrary disk and filesystem content, and arbitrary input to any userspace process.
- Fully controls any userspace process it compromises, including device-driver servers.
- Drives the AI assistant with adversarial prompts, including content crafted to elicit privilege escalation or to spoof a consent decision.
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
- The in-tree model weights of the auditor and the assistant.

The model weights are trusted deliberately and uncomfortably. Because their compromise cannot be ruled out by structure, shrinking what their compromise can reach is a permanent design pressure, which is why INV-AUDIT and INV-ASSIST exist: they cap the blast radius of a bad model to visibility and to consented actions respectively.

Outside the TCB, assumed hostile:

- Every userspace process, including the `console` server.
- Every network byte, every disk byte.
- Every device driver. Drivers run as ordinary servers with bounded device capabilities and no special standing.

## Per-invariant verification and blast radius

INV-AUTH. How we know: Kani proofs on the capability and IPC paths, backed by types that make a forged or widened capability unrepresentable. If violated: a process gains authority it was never granted; this is full escalation and is the worst case the design exists to prevent.

INV-MEM. How we know: a structural page-table invariant plus the absence of any heap allocator in the kernel image. If violated: W^X loss enables code injection in the affected domain; no kernel heap removes a whole class of use-after-free and allocator-corruption bugs from the TCB.

INV-IPC. How we know: types that make a shared-memory channel or async queue unrepresentable in tree, plus proofs on the rendezvous path. If violated: shared mutable state between domains reopens TOCTOU and confused-deputy patterns the synchronous model forecloses.

INV-BOOT. How we know: published PCR predictions matched against attested values, plus a reproducible build any third party can reproduce bit for bit. If violated: an attacker can ship or boot an image that does not match its attestation; measured boot is what makes that detectable rather than silent.

INV-AUDIT. How we know: the auditor's frozen capability manifest is the proof. It physically cannot name the capabilities it lacks, so it cannot spawn, mutate the kernel, or reach the network regardless of what its model decides. If violated (only possible via a manifest error): audit visibility is lost; privilege is not, by construction.

INV-ASSIST. How we know: a documented capability-confinement suite the assistant must pass under active prompt injection, with no escalation under any input, plus the same manifest discipline as the auditor. If violated: the assistant could act without consent; the consent trusted path (below) is the structural backstop.

Standing bars, enforced in CI and never allowed to regress:

- Auditor true-positive rate above 95% on the released CTF corpus.
- Machine-checked coverage of kernel invariants driven toward 80%.
- Zero external dependencies in cargo metadata is the target; the current crate list is tracked debt that only decreases.

## Trusted path and the console (open decision)

The consent action that upholds INV-ASSIST happens on the trusted console. A full-color terminal in the `console` server raises a boundary question that must be settled before the feature lands.

The risk is not color. It is that a general escape-sequence interpreter, fed untrusted output (assistant text, auditor findings, filenames, disk or network bytes), can spoof the trusted path two ways: cursor and clear and color codes can redraw or overwrite the consent prompt, and reflection sequences (answerback, device status report, device attributes, cursor-position report, OSC clipboard) can make the terminal write back into its own input stream and forge the consent keystroke.

Design rules that keep the terminal outside the TCB:

- Color is a decision the trusted renderer makes about structured output, never an in-band code interpreted from an untrusted byte stream. Servers send text plus semantic attributes over the capability-mediated channel; the console maps attribute to color. There is no in-band control channel for untrusted text to hijack.
- The terminal is strictly one-way. It never writes to its input under any sequence. Reflection sequences are not implemented.
- If in-band SGR is ever allowed, it is a closed whitelist grammar implemented as a small state machine, fuzzed and Kani-checked like every other in-tree parser, with everything outside the set rendered as literal bytes.

The decision to make: whether the consent path rides on this same console.

- Option A, recommended: a kernel-intercepted secure attention sequence switches to a consent context the `console` server cannot observe or forge. The full-color terminal stays fully untrusted and out of the TCB. INV-ASSIST rests on the kernel, not on console correctness.
- Option B: the consent prompt renders in a reserved region the untrusted output stream is structurally unable to address. Simpler, but it makes the consent renderer part of the trusted path and therefore TCB surface, which contradicts the "trusted set only ever shrinks" principle.

Until this is settled, the color terminal ships only for non-consent output. The consent path does not depend on it.

## Deployment threat profile (outbound-only · single-user · terminal-in-Docker)

This section is **additive**. It does not replace the general attacker model above; it re-ranks it for the specific deployment BraiNIX actually ships in, so design effort is spent where the residual risk concentrates. The general model remains authoritative for any deployment that reintroduces a retired surface.

**Deployment, stated:** BraiNIX is a real x86-64 ring-0 kernel booted under QEMU; Docker is the build/run host. The runtime profile is a single local user, terminal/serial console only, **outbound-only with no inbound listening socket**. (A working **vTPM/swtpm is a hard dependency** for the measured-boot and sealing guarantees and is **currently unmet** — see the architecture spec §0; until it is wired, INV-BOOT and any TPM-anchored guarantee degrade to the honest software-only fallback.)

**What the deployment retires (lowers, does not eliminate):**

- **Inbound network surface.** With no listening socket, remote-initiated attacks against an in-kernel server (e.g. the former SSH server on 2222) are retired for this deployment. The kernel's outbound client code is still exposed to hostile *responses* from the servers it dials.
- **Multi-user lateral movement.** Single-user removes cross-user confused-deputy paths; capability confinement between *processes* still matters (the AI, the device servers).

**Dominant threats, re-ranked for this deployment (highest first):**

1. **Hostile data at rest / on disk.** The largest remaining attacker-controlled byte stream is the disk. The sub-project-A persistence decoder and any on-disk audit/log format parse attacker-controlled bytes in ring 0 → must be `#![no_std]`, fuzzed, and Kani-checked, fail-closed on any malformed length/offset/type tag, and never grow a pool from disk-supplied sizes.
2. **Hostile LLM output.** The advisory AI's `SecurityProposal` tokens are attacker-influenced (prompt injection against trusted-but-uncomfortable weights). The validator that consumes them is a hostile-input parser; per the architecture spec, parsing stays in a userspace validator and the ring-0 apply-primitive is minimized, whitelisted, and incapable of touching invariant state. Consent for any applied change rides the trusted path under the no-reflection terminal rules.
3. **Supply chain.** The toolchain plus the four tracked-debt crates (`sha2`, `chacha20`, `ed25519-dalek`, `curve25519-dalek`) are trusted code paths; the standing bar (zero external deps, list only decreases) is the control, and no new crate may be added (`hashbrown` and any DB/Wasm crate are excluded).
4. **Container / host escape.** Because the build/run host is a container, a QEMU or host-kernel escape is a deployment-level concern outside BraiNIX's own TCB but inside the user's risk picture. Tracked as a deployment requirement (current/patched QEMU, least-privilege container), not a BraiNIX invariant.
