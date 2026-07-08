# BraiNIX north-star

Trust boundary, attacker model, and verification posture live in THREAT_MODEL.md. This document is the timeless target and the rules that defend it.

## The destination

BraiNIX is a minimal, capability-based, security-first x86-64 microkernel whose purpose is to **serve LLM inference securely to remote network clients**. It is written end to end in Rust, and its dependency closure is itself: zero external code, with every byte that runs, from bootloader through kernel, network stack, inference engine, device drivers, libraries, and crypto primitives, in-tree, audited, and reproducibly built from source the project owns. The external crates still vendored today are tracked debt against this rule, not exceptions to it.

The security invariants are the product, not an obstacle to it. "Secure" is the word that separates BraiNIX from a commodity inference server: the same capability model, W^X memory discipline, minimal named TCB, and measured boot that a hardened microkernel demands are turned outward to protect a network-facing inference service against hostile clients, hostile prompts, and model-weight compromise. On that base sit three subsystems: a **secure serving path** that authenticates remote clients and mediates every request through capabilities; an **in-tree inference engine** that runs the served model with all available compute (CPU today; GPU/VRAM on a later hardware milestone) devoted to the model within fixed, reserved regions; and an **observe-only LLM security auditor** that continuously checks the running serving stack against its documented invariants.

## First principles

These decide every tradeoff. When they conflict with convenience — or with throughput — the principle wins unless the owner signs off otherwise in writing.

- Least authority. Nothing holds a capability it does not need, and no capability is ambient. Authority is named, granted, and revocable. A remote client is granted only its own session.
- Fail closed. Absence of an explicit grant is denial. A malformed request, an oversized or corrupt model blob, an error path that cannot prove safety — all deny the operation.
- Structure over secrecy. Security is a property of the design, enforced by the capability model, the type system, or a machine-checked proof. Nothing rests on an attacker not knowing something.
- Minimize and name the trust. The set of components that can violate security is small, written down, and justified. Anything not in it — every remote client, every network byte, every prompt, the served model's outputs — is treated as hostile.
- Every claim is falsifiable. A property that is asserted but not checked does not count as enforced.

## Invariants

The contract. Each is named, documented, and individually checkable. Verification and consequences-of-compromise are in THREAT_MODEL.md.

- INV-AUTH: no ambient authority; every server's capability set is frozen at launch and capabilities are unforgeable.
- INV-MEM: W^X holds for every page, always; no dynamic kernel heap, fixed-size pools only. Model weights and KV-cache live in fixed, reserved regions sized at build time — never a growing allocator.
- INV-IPC: inter-process communication is synchronous rendezvous only; no shared-memory IPC and no async queues exist in tree.
- INV-BOOT: every release is measured into the TPM, reproducibly built, and Ed25519-signed, with predicted PCRs published before the artifact ships.
- INV-SERVE: inbound clients are mutually isolated; no client can name a capability to another client's session, weights view, or KV state. The network request decoder is a fail-closed hostile-input parser; a malformed or over-length request denies, never grows a pool.
- INV-MODEL: the served model is a confined tenant, never a trusted authority. Its weights are integrity-checked before use (a corrupt or oversized blob fails closed); it cannot escalate, cannot read other clients' sessions or other processes, and cannot reach the network except through the capability-mediated serving channel. The confinement holds under adversarial prompting.
- INV-AUDIT: the auditor observes the serving stack and reports and does nothing else; it holds no spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege.
- INV-GPU (deferred milestone): accelerator DMA is confined by the IOMMU; the GPU driver is an ordinary capability-bounded server with no ambient device authority. Until the GPU milestone lands, inference is CPU-only and this invariant is a stated target, not a shipped guarantee.

## What advancing the goal means

- The dependency closure shrinks toward itself. Removing an external crate advances the goal. Adding one is anti-goal — the inference engine, the serving protocol, and the device drivers are written in-tree, not vendored.
- New code lands behind an invariant. A feature that cannot be expressed as, or checked against, the invariants above is not ready.
- The served model earns its resources by staying confined. Give it all available compute and reserved memory; give it no authority. Capability first, capability always; the model is a tenant, never a trusted authority, no matter how central it is to the product.
- The trusted set only ever shrinks. The inbound serving surface is the largest new attack surface; every byte of it that can be moved out of the TCB or proven correct is progress. Any change that enlarges the TCB pays for itself explicitly or does not land.

## Hard lines (do not cross without explicit sign-off)

- No ambient authority anywhere. Capability sets are frozen at launch. A remote client's grant covers only its own session.
- W^X enforced globally and structurally. No page is ever writable and executable — including inference-engine and driver code paths.
- Synchronous rendezvous IPC only. No shared-memory IPC, no async queues.
- No dynamic kernel heap. Fixed-size pool allocators only. "Give all resources to the LLM" is satisfied by large fixed reserved regions for weights and KV-cache, never by adding an allocator.
- No new external crate dependencies. The standing job is to remove the ones still present (multiboot2, sha2, chacha20, ed25519-dalek, x86_64, bitflags, log, uefi-raw, uguid, ptr_meta), not add more. The inference engine and GPU driver are in-tree.
- The auditor never holds spawn, kernel-mutation, or network capability. The served model never reads another client's session or another process, and never makes a network call except through the capability-mediated serving channel.
- No path to security depends on attacker ignorance.

## Non-goals

POSIX compatibility, dynamic loading, ambient authority, telemetry or phone-home of any kind, treating the served model or any remote client as trusted, and any security argument that rests on obscurity. Inbound serving is now a goal; it is delivered through a single authenticated, capability-gated path, not by relaxing the confinement rules above.
