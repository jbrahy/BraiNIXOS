# BraiNIX north-star

Trust boundary, attacker model, and verification posture live in THREAT_MODEL.md. This document is the timeless target and the rules that defend it.

## The destination

BraiNIX is a capability-based, security-first x86-64 microkernel OS written end to end in Rust. Its dependency closure is itself: zero external code, with every byte that runs, from bootloader through kernel, userspace servers, libraries, and crypto primitives, in-tree, audited, and reproducibly built from source the project owns. The external crates still vendored today are tracked debt against this rule, not exceptions to it. On that base sit two distinguishing subsystems: an observe-only LLM security auditor that continuously checks the running system against its documented invariants, and a consent-gated AI assistance layer reached through capability-mediated IPC rather than by trusting any one component.

## First principles

These decide every tradeoff. When they conflict with convenience, convenience loses.

- Least authority. Nothing holds a capability it does not need, and no capability is ambient. Authority is named, granted, and revocable.
- Fail closed. Absence of an explicit grant is denial. An error path that cannot prove safety denies the operation.
- Structure over secrecy. Security is a property of the design, enforced by the capability model, the type system, or a machine-checked proof. Nothing rests on an attacker not knowing something.
- Minimize and name the trust. The set of components that can violate security is small, written down, and justified. Anything not in it is treated as hostile.
- Every claim is falsifiable. A property that is asserted but not checked does not count as enforced.

## Invariants

The contract. Each is named, documented, and individually checkable. Verification and consequences-of-compromise are in THREAT_MODEL.md.

- INV-AUTH: no ambient authority; every server's capability set is frozen at launch and capabilities are unforgeable.
- INV-MEM: W^X holds for every page, always; no dynamic kernel heap, fixed-size pools only.
- INV-IPC: inter-process communication is synchronous rendezvous only; no shared-memory IPC and no async queues exist in tree.
- INV-BOOT: every release is measured into the TPM, reproducibly built, and Ed25519-signed, with predicted PCRs published before the artifact ships.
- INV-AUDIT: the auditor observes and reports and does nothing else; it holds no spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege.
- INV-ASSIST: the assistant acts only after explicit per-action consent on the trusted console, cannot read the audit log or other processes, and cannot touch the network without a separate explicit grant. It holds under adversarial prompting.

## What advancing the goal means

- The dependency closure shrinks toward itself. Removing an external crate advances the goal. Adding one is anti-goal.
- New code lands behind an invariant. A feature that cannot be expressed as, or checked against, the invariants above is not ready.
- The AI half earns its place only by staying confined. Capability first, capability always; the model is a tenant, never a trusted authority.
- The trusted set only ever shrinks. Any change that enlarges the TCB pays for itself explicitly or does not land.

## Hard lines (do not cross without explicit sign-off)

- No ambient authority anywhere. Capability sets are frozen at launch.
- W^X enforced globally and structurally. No page is ever writable and executable.
- Synchronous rendezvous IPC only. No shared-memory IPC, no async queues.
- No dynamic kernel heap. Fixed-size pool allocators only.
- No new external crate dependencies. The standing job is to remove the ones still present (multiboot2, sha2, chacha20, ed25519-dalek, x86_64, bitflags, log, uefi-raw, uguid, ptr_meta), not add more.
- The auditor never holds spawn, kernel-mutation, or network capability. The assistant never reads the audit log or other users' processes, and never makes a network call without a separate explicit grant.
- No path to security depends on attacker ignorance.

## Non-goals

POSIX compatibility, dynamic loading, ambient authority, network egress without an explicit grant, telemetry or phone-home of any kind, and any security argument that rests on obscurity.
