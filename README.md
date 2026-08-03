<div align="center">

# BraiNIX

**A security-first microkernel built to serve LLM inference securely to remote clients — written end to end in Rust.**

Every security property is *structural*. Nothing rests on an attacker not knowing something.

[![Site](https://img.shields.io/badge/site-brainix-5af2a8?style=flat-square)](https://jbrahy.github.io/BraiNIXOS/)
[![Target](https://img.shields.io/badge/target-Apple%20Silicon%20%2B%20x86__64-blue?style=flat-square)](#platforms)
[![Rust](https://img.shields.io/badge/rust-no__std%20nightly-orange?style=flat-square)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](#license)

[Website](https://jbrahy.github.io/BraiNIXOS/) · [North star](docs/NORTH_STAR.md) · [Threat model](docs/THREAT_MODEL.md) · [Roadmap](docs/ROADMAP.md) · [Security policy](SECURITY.md)

</div>

---

## What it is

BraiNIX is a minimal, capability-based, security-first microkernel whose purpose is to **serve LLM
inference securely to remote network clients**. It is written end to end in Rust (`no_std`), with a
dependency closure that aims at *itself* — every byte that runs, from bootloader through kernel, network
stack, inference engine, drivers, and crypto, in-tree and reproducibly built from source the project owns.

The security model *is* the product. The same guarantees a hardened microkernel demands — authority is
capability-mediated and never ambient, the kernel is never mapped in user page tables (KPTI), no page is
ever simultaneously writable and executable (W^X), all IPC is synchronous kernel-mediated rendezvous, and
boot is measured — are turned **outward** to protect a network-facing inference service against hostile
clients, hostile prompts, and model-weight compromise. "Secure" is the word that separates BraiNIX from a
commodity inference server.

This is **not** a general-purpose OS. The served model gets all available compute and reserved memory —
and **zero authority**. It is a confined tenant, never a trusted component.

> ⚠️ **Status: research-grade, early, actively developed.** The hardened microkernel substrate boots and
> runs userspace servers today; the secure serving path and in-tree inference engine are in design and
> early implementation. It does not yet serve inference and is not suitable for production use. See
> [Status](#status).

## Security model

Each invariant is named, documented, and individually checkable. *Asserted is not enforced.*

| Invariant | Guarantee |
|---|---|
| **INV-AUTH** | No ambient authority. Every server's capability set is frozen at launch; capabilities are unforgeable typed tokens. A remote client is granted only its own session. |
| **INV-MEM**  | W^X holds for every page, always. No dynamic kernel heap — fixed-size pool allocators only (KPTI per-process page tables). Model weights and KV-cache live in fixed reserved regions, never a growing allocator. |
| **INV-IPC**  | Synchronous rendezvous IPC only. No shared-memory IPC, no async queues. |
| **INV-BOOT** | Every release is measured into the TPM, reproducibly built, and Ed25519-signed, with predicted PCRs published before the artifact ships. ⚠️ **Holds in full on x86-64 only** — see [Platforms](#platforms). |
| **INV-SERVE** | Inbound clients are mutually isolated — no client can name another's session, weights view, or KV state. The network request decoder is a fail-closed, zero-allocation hostile-input parser. |
| **INV-MODEL** | The served model is a confined tenant, never a trusted authority. Its weights are integrity-checked before use; it cannot escalate, read another client's session, or reach the network outside the serving channel. The confinement holds under adversarial prompting. |
| **INV-AUDIT**| The observe-only auditor watches the serving stack and reports — nothing else. It holds no spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege. |
| **INV-GPU** *(active on the primary platform)* | Accelerator DMA is confined by the IOMMU; the GPU driver is an ordinary capability-bounded server with no ambient device authority, and cannot widen its own DMA window. It is the control that makes running Apple's opaque GPU firmware survivable, and must be proven **before** that firmware is ever loaded. Inference is still CPU-first by ordering. ⚠️ **On x86-64 it remains a stated target.** |

See [`docs/security/`](docs/security/) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
contract, attacker model, and verification posture.

## Architecture

- **Microkernel core** — the smallest possible ring-0 surface; drivers, filesystem, network stack, the serving front end, and the inference engine live in userspace.
- **Capability-mediated everything** — no ambient authority; every resource is an unforgeable, typed, bounded, revocable token.
- **KPTI & W^X, structurally** — the kernel is not mapped in user page tables; no page is ever writable *and* executable.
- **Secure serving path** — an authenticated, capability-gated inbound protocol (pre-shared client keys, HKDF-SHA256 key schedule, ChaCha20-Poly1305 records) with mutually isolated per-client sessions.
- **In-tree inference engine** — a `no_std` transformer runtime; the served model runs as a confined tenant with weights in fixed reserved regions.
- **Decomposed network stack** — link, IP, and transport run as isolated servers chained only by synchronous IPC.
- **Multi-arch by design** — a hardware abstraction layer with **Apple Silicon (aarch64)** and **x86-64** as compile-time backends.
- **Reproducible, signed boot** — reproducibly built and Ed25519-signed on both platforms; measured into a TPM on x86-64 only.

## Platforms

BraiNIX targets two platforms at **different assurance levels**. Naming the platform is part of describing
a deployment.

| | Platform | Role | Assurance |
|---|---|---|---|
| **Primary** | **Apple Silicon** — Mac mini M2 Pro (`Mac14,12`, `T6020`, 32 GB) | The serving deployment. CPU + AGX GPU at maximum. |  ⚠️ **No remote attestation, no sealing** |
| **Secondary** | **x86-64** | Development, CI, and attested deployments | ✅ Full — INV-BOOT holds in every clause |

**Why the asymmetry.** Apple Silicon has no TPM and none can be added; the Secure Enclave exposes no
PCR-style extend/quote/seal interface to third-party software. On the primary platform a remote client
**cannot cryptographically verify what it is talking to**, and an early kernel compromise is undetectable
from outside. What survives there is reproducible builds, Ed25519 release signatures, and iBoot-verified
payload integrity at rest — real tamper-resistance, but Apple's trust root, keyed to one machine, proving
nothing to anyone else.

This is structural and permanent, not an unimplemented feature. It is recorded as the signed exception
**INV-BOOT/AS** in the [north star](docs/NORTH_STAR.md). **Deployments requiring attestation or sealing
must run x86-64.** Full detail: [platform support matrix](docs/operations/PLATFORM_SUPPORT_MATRIX.md) ·
[attestation model](docs/operations/ATTESTATION_MODEL.md).

Third-party reverse-engineering work (notably [Asahi Linux](https://asahilinux.org/)) is **reference-only**:
published documentation in, clean-room implementation out. No code is copied, regardless of license.

## Status

Early, actively developed. BraiNIX pivoted from an internal-only hardened microkernel to a
**network-facing secure inference server** (2026-07-07), and Apple Silicon became the primary platform
(2026-08-02). The [north star](docs/NORTH_STAR.md), [threat model](docs/THREAT_MODEL.md), and
[roadmap](docs/ROADMAP.md) are the authoritative, up-to-date contract.

**What exists (the substrate, on x86-64):**
- ✅ Boots under QEMU via a GRUB2 ISO: bootloader → kernel → `[OK] BraiNIX: boot complete`.
- ✅ Userspace ELF loader into KPTI-isolated address spaces with W^X-correct mappings and guard-protected stacks.
- ✅ Capability model, synchronous IPC, decomposed network stack, and a fixed-pool in-kernel store — with Kani proofs and fuzz targets on the hostile-input paths.
- ✅ Measured boot via swtpm, with honest runtime TPM-presence gating.

**Designed, not yet implemented:**
- 📐 Multi-arch HAL — trait design landed ([`HAL.md`](docs/architecture/HAL.md)); **no backend extracted yet**. This gates all Apple Silicon work.
- 📐 BSP v2 serving protocol — [spec landed](docs/architecture/BSP-v2-serving-protocol.md); server not built.

**Not started:**
- ⬜ Apple Silicon platform (ADT parser, boot stub, AIC, DART, RTKit/ANS2, PCIe, Ethernet).
- ⬜ In-tree CPU inference engine and the confined-model tenant.

> ⚠️ BraiNIX does not yet serve inference. It is research-grade and not suitable for production use.

## Requirements

- A nightly Rust toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) with the
  `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview` components.
- Bare-metal target `x86_64-unknown-none` today. `aarch64-unknown-none` is added by the HAL extraction; the
  Apple Silicon boot stub needs a custom in-tree target spec beyond that.
- For Apple Silicon bring-up (not yet started): a Mac mini M2 Pro in Permissive Security, a debug UART cable,
  and a macOS stub install that must remain on disk. Provisioning requires physical presence.
- For the live boot: Docker (the dev container ships QEMU, GRUB, `xorriso`, and `swtpm`).

## Building

```bash
# Type-check, format, lint, and build for the bare-metal target
cargo check   --target x86_64-unknown-none
cargo fmt     --all -- --check
cargo clippy  --workspace --all-targets
cargo build   --release --offline --target x86_64-unknown-none
```

## Running

```bash
# Build the kernel + bootloader + shell, produce a GRUB2 ISO, and boot it under QEMU
bin/run-brainx.sh            # keep running until you interrupt
bin/run-brainx.sh --once     # boot once, assert "boot complete", then exit
```

The wrapper builds and runs everything inside the dev container, streaming the GRUB → bootloader →
kernel chain to your terminal.

## Layout

```
src/kernel/        the microkernel (no_std)
src/bootloader/    multiboot2 bootloader + ELF loader
src/servers/       userspace server libraries (libsyscall, …)
userland/shell/    the userspace shell
docs/              north star, threat model, architecture, security invariants
bin/, docker/      build + live-boot tooling
```

## Documentation

- [North star](docs/NORTH_STAR.md) — the timeless target and the rules that defend it.
- [Threat model](docs/THREAT_MODEL.md) — attacker model, the TCB, per-invariant verification.
- [Architecture](docs/architecture/) — capability model, IPC spec, memory model, the multi-arch HAL, the serving protocol.
- [Security](docs/security/) — invariants, unsafe-code policy.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. BraiNIX holds a high
bar: full-word names, small functions, no unjustified `unsafe`, and every security-relevant change tied
to a named invariant.

## Security

Found a vulnerability? Please **do not** open a public issue — see [SECURITY.md](SECURITY.md) for private
reporting.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at
your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project shall be dual licensed as above, without any additional terms or conditions.
