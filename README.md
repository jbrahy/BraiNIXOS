<div align="center">

# BraiNIX

**A security-first microkernel built to serve LLM inference securely to remote clients — written end to end in Rust.**

Every security property is *structural*. Nothing rests on an attacker not knowing something.

[![Site](https://img.shields.io/badge/site-brainix-5af2a8?style=flat-square)](https://jbrahy.github.io/BraiNIXOS/)
[![Target](https://img.shields.io/badge/target-x86__64%20%2B%20aarch64-blue?style=flat-square)](#building)
[![Rust](https://img.shields.io/badge/rust-no__std%20nightly-orange?style=flat-square)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](#license)

[Website](https://jbrahy.github.io/BraiNIXOS/) · [North star](docs/NORTH_STAR.md) · [Threat model](docs/THREAT_MODEL.md) · [Security policy](SECURITY.md)

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
| **INV-BOOT** | Every release is measured into the TPM, reproducibly built, and Ed25519-signed, with predicted PCRs published before the artifact ships. |
| **INV-SERVE** | Inbound clients are mutually isolated — no client can name another's session, weights view, or KV state. The network request decoder is a fail-closed, zero-allocation hostile-input parser. |
| **INV-MODEL** | The served model is a confined tenant, never a trusted authority. Its weights are integrity-checked before use; it cannot escalate, read another client's session, or reach the network outside the serving channel. The confinement holds under adversarial prompting. |
| **INV-AUDIT**| The observe-only auditor watches the serving stack and reports — nothing else. It holds no spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege. |
| **INV-GPU** *(deferred)* | Accelerator DMA is confined by the IOMMU; the GPU driver is an ordinary capability-bounded server with no ambient device authority. Inference is CPU-first; GPU is a later hardware milestone. |

See [`docs/security/`](docs/security/) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
contract, attacker model, and verification posture.

## Architecture

- **Microkernel core** — the smallest possible ring-0 surface; drivers, filesystem, network stack, the serving front end, and the inference engine live in userspace.
- **Capability-mediated everything** — no ambient authority; every resource is an unforgeable, typed, bounded, revocable token.
- **KPTI & W^X, structurally** — the kernel is not mapped in user page tables; no page is ever writable *and* executable.
- **Secure serving path** — an authenticated, capability-gated inbound protocol (in-tree Ed25519 / X25519 / ChaCha20-Poly1305) with mutually isolated per-client sessions.
- **In-tree inference engine** — a `no_std` transformer runtime; the served model runs as a confined tenant with weights in fixed reserved regions.
- **Decomposed network stack** — link, IP, and transport run as isolated servers chained only by synchronous IPC.
- **Multi-arch by design** — a hardware abstraction layer targeting **x86-64 and aarch64 servers** as compile-time backends.
- **Measured, reproducible boot** — bootloader through kernel is measured into the TPM and Ed25519-signed.

## Status

Early, actively developed. BraiNIX has pivoted from an internal-only hardened microkernel to a
**network-facing secure inference server**; the [north star](docs/NORTH_STAR.md) and
[threat model](docs/THREAT_MODEL.md) are the authoritative, up-to-date contract.

**What exists (the substrate):**
- ✅ Boots under QEMU via a GRUB2 ISO: bootloader → kernel → `[OK] BraiNIX: boot complete`.
- ✅ Userspace ELF loader into KPTI-isolated address spaces with W^X-correct mappings and guard-protected stacks.
- ✅ Capability model, synchronous IPC, decomposed network stack, and a fixed-pool in-kernel store — with Kani proofs and fuzz targets on the hostile-input paths.

**In progress (the direction):**
- 🚧 Multi-arch HAL (x86-64 + aarch64) — trait design landed; x86-64 backend implementation underway.
- 🚧 Secure serving protocol + fail-closed request parser — spec landed.
- 🚧 In-tree CPU inference engine and the confined-model tenant.

> ⚠️ BraiNIX is research-grade and not yet suitable for production use.

## Requirements

- A nightly Rust toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) with the
  `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview` components.
- Bare-metal target `x86_64-unknown-none` today; `aarch64-unknown-none` as the multi-arch HAL lands.
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
