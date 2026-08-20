<div align="center">

# BraiNIX

**A security-first microkernel built to serve LLM inference securely to remote clients — written end to end in Rust.**

Every security property is *structural*. Nothing rests on an attacker not knowing something.

[![Site](https://img.shields.io/badge/site-brainix-5af2a8?style=flat-square)](https://jbrahy.github.io/BraiNIXOS/)
[![Target](https://img.shields.io/badge/target-Apple%20Silicon%20(aarch64)-blue?style=flat-square)](#platform)
[![Rust](https://img.shields.io/badge/rust-no__std%20nightly-orange?style=flat-square)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-AGPL--3.0-green?style=flat-square)](#license)

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
> runs userspace servers today. The serving protocol, its transport cryptography, and every component of
> the inference engine are implemented and host-tested as standalone crates — but the servers that compose
> them into a system are not built, and no part of BraiNIX runs on Apple Silicon yet. It does not serve
> inference and is not suitable for production use. See [Status](#status).

## Security model

Each invariant is named, documented, and individually checkable. *Asserted is not enforced.*

| Invariant | Guarantee |
|---|---|
| **INV-AUTH** | No ambient authority. Every server's capability set is frozen at launch; capabilities are unforgeable typed tokens. A remote client is granted only its own session. |
| **INV-MEM**  | W^X holds for every page, always. No dynamic kernel heap — fixed-size pool allocators only (KPTI per-process page tables). Model weights and KV-cache live in fixed reserved regions, never a growing allocator. |
| **INV-IPC**  | Synchronous rendezvous IPC only. No shared-memory IPC, no async queues. |
| **INV-BOOT** | Every release is reproducibly built and Ed25519-signed, and its payload's integrity is verified at every boot by iBoot against the machine's Secure-Enclave-held local policy. The kernel records a self-reported measurement log — a debugging aid, never evidence. ⚠️ **No remote attestation, no sealing, permanently** — see [Platform](#platform). |
| **INV-SERVE** | Inbound clients are mutually isolated — no client can name another's session, weights view, or KV state. The network request decoder is a fail-closed, zero-allocation hostile-input parser. |
| **INV-MODEL** | The served model is a confined tenant, never a trusted authority. Its weights are integrity-checked before use; it cannot escalate, read another client's session, or reach the network outside the serving channel. The confinement holds under adversarial prompting. |
| **INV-AUDIT**| The observe-only auditor watches the serving stack and reports — nothing else. It holds no spawn, kernel-mutation, or network capability, so its compromise costs visibility, never privilege. |
| **INV-GPU** | Accelerator DMA is confined by the IOMMU; the GPU driver is an ordinary capability-bounded server with no ambient device authority, and cannot widen its own DMA window. It is the control that makes running Apple's opaque GPU firmware survivable, and must be proven **before** that firmware is ever loaded. Inference is still CPU-first by ordering. |

See [`docs/security/`](docs/security/) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
contract, attacker model, and verification posture.

## Architecture

- **Microkernel core** — the smallest possible ring-0 surface; drivers, filesystem, network stack, the serving front end, and the inference engine live in userspace.
- **Capability-mediated everything** — no ambient authority; every resource is an unforgeable, typed, bounded, revocable token.
- **KPTI & W^X, structurally** — the kernel is not mapped in user page tables; no page is ever writable *and* executable.
- **Secure serving path** — an authenticated, capability-gated inbound protocol (pre-shared client keys, HKDF-SHA256 key schedule, ChaCha20-Poly1305 records) with mutually isolated per-client sessions.
- **In-tree inference engine** — a `no_std` transformer runtime; the served model runs as a confined tenant with weights in fixed reserved regions.
- **Decomposed network stack** — link, IP, and transport run as isolated servers chained only by synchronous IPC.
- **Single-architecture by decision** — **Apple Silicon (aarch64)** and nothing else. The in-tree x86-64 code is a frozen reference implementation, not a second target.
- **Reproducible, signed boot** — reproducibly built, Ed25519-signed, and iBoot-verified at rest. **Not measured, not attested** — there is no TPM on the platform.

## Platform

BraiNIX runs on **one** platform.

| Platform | Role | Assurance |
|---|---|---|
| **Apple Silicon (aarch64)** — Mac mini M2 Pro (`Mac14,12`, `T6020`, 32 GB) | The serving deployment, and the only one. CPU + AGX GPU at maximum. | ⚠️ **No remote attestation, no sealing — permanently** |

x86-64 was **dropped as a platform** on 2026-08-03. Its code stays in tree and stays building as the
**frozen reference implementation** the aarch64 port is written against, and is deleted only when aarch64
replaces it. It is not a target, not a deployment, and not a fallback.

**What that costs, plainly.** Apple Silicon has no TPM and none can be added; the Secure Enclave exposes no
PCR-style extend/quote/seal interface to third-party software. A remote client
**cannot cryptographically verify what it is talking to**, and an early kernel compromise is undetectable
from outside. What survives is reproducible builds, Ed25519 release signatures, and iBoot-verified
payload integrity at rest — real tamper-resistance, but Apple's trust root, keyed to one machine, proving
nothing to anyone else. The credential store is likewise **plaintext at rest**: a stolen disk yields every
client and admin key.

This is structural and permanent, not an unimplemented feature. **BraiNIX cannot prove its boot state to a
remote party, and never will** — and with x86-64 gone there is no other target to point such a deployment
at. It is recorded in the [north star](docs/NORTH_STAR.md) as the boot posture (formerly the signed
exception **INV-BOOT/AS**, now the rule). Full detail:
[platform support matrix](docs/operations/PLATFORM_SUPPORT_MATRIX.md) ·
[attestation model](docs/operations/ATTESTATION_MODEL.md).

Third-party reverse-engineering work (notably [Asahi Linux](https://asahilinux.org/)) is **reference-only**:
published documentation in, clean-room implementation out. No code is copied, regardless of license.

## Help wanted — Apple Silicon

**If you have an M-series Mac and want to work on an operating system, this is a good place to start,
and I would genuinely like the help.**

The hard part is done. BraiNIX boots on an M2 Pro, gets itself from EL2 to EL1, walks its own page
tables, takes syscalls, enforces PAC-BTI, and brings a second core out of reset — all verified on the
machine rather than in an emulator. What is missing is breadth: the device drivers between "a kernel
runs" and "a model serves".

**What you would need**

| | |
|---|---|
| Hardware | Any Apple Silicon Mac. The reference is a Mac mini M2 Pro (`Mac14,12`, `T6020`) but the core is not model-specific. |
| Cable | One USB-C cable for the serial console. |
| Host | Any Mac or Linux box running `picocom`/`screen` and m1n1's proxy tooling. |
| Time to first boot | [`docs/operations/APPLE_SILICON_BRINGUP_RIG.md`](docs/operations/APPLE_SILICON_BRINGUP_RIG.md) is the wiring guide. It requires physical presence once, for a security downgrade that cannot be done over SSH. |

**The iteration loop is fast, which is the thing that usually is not.** `bin/as-kernel-probe.sh` builds,
loads, runs and reports in about forty seconds with nobody in the room. AS-1b sat unfinished for two days
against a ten-minute-per-attempt physical loop; five subsystems landed in one session once that was
replaced. You will not be walking to a machine to read one bit.

**Where the work is**, roughly in dependency order:

- **AIC** — the interrupt controller. Nothing above it can be interrupt-driven until it exists.
- **DART** — the IOMMU. [`src/dart/`](src/dart/) has the window model and Kani proofs; the hardware
  backend is unwritten.
- **RTKit / ANS2** — the NVMe path, and therefore persistence.
- **PCIe / Ethernet** — [`src/pcie-config/`](src/pcie-config/) has a capability walker a hostile device
  cannot hang. Everything past enumeration is open.
- **AGX GPU** — the largest single piece, and the one the serving performance argument eventually rests on.

**Two rules that are not negotiable**, both in [`CONTRIBUTING.md`](CONTRIBUTING.md):

1. **Clean-room only.** Third-party reverse-engineering work — notably [Asahi Linux](https://asahilinux.org/)
   — is *reference-only*: published documentation in, independent implementation out. No code is copied,
   whatever its licence says.
2. **No external crates in the kernel.** The dependency floor is a permanent, named exception list, not a
   budget to spend.

Read [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) first —
they are the contract, and a change that crosses one of the hard lines will be refused however good the
code is. Then open an issue describing what you want to take, so two people do not write the same driver.

## Status

Early, actively developed. BraiNIX pivoted from an internal-only hardened microkernel to a
**network-facing secure inference server** (2026-07-07), Apple Silicon became the primary platform
(2026-08-02), and on **2026-08-03 it became the only one**. The [north star](docs/NORTH_STAR.md),
[threat model](docs/THREAT_MODEL.md), and [roadmap](docs/ROADMAP.md) are the authoritative, up-to-date
contract.

**What exists — on the frozen x86-64 reference, which is not a platform. None of it runs on Apple Silicon
yet:**
- ✅ Boots under QEMU via a GRUB2 ISO: bootloader → kernel → `[OK] BraiNIX: boot complete`.
- ✅ Userspace ELF loader into KPTI-isolated address spaces with W^X-correct mappings and guard-protected stacks.
- ✅ Capability model, synchronous IPC, decomposed network stack, and a fixed-pool in-kernel store — with Kani proofs and fuzz targets on the hostile-input paths.
- ✅ Measured boot via swtpm, with honest runtime TPM-presence gating.

**Implemented and host-tested as standalone crates. Each is a finished component; none is wired to any
other, and none of it is reachable from a running system yet:**
- ✅ **Apple Device Tree parser** ([`src/adt/`](src/adt/)) — `no_std`, zero-allocation, fail-closed, with a [written format spec](docs/platform-specs/apple-device-tree-format.md), a boot-args parser, an ADT/boot-args memory-range cross-check, Kani harnesses, and a 46-input fuzz corpus.
- ✅ **BSP v2 serving protocol** — [spec](docs/architecture/BSP-v2-serving-protocol.md) plus the fail-closed wire decoder ([`src/bsp/`](src/bsp/)): zero-alloc, bounded, 16 Kani proofs, an 89-input fuzz corpus.
- ✅ **Transport cryptography** ([`src/transport-crypto/`](src/transport-crypto/)) — PSK handshake FSM, HKDF-SHA256 key schedule, ChaCha20-Poly1305 record layer, HKDF ratchet; 10 Kani proofs, two fuzz corpora.
- ✅ **Inference engine components** — BXW1 weight [format](docs/architecture/BXW1-weight-format.md) and fail-closed decoder ([`src/bxw1/`](src/bxw1/)), tensor kernels ([`src/tensor/`](src/tensor/): matmul with Q8 dequant, RMSNorm, softmax, RoPE, SiLU/SwiGLU), in-tree BPE tokenizer ([`src/tokenizer/`](src/tokenizer/)), and the transformer forward pass with KV cache and sampling ([`src/transformer/`](src/transformer/)).
- ✅ **AS-1a first-light boot stub** ([`src/boot-stub-apple/`](src/boot-stub-apple/)) — the first Apple Silicon payload: entry assembly, s5l UART transmit, ADT-derived UART discovery, banner. Links for `aarch64-unknown-none-softfloat` into a single-segment, relocation-free raw image. **Complete to the hardware gate** — see [its design](docs/architecture/AS-1a-first-light-boot-stub.md) and [the UART fact table](docs/platform-specs/apple-s5l-uart.md). **It has never run**: that needs the bring-up rig.

**Specified, not built — this is the gap between "components" and "a system":**
- 📐 `servd` (session manager), `inferd` (confined model tenant), `modeld` (one-shot weight loader), and `tools/bsp-client/`. **None of these directories exists.**
- 📐 The `Serve`/`Model`/`Gpu`/`Admin` capability types, and the reserved `WEIGHTS_REGION` / `KV_REGION`.

**Cancelled:**
- ⛔ Multi-arch HAL ([`HAL.md`](docs/architecture/HAL.md), SUPERSEDED) — one platform needs no abstraction layer over one backend. Its proof obligations moved to the aarch64 MMU and the DART backend.

**Running on the hardware:**
- ✅ **AS-1a — first light, ran on an M2 Pro 2026-08-16.** The boot stub reaches the s5l UART and prints.
- ✅ **AS-1b — the aarch64 core, complete 2026-08-17, every item verified on the machine.** EL2→EL1, MMU with the hardware walking tables this repository built, exception vectors, timer, SVC entry, PAC-BTI enforcement, kernel-chosen entropy on a part with no RNG, and a second CPU out of reset.

**Not started:**
- ⬜ **The Apple Silicon platform above AS-1b** — AIC, DART, RTKit/ANS2, PCIe, Ethernet, AGX GPU. See [help wanted](#help-wanted--apple-silicon) below.
- ⬜ Userspace FP/SIMD enablement; the adversarial-prompt confinement suite; fuzz execution in CI (the targets are committed but **CI never runs them** — only the Kani proofs run).

Proof coverage is **62.5%** (5 of 8 invariants, 40 Kani proofs, 11 fuzz targets); INV-AUDIT, INV-GPU, and
INV-MODEL are uncovered. Run `cargo run --release --manifest-path tools/proof-coverage/Cargo.toml` for the
current figure.

> ⚠️ BraiNIX does not yet serve inference, and **does not yet run on the platform it targets.** It is
> research-grade and not suitable for production use.

## Requirements

- A nightly Rust toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) with the
  `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview` components.
- Bare-metal targets `x86_64-unknown-none` (the **frozen reference** build, kept green) and
  `aarch64-unknown-none-softfloat` (the AS-1a boot stub). Both are **built-in** rustc targets and are
  pinned in [`rust-toolchain.toml`](rust-toolchain.toml). ~~The Apple Silicon boot stub needs a custom
  in-tree aarch64 target spec~~ — it does not; a custom spec is needed only once PAC-BTI or M2-specific
  CPU tuning is.
- For Apple Silicon bring-up (not yet started): a Mac mini M2 Pro in Permissive Security, a debug UART cable,
  and a macOS stub install that must remain on disk. Provisioning requires physical presence.
- For the live boot: Docker (the dev container ships QEMU, GRUB, `xorriso`, and `swtpm`).

## Building

```bash
# Type-check, format, lint, and build the frozen x86-64 reference (the only bare-metal
# target that exists today; the aarch64 target spec lands with the Apple boot stub)
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
src/kernel/            the microkernel (no_std)
src/bootloader/        multiboot2 bootloader + ELF loader
src/servers/           userspace server libraries (libsyscall, linkd, ipd, transportd, auditd, …)
userland/shell/        the userspace shell

src/adt/               Apple Device Tree + boot-args parser (fail-closed)
src/bsp/               BSP v2 serving-protocol wire decoder (fail-closed)
src/transport-crypto/  PSK handshake, HKDF-SHA256 schedule, ChaCha20-Poly1305 records
src/bxw1/              BXW1 weight-blob decoder (fail-closed)
src/tokenizer/         in-tree BPE tokenizer + vocab parser
src/tensor/            no_std tensor kernels
src/transformer/       forward pass, KV cache, decode loop, sampling
src/*-verify/          Kani proof harnesses (capability, adt, bsp, transport-crypto, bootloader)
src/boot-stub-apple/   AS-1a first-light payload (aarch64, outside the workspace)

fuzz/                  libFuzzer targets + seeded corpora
tools/proof-coverage/  invariant-to-proof coverage tracker
docs/                  north star, threat model, architecture, platform specs, security invariants
bin/, docker/          build + live-boot tooling
```

## Documentation

- [North star](docs/NORTH_STAR.md) — the timeless target and the rules that defend it.
- [Threat model](docs/THREAT_MODEL.md) — attacker model, the TCB, per-invariant verification.
- [Architecture](docs/architecture/) — capability model, IPC spec, memory model, the serving protocol.
- [Security](docs/security/) — invariants, unsafe-code policy.

## Contributing

Contributions are welcome — please read [CONTRIBUTING.md](CONTRIBUTING.md) first. BraiNIX holds a high
bar: full-word names, small functions, no unjustified `unsafe`, and every security-relevant change tied
to a named invariant.

**If you have an M-series Mac, [Help wanted — Apple Silicon](#help-wanted--apple-silicon) is where the
work is and what it needs.** The kernel already boots there; what is missing is drivers.

## Security

Found a vulnerability? Please **do not** open a public issue — see [SECURITY.md](SECURITY.md) for private
reporting.

## License

Copyright (C) 2026 John Brahy.

BraiNIX is free software: you may redistribute it and modify it under the terms of the
**[GNU Affero General Public License, version 3](LICENSE)** as published by the Free Software
Foundation. It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY, without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See
[`LICENSE`](LICENSE) for the full terms.

AGPL-3.0 is chosen deliberately. BraiNIX exists to be **run as a network service**, and section 13
carries the copyleft across that boundary: if you modify BraiNIX and let others use it over a network,
you must offer those users the complete corresponding source of your modified version. Distributing a
binary carries the same obligation. In every case the copyright and license notices must be preserved.

Release `v0.1.0` was published under `MIT OR Apache-2.0` and remains available under those terms.
Everything after it is AGPL-3.0-only.

Third-party code vendored under `vendor/` keeps its own licenses (MIT, Apache-2.0, Unicode-3.0), all of
which are AGPL-3.0 compatible.

Contributions are accepted under the same AGPL-3.0-only terms, without any additional terms or
conditions.
