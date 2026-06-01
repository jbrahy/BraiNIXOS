<div align="center">

# BraiNIX

**A capability-based, security-first x86-64 microkernel — written end to end in Rust.**

Every security property is *structural*. Nothing rests on an attacker not knowing something.

[![Site](https://img.shields.io/badge/site-brainix-5af2a8?style=flat-square)](https://jbrahy.github.io/BraiNIXOS/)
[![Target](https://img.shields.io/badge/target-x86__64--unknown--none-blue?style=flat-square)](#building)
[![Rust](https://img.shields.io/badge/rust-no__std%20nightly-orange?style=flat-square)](rust-toolchain.toml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-green?style=flat-square)](#license)

[Website](https://jbrahy.github.io/BraiNIXOS/) · [North star](docs/NORTH_STAR.md) · [Threat model](docs/THREAT_MODEL.md) · [Security policy](SECURITY.md)

</div>

---

## What it is

BraiNIX is a small, security-first microkernel operating system for x86-64, written end to end in
Rust (`no_std`). It targets seL4-level *structural* security guarantees: authority is capability-mediated
and never ambient, the kernel is never mapped in user page tables (KPTI), no page is ever simultaneously
writable and executable (W^X), and all inter-process communication is synchronous, kernel-mediated
rendezvous. Drivers, the filesystem, and the network stack all run as isolated userspace servers with
bounded capability sets.

This is **not** a general-purpose OS. It is a deliberate, minimal, auditable system whose long-term goal
is a dependency closure of *itself* — every byte that runs, from bootloader through kernel, userspace
servers, libraries, and crypto, in-tree and reproducibly built from source the project owns.

## Security model

Each invariant is named, documented, and individually checkable. *Asserted is not enforced.*

| Invariant | Guarantee |
|---|---|
| **INV-AUTH** | No ambient authority. Every server's capability set is frozen at launch; capabilities are unforgeable typed tokens. |
| **INV-MEM**  | W^X holds for every page, always. No dynamic kernel heap — fixed-size pool allocators only. Per-process page tables (KPTI). |
| **INV-IPC**  | Synchronous rendezvous IPC only. No shared-memory IPC, no async queues. |
| **INV-BOOT** | Every release is measured into the TPM, reproducibly built, and Ed25519-signed, with predicted PCRs published before the artifact ships. |
| **INV-AUDIT**| The observe-only auditor reports and nothing else — it holds no spawn, kernel-mutation, or network capability. |
| **INV-ASSIST** | Any assistance layer acts only after explicit per-action consent on the trusted console, reached through capability-mediated IPC. A tenant, never a trusted authority. |

See [`docs/security/`](docs/security/) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for the full
contract, attacker model, and verification posture.

## Architecture

- **Microkernel core** — the smallest possible ring-0 surface; drivers, filesystem, and network stack live in userspace.
- **Capability-mediated everything** — no ambient authority; every resource is an unforgeable, typed, bounded, revocable token.
- **KPTI & W^X, structurally** — the kernel is not mapped in user page tables; no page is ever writable *and* executable.
- **Decomposed network stack** — link, IP, and transport run as three isolated servers chained only by synchronous IPC.
- **One server per device** — each device gets its own isolated server with a bounded capability set.
- **Measured, reproducible boot** — bootloader through kernel is measured into the TPM and Ed25519-signed.

## Status

Early, actively developed. Current milestones:

- ✅ Boots under QEMU via a GRUB2 ISO: bootloader → kernel → `[OK] BraiNIX: boot complete`.
- ✅ Userspace ELF loader: the shell server is loaded into a fresh KPTI-isolated address space with W^X-correct mappings and a guard-protected stack.
- 🚧 First-entry dispatch to Ring 3 (the KPTI syscall trampoline) — in progress.

> ⚠️ BraiNIX is research-grade and not yet suitable for production use.

## Requirements

- A nightly Rust toolchain (pinned in [`rust-toolchain.toml`](rust-toolchain.toml)) with the
  `rust-src`, `rustfmt`, `clippy`, and `llvm-tools-preview` components.
- Target `x86_64-unknown-none`.
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
docs/              architecture, security invariants, threat model, operations
bin/, docker/      build + live-boot tooling
```

## Documentation

- [North star](docs/NORTH_STAR.md) — the timeless target and the rules that defend it.
- [Threat model](docs/THREAT_MODEL.md) — protected assets, attacker classes, the TCB.
- [Architecture](docs/architecture/) — capability model, IPC spec, memory model.
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
