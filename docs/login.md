# BraiNIX Development Access

> **Scope note (2026-08-02):** this page covers **development** access to a BraiNIX instance running under
> QEMU on x86-64. It is not a production access design — production clients reach the system only through
> the authenticated, capability-gated BSP serving path
> ([`architecture/BSP-v1-serving-protocol.md`](architecture/BSP-v1-serving-protocol.md)).
>
> Apple Silicon bring-up uses a debug UART cable rather than anything described here; see
> [`operations/PLATFORM_SUPPORT_MATRIX.md`](operations/PLATFORM_SUPPORT_MATRIX.md) §2.5.

## Local Test Suite

Run the same checks that CI runs:

```bash
bin/test-code.sh          # cargo check + fmt + clippy + capability-verify tests
bin/test-code.sh --fix    # auto-format first, then check
```

| Check | What it validates |
|-------|-------------------|
| `cargo check` | Type-checks bare-metal kernel for `x86_64-unknown-none` |
| `cargo fmt --check` | Enforces the project formatting standard |
| `cargo clippy` | Enforces all workspace lints (full-word names, 6-line limit, etc.) |
| `cargo test -p brainix-capability-verify` | Unit tests for capability/IPC logic (hosted, uses std) |

---

## Docker Dev Environment

The dev container has: Rust nightly-2025-12-01, QEMU x86_64, OpenSSH server.
Source is volume-mounted — edits on the host are immediately visible inside.

### Start the container

```bash
bin/deploy-docker.sh
```

On first run, generates an SSH keypair at `~/.ssh/brainix_dev` (Ed25519, no passphrase).
Subsequent runs reuse the existing key.

### SSH into the dev shell

```bash
ssh -i ~/.ssh/brainix_dev -p 2222 dev@localhost
```

Inside the container you have the full Rust toolchain and can run `cargo` commands
against the mounted source tree at `/home/dev/brainix`.

### QEMU serial console (Phase 1+)

Once Phase 1 adds a kernel entry point and boots a binary, QEMU starts automatically
inside the container and exposes the kernel's serial console on port 4444:

```bash
nc localhost 4444
```

Expected boot output (Phase 1+):

```
================================================================================
 BRAINIX MICROKERNEL  v0.1.0
 x86_64-unknown-none | Rust nightly-2025-12-01
================================================================================
[BOOT] [OK  ] Serial console initialized (COM1 | 115200 8N1)
[BOOT] [OK  ] Kernel entry point reached
[BOOT] [INFO] Build: Phase 0 stub -- boot logging infrastructure online
[BOOT] [INFO] Upcoming phases:
[BOOT] [INFO]   Phase 1: CPU verification, memory map, interrupt handlers
...
[BOOT] [HALT] No userspace ready -- halting processor
```

If the kernel panics, the serial output shows:

```
[PANIC] ========================================
[PANIC] KERNEL PANIC -- system halted
[PANIC] ========================================
[PANIC] panicked at 'example message', src/kernel/src/boot/phases.rs:42:8
[PANIC] Inspect serial output above for context
```

### Other container commands

```bash
bin/deploy-docker.sh --rebuild   # force Docker image rebuild (after Dockerfile changes)
bin/deploy-docker.sh --stop      # stop and remove container
bin/deploy-docker.sh --logs      # tail container stdout
```

---

## CI on GitHub Actions

Push to trigger the full pipeline:

```bash
git push origin <branch>
```

| Job | Trigger |
|-----|---------|
| Style Check | First, blocks all other jobs |
| Supply Chain Audit | After Style |
| Unit Tests | After Supply Chain |
| Kernel Cross-Compile | After Supply Chain |
| Formal Verification (Kani) | After Unit Tests |
| QEMU Integration Test | After Kernel Build + Formal Verification |
| Security Scan | Independent |

The **Style Check** and **Kernel Cross-Compile** jobs are the critical ones for Phase 0.
Formal Verification and QEMU Integration tests depend on Phase 1+ code and may fail until then.

---

## SSH Key Location

```
~/.ssh/brainix_dev       private key (keep secret, never commit)
~/.ssh/brainix_dev.pub   public key (injected into container at runtime)
```

The public key is mounted read-only into the container as `authorized_keys`. No password is set.
To re-key, delete both files and re-run `bin/deploy-docker.sh`.
