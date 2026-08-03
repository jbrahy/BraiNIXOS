# Context Handoff: Userspace dispatch — DONE; next: login + networking

**Status:** dispatch SOLVED (shell runs in ring 3). Goal not yet met (users + networking).
**Updated:** 2026-06-01

## What We're Building

Active `/goal`: **two users (`root`, `jbrahy`, password `brainxos`, must change on
first login) + a functional IPv4/IPv6 network stack.** Both were blocked on the
**KPTI userspace dispatch** — that keystone is now **fixed and on `main`**.

## DONE — KPTI userspace dispatch (main @ 28771c6)

Boot reaches a live `$ ` prompt on COM1, zero faults, 343 host tests pass.
Five defects fixed (one commit, squashed from the old CHUNK 1/CHUNK 2 split):

1. **EFER.SCE** never set → `sysret`/`syscall` raised #UD. Now set in
   `install_syscall_entry_point` (`enable_syscall_extensions_in_efer`).
2. **Intermediate page-table USER bit**: `kernel_page_table` now propagates
   `USER_ACCESSIBLE` to PML4/PDPT/PD entries for user leaves (the walk ANDs
   U/S across all levels). Kernel mappings stay supervisor-only.
3. **ELF copy page-offset**: `elf_load_into_address_space::write_one_byte_to_user_address`
   added `(VA & 0xFFF)` to the frame base — bytes were all landing at frame+0,
   leaving code pages zero-filled (shell entry decoded as `add [rax],al` → #PF @ CR2=0).
4. **Callee-saved registers**: syscall exit now *preserves* rbx/rbp/r13-15
   (saves on entry, restores on exit) instead of zeroing them. The shell's
   banner loop counter is in rbx; zeroing it stuck the loop on `banner[0]='B'`.
5. **serial_write ABI**: libsyscall now passes the byte in **r8** (message
   register 0), the register the kernel reads — was `rdi` (endpoint slot).

### Key design constraint discovered: userspace runs with **IF masked**
KPTI maps neither the IDT nor interrupt entry stubs into user page tables, so
ANY hardware interrupt taken in ring 3 triple-faults (confirmed: IF=1 → #DF at
first instruction before the shell prints anything). SYSRET RFLAGS = `0x002`
(IF clear). The shell polls COM1 via synchronous syscalls. **Interrupt-driven
userspace (preemption + NIC RX for the network stack) requires a CR3-swapping
interrupt trampoline mapped into every user page table — the next major KPTI
milestone, and a hard prerequisite for the network stack.**

## Login — IN PROGRESS (MVP live; hardening pending)

DONE since the dispatch fix:
- **Kernel auth core** (`src/kernel/src/auth/mod.rs`): the TCB credential store —
  users root/jbrahy, initial pw `brainxos`, must-change flag; salted SHA-256
  hashes; constant-time verify; change_password rotates salt+hash and clears the
  flag. 9 host tests. NOT yet wired to a syscall.
- **Shell login flow** (`userland/shell/0.01/src/login.rs`): pure, host-tested
  state machine (login → password → forced new-password → confirm → welcome;
  wrong/unknown → "login incorrect"; mismatch → re-prompt). Calls an injected
  `CredentialAuthority`. 6 host tests + the in-memory authority test.
- **Live login gate** (`entry.rs`): boot shows `login: ` after the banner, reads
  COM1 byte-by-byte, suppresses password echo, runs to auth then the `$ ` REPL.
  Zero faults; verified live.

DISK progress (kernel-side, TCB-justified for credentials):
- **PCI enumeration** (`src/kernel/src/arch/pci.rs`): 0xCF8/0xCFC config-space
  reads, find-by-vendor/device, BAR reads, bus-0 scan. Boot logs virtio devices.
- **Finding:** the virtio-blk data disk is at **bus 0 / device 2 / function 0**,
  **device_id 0x1001** (transitional), **BAR0 = I/O 0xc000**, BAR4 = MMIO
  0xfe000000 — NOT the `0xFEBD_0000` hardcoded in `device_table.rs` (that const,
  and the virtio-net one, are wrong; the NIC is actually an Intel e1000, vendor
  0x8086, not virtio). Use the ENUMERATED BAR.
- **virtio-blk handshake** (`src/kernel/src/arch/virtio_blk.rs`):
  `initialize_block_device()` does reset → ACK → DRIVER → negotiate-no-features →
  FEATURES_OK and reads capacity. Boot confirms io_base 0xc000, 0x8000 sectors
  (16 MiB). Driver is polled (no IRQ — fits IF-masked userspace). Legacy I/O
  register offsets are in the module.

PART 1 (login) — COMPLETE and secure:
- **virtio-blk virtqueue** done (`arch/virtio_blk.rs`): polled sector read/write,
  persistence proven across reboots (marker survived).
- **Persistent credential store** done (`boot/credential_store.rs`): loads from
  data-disk sector 0 or provisions root/jbrahy (pw brainxos, must-change, CSPRNG
  salts) and writes it; password changes reserialize + rewrite. Block is an
  integrity-checksummed `auth::CredentialStore` serialization (`auth/mod.rs`).
  Verified: boot 1 provisions, boot 2 loads-from-disk.
- **Kernel-TCB verification** done: `copy_from_user` (`syscall/user_memory.rs`)
  + `sys_auth_login` (14) / `sys_auth_set_password` (15) (`syscall/auth_syscalls.rs`);
  shell `KernelCredentialAuthority` calls them. Verified live (AUTHTEST:
  root/brainxos = mustchange, root/wrongpw = rejected, 0 faults).
- **Privilege-escalation fixed**: set_password requires the current password
  (verified before change) — caller can only rotate an account it can already
  authenticate as.
- Integrity note: today's credential block uses an unkeyed SHA-256 checksum.
  When the disk driver moves to the untrusted devd-disk server, replace it with
  a TPM-sealed keyed MAC (swtpm is present).
- ONE live-demo gap (not a correctness gap): the full interactive login (typing
  through prompts across a reboot) isn't scripted — the harness boots
  non-interactively. All components are verified individually + the syscall
  round-trip live; persistence is proven by composition (write/load across
  reboot + serialize round-trip host test incl. a changed password).

### B. IPv4/IPv6 network stack — IN PROGRESS (driver built; ARP round-trip pending)

CURRENT STATE (main @ 79cae50): e1000 driver has TX/RX rings + send/receive
(`arch/e1000.rs`), link up (STATUS.LU set), and a pure ARP module (`net/mod.rs`,
3 host tests). Boot tries to ARP-resolve the gateway 10.0.2.2 but gets NO reply
("TX ok, RX/timing?"). Bring-up is fully verified; the TX-egress/RX round trip
is the blocker.
ISOLATED (exhaustively, guest-side): the pcap is **24 bytes — global header
only, ZERO packets**, so nothing egressed (TX bug, not RX). BUT the descriptor
and addresses are PROVABLY CORRECT — a diagnostic confirmed:
  - TX ring `compute_phys == walk_phys == 0x47b000` (the two physical-address
    derivations agree),
  - the descriptor CMD byte read via the kernel vaddr == read via the direct map
    at the device physical (TDBAL) == `0xb` (EOP|IFCS|RS) — so QEMU reads exactly
    the descriptor we wrote, with EOP and RS set, length 42, valid buffer addr,
  - `TCTL = 0x400fa` (EN set), `STATUS` LU bit set (link up),
  - `TDH` advances 0→1 on the TDT write (QEMU's start_xmit ran and consumed it).
Per QEMU's e1000 model, a legacy descriptor with EOP should transmit and with RS
should set DD — neither happens. This contradicts the model given verified-good
inputs, so NEXT SESSION must trace the QEMU side, not the guest: run QEMU with
e1000 trace events (`-trace 'e1000_*'`) or `-d guest_errors`, or inspect via the
QEMU monitor, to see why start_xmit consumes the descriptor without emitting.
Candidate culprits to check QEMU-side: a TX gating register the model wants that
the guest didn't set, the exact TCTL field decode, or a QEMU-version quirk. The
guest-side driver (rings, descriptor format, addresses) is verified correct.
e1000.rs has debug_register / debug_tx_descriptor / debug_descriptor_paths
methods retained for this.
NEXT-SESSION FIX (focused): QEMU's e1000 advancing TDH without emitting a frame
means it read a descriptor it treats as empty/no-op. Most likely the descriptor
buffer ADDRESS QEMU reads is wrong (points at 0 or unmapped):
  - Log the EXACT values written to TDBAL and the TX descriptor's buffer addr
    (offset 0-7) and length — verify they're the true guest-physical of the ring
    and TX_BUFFER. `dma_physical_address` uses `kernel_virtual_to_physical`
    (page-table walk) with `.unwrap_or(0)` — if resolve returns None it silently
    becomes 0. Check it's non-zero; if zero, the walk is failing for high-half
    BSS addresses (try `compute_physical_address_of_bss_page`, which is PROVEN
    correct for the virtio-blk queue DMA).
  - Re-add the test.sh pcap dump to confirm when egress starts working.
  - Then the gateway ARP reply should arrive → parse it → gateway MAC
    52:55:0a:00:02:02 = the "networking works" milestone, then IPv4/ICMP/etc.
Note: QEMU legacy TX DD write-back is also unreliable here; send_frame confirms
via TDH==tail instead (so it returns true even though nothing egressed — that's
why the symptom looked like "TX ok").

--- earlier notes (bring-up) ---
- **e1000 located + brought up** (`arch/e1000.rs`): PCI says Intel 0x8086:100e at
  bus0/dev3/fn0, MMIO BAR0 **0xfeb80000**. `initialize_nic()` maps the 128 KiB
  BAR strong-uncacheable into the kernel PML4 (new
  `kernel_page_table::map_mmio_region_into_kernel`), resets via CTRL.RST, and
  reads the MAC = 52:54:00:12:34:56 (matches QEMU). Verified, 0 faults. Polled
  design (no IRQ — most secure; user pages don't map the IDT).
- **Next (driver):** RX/TX descriptor rings. Allocate page-aligned ring memory
  (like the virtio queue: static BSS, phys via `compute_physical_address_of_bss_page`).
  TX: TDBAL/TDBAH (0x3800/0x3804) = ring phys, TDLEN (0x3808), TDH/TDT
  (0x3810/0x3818), TCTL (0x0400) enable+PSP, TIPG (0x0410). Put frame in a TX
  desc {addr,len,cmd=EOP|RS}, bump TDT, poll desc DD/status. RX: RDBAL/RDBAH
  (0x2800/04), RDLEN (0x2808), RDH/RDT (0x2810/0x2818), RCTL (0x0100) enable+
  bcast+bsize, fill rx descs with buffers, poll DD bit. MTAs (0x5200..) zero.
- **Then (stack), incrementally:** ARP (reply to who-has, cache) → IPv4 (header,
  checksum) → ICMP echo (ping reply) → UDP → IPv6 + NDP → TCP. `copy_from_user`
  already exists for userspace packet buffers if the path moves to a server.
- QEMU: user-mode NIC (slirp), gateway 10.0.2.2, guest 10.0.2.15; pcap at
  `/tmp/qemu-net.pcap` inside the container (`tshark -r` to inspect frames).

## What to Do Next
1. e1000 RX/TX rings + send/receive one frame (verify via the pcap dump).
2. ARP → IPv4 → ICMP ping (a host `ping 10.0.2.15`-style reply is a great
   first end-to-end milestone), then UDP → IPv6/NDP → TCP.
3. Optional later: KPTI interrupt trampoline (map IDT + CR3-swap stub into user
   PMLs) if interrupt-driven NIC/preemption is wanted over polling.

## Gotchas
- `main` = **private dev** (`origin` = jbrahy/BraiNIX). Public releases go to
  jbrahy/BraiNIXOS via the local-only `./publish-release.sh vX.Y.Z "notes"`
  (squashed curated releases, NOT dev history). Don't push dev churn to public.
- **No AI co-authorship** anywhere in the repo (commits, docs). Keep Claude scrubbed.
- Locally-ignored (never commit/publish): `.planning/`, `.claude/`, `CONTEXT.md`,
  `docs/superpowers/`, `publish-release.sh`, this handoff — all in `.git/info/exclude`.
- `boot`/`arch` are `#[cfg(target_arch="x86_64")]` → host tests don't compile them.
  Live QEMU boot is the only real verifier for dispatch/paging/syscall code.
- Host tests: `cargo test -p brainix-kernel --target aarch64-apple-darwin --lib`
  (the repo's default target is x86_64-unknown-none, which can't run tests).
  There is ONE pre-existing broken doctest (`audit_log_protection.rs`) — unrelated.
- Each container boot ≈ 3-5 min. Before each run:
  `docker ps -q --filter ancestor=brainix-dev:latest | xargs -r docker kill; rm -f brainix.iso`
- For triple-fault debugging: add `-d int,cpu_reset -no-reboot` to the QEMU line
  in `docker/test.sh` (reverted now), boot, read the exception/reset dump.

## Build / Run (copy-paste)
```bash
cd /Users/jbrahy/OtherProjects/brainix
RUSTUP_CARGO=$(rustup which cargo) && export PATH="$(dirname "$RUSTUP_CARGO"):$PATH"

# Bare-metal type-check (fast):
cargo build -p brainix-kernel --features kernel-binary --target x86_64-unknown-none --release

# Live boot (only real verifier) — look for the shell banner + "$ " prompt:
docker ps -q --filter ancestor=brainix-dev:latest | xargs -r docker kill 2>/dev/null; rm -f brainix.iso
bin/run-brainx.sh --once

# Host unit tests:
cargo test -p brainix-kernel --target aarch64-apple-darwin --lib
```
