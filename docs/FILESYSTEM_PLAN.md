> # 📋 UNSCHEDULED — accurate design, not on the roadmap
>
> **Reviewed 2026-08-02; re-checked 2026-08-03.** Nothing is being built against this. It is not scheduled
> in [`ROADMAP.md`](ROADMAP.md). Its subtitle still says "x86-64 Operating System"; **x86-64 was dropped as
> a platform on 2026-08-03**, which is one more reason nothing here is scheduled. The body is left
> as-written, per the rule that unscheduled and historical documents are corrected by banner, not rewrite.
>
> The serving product needs **weight loading**, not a general filesystem: the BXW1 loader (P3-T3) reads a
> single measured blob, and on the primary platform storage arrives via RTKit + ANS2 NVMe (AS-4a). A
> general filesystem is a much larger TCB surface than that requires, and adding one would need explicit
> justification under the "trusted set only shrinks" rule.
>
> Companion: [`FILESYSTEM_HARDENING.md`](FILESYSTEM_HARDENING.md), likewise unscheduled.

---

# BraiNIX Filesystem Plan *(unscheduled)*
## Minimal Secure Storage Layout for an Ultra-Secure x86-64 Operating System

Version: 1.0  
Status: Proposed Baseline  
Scope: Boot storage, immutable operating system storage, mutable system state, mount policy, update flow, and future expansion guidance

---

## 1. Purpose

This document defines the recommended filesystem layout for BraiNIX.

The goal is not to choose a filesystem based on popularity or feature count. The goal is to choose a storage design that supports the BraiNIX security model:

- minimal complexity
- strong integrity for the operating system image
- strict separation between immutable code and mutable state
- predictable update behavior
- reduced attack surface
- easier auditing and recovery

The recommended design is a **three-part storage model**:

1. **EFI / boot partition**
2. **immutable operating system partition**
3. **writable state partition**

This is intentionally simpler and more secure than a traditional fully writable Unix-style root filesystem.

---

## 2. Design Principles

The BraiNIX filesystem design must follow these rules:

1. The boot process must start from a firmware-compatible partition.
2. The main operating system image must be immutable during normal operation.
3. Writable state must be stored separately from the operating system image.
4. Integrity and authenticity of the operating system must be verifiable.
5. Mutable system data must not be mixed casually into the immutable operating system image.
6. Encryption and integrity are different goals and must be treated separately.
7. Filesystem complexity is attack surface and must be minimized.
8. The system should prefer whole-image updates over ad hoc mutation of the live root filesystem.

---

## 3. High-Level Recommendation

BraiNIX should use the following storage layout:

### Partition 1 — EFI / Boot Partition
Filesystem type:
- FAT32

Purpose:
- firmware-readable boot partition
- bootloader
- kernel image or kernel stub
- early boot assets required before the main operating system filesystem is mounted

Why:
- UEFI firmware expects a bootable EFI system partition
- FAT32 is used here for compatibility, not because it is trusted as a secure filesystem
- this partition is part of the bootstrapping path, not the main trusted runtime body of the OS

### Partition 2 — Immutable Operating System Partition
Filesystem type:
- EROFS or an equivalent read-only filesystem

Purpose:
- the actual BraiNIX operating system image
- system binaries
- core userspace
- immutable configuration
- libraries
- system services
- possibly kernel-related runtime assets that are not required directly by firmware

Why:
- the operating system should not be writable during normal operation
- an immutable root reduces tampering, persistence, and accidental drift
- a read-only filesystem is easier to reason about and audit
- the root image should be integrity-protected and versioned as a whole

### Partition 3 — Writable State Partition
Filesystem type:
- a small, conservative writable filesystem such as ext4 or a BraiNIX-native equivalent

Purpose:
- logs
- audit state
- mutable configuration
- runtime state
- spool data
- temporary service data that must persist across boot
- optional machine-local data

Why:
- the system needs a place for legitimate change
- mutable state should be isolated from the immutable operating system
- failure recovery and forensics are easier when state lives in a separate partition

---

## 4. Clarified Boot Model

The FAT32 partition is **not** the full operating system.

The recommended boot sequence is:

1. UEFI firmware reads the FAT32 EFI partition.
2. Firmware or bootloader loads the BraiNIX kernel image or boot stub.
3. The BraiNIX kernel starts and performs early initialization.
4. The kernel mounts the immutable operating system partition.
5. The kernel mounts the writable state partition.
6. The system transitions into the full supervised runtime environment.

This means:

- FAT32 is for bootstrapping
- EROFS is for the trusted immutable body of the operating system
- the writable state filesystem is for live system data

---

## 5. Recommended Mount Layout

A recommended BraiNIX v1 mount model would look like this:

- EFI system partition mounted at `/boot` or another reserved boot path
- immutable operating system partition mounted as `/` or `/sysroot`
- writable state partition mounted at `/var`

Optional refinements:

- `/etc` mostly stored in the immutable OS image, with carefully defined writable overrides
- `/tmp` backed by memory or a bounded writable scratch area
- `/home` omitted entirely in the earliest secure admin image, or placed on a separate writable data volume later
- `/audit` optionally separated from general `/var/log` if audit isolation becomes a requirement

### Preferred v1 structure

#### EFI / boot
- `/boot`
- FAT32
- mounted read-only during normal operation if practical

#### Immutable OS
- `/`
- EROFS
- mounted read-only, always

#### Writable state
- `/var`
- writable filesystem
- contains:
  - `/var/log`
  - `/var/lib`
  - `/var/run` or runtime equivalents if not using tmpfs
  - spool and cache data only where explicitly justified

---

## 6. What Goes in Each Area

### 6.1 FAT32 Boot Partition

Should contain only:

- bootloader
- bootloader config
- kernel image or EFI kernel stub
- minimal early-boot artifacts
- signed boot assets as required by the boot chain

Should not contain:

- general mutable runtime state
- normal logs
- user data
- application data
- package caches
- interactive shell configuration
- authentication secrets beyond what is strictly required by the early boot chain

### 6.2 Immutable OS Partition

Should contain:

- BraiNIX system binaries
- core libraries
- immutable service definitions
- default system configuration
- static auth policy templates
- default networking tooling
- base shell/editor/core utility binaries
- the read-only system image manifest

Should not contain:

- changing logs
- writable PID files
- rotating caches
- DHCP leases
- mutable SSH host key state unless those are generated and overlay-managed separately
- console enrollment state
- OTP seeds
- user-modifiable admin state

### 6.3 Writable State Partition

Should contain:

- logs
- audit logs
- DHCP lease state
- mutable host identity state if not sealed into the image
- installed machine enrollment state
- OTP seeds
- USB-key enrollment mappings
- update staging metadata
- runtime databases or small service state

Should not contain by default:

- a second copy of the whole operating system
- uncontrolled package-manager state
- arbitrary developer toolchains
- general-purpose software caches unless clearly justified

---

## 7. Integrity Model

The immutable operating system partition should not merely be read-only. It should also be **integrity-protected**.

Recommended direction:

- use a dm-verity-like block-level verification model for the read-only OS image
- store or bind the root hash into the secure boot / measured boot chain
- verify the image before trusting it as the live operating system body

This gives BraiNIX two important protections:

1. the filesystem is not writable during normal operation
2. the filesystem cannot be silently modified offline without detection

Read-only alone is not enough. Integrity verification is also required.

---

## 8. Encryption Model

Encryption should be treated as a separate layer from filesystem type.

### Immutable OS partition
The main need is integrity and authenticity, not secrecy.

The OS image can remain unencrypted if the threat model focuses on tamper resistance and boot trust.

### Writable state partition
This is where encryption may matter, especially for:

- OTP seeds
- USB-key mappings
- system identity state
- audit-related local metadata
- machine-specific secrets

Recommended direction:

- support per-directory or per-subtree encryption for sensitive state
- keep encryption scope narrow in the first secure version
- do not make the whole system depend on complicated full-disk encryption orchestration unless clearly required by the deployment model

---

## 9. Update Model

The BraiNIX update model should match the filesystem design.

### Recommended update behavior

- do not patch the live immutable OS partition in place
- build a new complete signed system image
- verify the new image
- atomically switch the active OS image reference at boot
- preserve writable state separately
- allow rollback only according to signed and documented policy

This is safer than a traditional mutable-root/package-manager model because it reduces drift and makes the running OS easier to reason about.

---

## 10. Why This Is Better Than a Fully Writable Root Filesystem

A traditional fully writable root filesystem causes several problems:

- the live system drifts over time
- it becomes harder to know what “the system” really is
- malware or misconfiguration can persist more easily
- update rollback and forensics become harder
- logs, configs, binaries, and state all mix together

The BraiNIX model avoids that by separating:

- bootstrapping
- immutable system code
- mutable state

This is much closer to the security model BraiNIX wants.

---

## 11. Why Coda Should Not Be Used

Coda should not be considered for the BraiNIX base filesystem.

Reasons:

- Coda is a distributed filesystem, not a simple local system filesystem
- it adds extra moving parts and distributed-state complexity
- it depends on additional userland components and cache-management behavior
- it is the wrong fit for a minimal, high-assurance local boot/runtime storage design

Even if Coda is historically interesting, it is not an appropriate choice for the BraiNIX base operating system layout.

---

## 12. Why a Feature-Rich Filesystem Is Not Automatically Better

Filesystems with many advanced features may provide useful capabilities, but they also introduce:

- more parser surface
- more recovery modes
- more metadata complexity
- more maintenance burden
- more code paths that must be trusted

BraiNIX should prefer a filesystem plan that is:

- simple
- explicit
- easy to validate
- easy to update safely
- consistent with immutable-image deployment

For BraiNIX v1, fewer features is a strength.

---

## 13. Proposed BraiNIX v1 Partition Table

A simple conceptual layout could be:

### Partition 1 — EFI
- type: EFI system partition
- filesystem: FAT32
- size: small, only as large as required for boot assets

### Partition 2 — BraiNIX OS Image
- type: immutable OS partition
- filesystem: EROFS
- integrity: dm-verity-like verification
- size: sized for full system image plus controlled growth

### Partition 3 — BraiNIX State
- type: writable system state
- filesystem: ext4-like or BraiNIX-native equivalent
- optional encryption for selected directories or the whole partition if later required

Optional future partitions:
- data partition
- audit partition
- recovery partition
- swap, if BraiNIX ever supports swap and the security model permits it

These should not be added to the first secure version unless clearly required.

---

## 14. Recommended v1 Mount Policy

### Always read-only
- EFI partition during normal runtime where practical
- immutable OS partition always

### Writable
- `/var` or BraiNIX state equivalent
- only directories that genuinely need mutation

### Avoid in v1
- writable `/usr`
- writable `/bin`
- writable `/sbin`
- writable `/lib`
- writable full root
- package-managed mutation of core system paths

---

## 15. Special Handling for Configuration

Configuration needs special treatment.

Recommended approach:

- default configuration lives in the immutable OS image
- machine-specific overrides live in writable state
- the override mechanism must be explicit and limited
- it must be possible to tell exactly which config came from the shipped image and which came from the local machine

This avoids turning configuration into an uncontrolled mutation path.

---

## 16. Special Handling for Authentication State

Authentication state must never depend on mutable home-directory storage.

The writable state partition should hold protected system paths for:

- root OTP seed
- USB-key enrollment mappings
- SSH host keys if generated at install time
- admin key enrollment state
- auth recovery metadata if the project later adopts it

These paths must be root-owned and tightly permissioned.

---

## 17. Minimalism Rules

The filesystem plan must remain aligned with BraiNIX minimalism:

1. No extra partitions without clear purpose.
2. No feature-heavy filesystem just because it is fashionable.
3. No mutable root filesystem in the first secure version.
4. No distributed filesystem in the base system.
5. No hidden update state spread throughout the root image.
6. No silent fallback from verified immutable root to writable rescue mode.

---

## 18. Final Recommended BraiNIX v1 Model

The recommended BraiNIX v1 filesystem model is:

- **FAT32 EFI partition** for firmware bootstrapping
- **EROFS immutable operating system partition** for the trusted OS body
- **separate writable state partition** for logs, config changes, runtime data, and machine-local secrets

In plain language:

- the FAT32 partition gets the machine started
- the EROFS partition contains the actual operating system image
- the writable partition contains the data the system needs to change over time

That is the cleanest secure storage design for BraiNIX at this stage.

---

## 19. Short Form

If this document must be reduced to one paragraph:

BraiNIX should not use a single fully writable root filesystem. It should use a FAT32 EFI partition for bootstrapping, a separate EROFS read-only partition for the immutable operating system image, and a third writable partition for system state such as logs, mutable config, audit data, and machine-local secrets. The immutable OS image should also be integrity-protected, and updates should replace the image atomically rather than mutating the live root in place.
