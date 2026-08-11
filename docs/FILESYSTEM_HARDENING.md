> # 📋 UNSCHEDULED — accurate design, not on the roadmap
>
> **Reviewed 2026-08-02.** An addendum to [`FILESYSTEM_PLAN.md`](FILESYSTEM_PLAN.md), which is itself
> unscheduled. Nothing is being built against either. See [`ROADMAP.md`](ROADMAP.md).

---

# Brainix Filesystem Hardening Addendum *(unscheduled)*

## Purpose
This document strengthens the existing filesystem plan by adding mandatory security controls, clarifications, and protections identified during red-team review.

---

## 1. Mandatory Boot Chain Integrity

### Requirement
The system MUST implement a full chain of trust:

1. Firmware verifies bootloader (Secure Boot or equivalent)
2. Bootloader verifies kernel
3. Kernel verifies root filesystem integrity
4. Root filesystem hash must be signed or measured

### Implementation
- Signed kernel images
- Signed bootloader configuration
- dm-verity (or equivalent) root hash embedded or verified
- Optional: TPM measured boot

---

## 2. Immutable OS Integrity (Mandatory)

### Requirement
The immutable OS partition MUST be:
- Read-only
- Integrity-protected using dm-verity or equivalent

EROFS alone is NOT sufficient.

---

## 3. Writable Partition Segmentation

### Required Layout
- /var/log
- /var/lib
- /var/tmp
- /var/cache (optional)
- /secrets (encrypted)
- /audit (optional, append-only)

---

## 4. Anti-Rollback Protection

### Requirement
System MUST prevent rollback to older images.

### Implementation
- TPM counter or secure version tracking
- Reject older versions unless explicitly allowed

---

## 5. Mount Flag Hardening

### Examples

/var/log:
- nodev
- nosuid
- noexec

/var/tmp:
- nodev
- nosuid
- noexec

/secrets:
- nodev
- nosuid
- noexec
- encrypted

Root:
- ro
- nodev

---

## 6. Boot Partition Restrictions

- Mounted read-only after boot
- Minimal size
- Only signed artifacts
- No runtime writes

---

## 7. Configuration Model

- Immutable defaults
- Writable overrides
- Explicit precedence

---

## 8. Secrets Handling

- Stored in /secrets
- Root-owned
- Strict permissions
- Encrypted

---

## 9. tmpfs for /tmp

- Memory-backed
- Cleared on reboot

---

## 10. Logging and Audit

- Separate audit logs
- Append-only recommended

---

## 11. No Scripts in Trusted Path

- Avoid shell scripts in boot/auth

---

## 12. Filesystem Manifest

- Maintain expected file list
- Detect anomalies

---

## Final Summary

Brainix filesystem must provide:

- Verified boot chain
- Immutable OS
- Segmented writable state
- Hardened mounts
- Anti-rollback protection
- Minimal attack surface
