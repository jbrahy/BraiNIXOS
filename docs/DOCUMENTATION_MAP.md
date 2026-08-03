# BraiNIX documentation map

Every Markdown file in this repository, what it is for, and whether it is current. Read this before
trusting any other document.

**Last reconciled:** 2026-08-02, against the Apple-primary platform decision.

## Authority order

When two documents disagree, the higher one wins and the lower one is drift to be fixed.

1. **[`NORTH_STAR.md`](NORTH_STAR.md)** — the contract: destination, first principles, invariants, hard
   lines, non-goals. Named invariant exceptions (INV-BOOT/AS, TCB-AS) live here and nowhere else.
2. **[`THREAT_MODEL.md`](THREAT_MODEL.md)** — attacker model, trust boundary, per-invariant verification
   and blast radius, deployment threat profile.
3. **[`ROADMAP.md`](ROADMAP.md)** — phasing, task breakdown, status, per-component "done" gate, risks.
4. **[`../CONTEXT.md`](../CONTEXT.md)** — current session state; the working answer to "where are we."
5. Everything else — architecture specs, security policy, operations policy. Subordinate to all of the
   above.

Two rules follow from this ordering:

- **Invariants are stated once**, in NORTH_STAR.md. Other documents may restate them for context but must
  not introduce, reword, or qualify one. A qualification that exists only in a subordinate document is a
  bug.
- **Roadmap and status live in-tree**, in ROADMAP.md. Planning files outside the repository are not
  authoritative and must not be relied on.

## Status vocabulary

| Status | Meaning |
|---|---|
| **CURRENT** | Reconciled with the authority spine. Trust it. |
| **SUPERSEDED** | Replaced by a named successor. The body is **preserved unedited** under a ⛔ banner that names the replacement and says why. Deleting would have destroyed content that is still useful as background; leaving it unmarked would have left two documents competing for authority. |
| **ARCHIVED** | A historical record of what was true at the time. **Not** maintained, **not** reconciled, and deliberately left as-written under a ⛔ banner. Do not edit these to match current reality — that would destroy the record. |
| **UNSCHEDULED** | Describes a real design that is not on the roadmap, marked with a 📋 banner. Accurate as a design, but nothing is being built against it. |

Every non-CURRENT file carries its banner **in the file itself**, so a reader who arrives by search rather
than through this index still sees the warning.

---

## Entry points

| File | Status | What it is |
|---|---|---|
| [`../README.md`](../README.md) | CURRENT | Public front door: what BraiNIX is, invariant table, platform posture, build/run. |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | CURRENT | How to contribute; the gates a change must pass. |
| [`../SECURITY.md`](../SECURITY.md) | CURRENT | Vulnerability disclosure policy. |
| `../CONTEXT.md` | CURRENT — **local only** | Session state, active work, build commands, gotchas. **Deliberately git-excluded** (`.git/info/exclude`), so it does not appear in a fresh clone. It is the working answer to "where are we"; `ROADMAP.md` is the committed equivalent. |

## The authority spine

| File | Status | What it is |
|---|---|---|
| [`NORTH_STAR.md`](NORTH_STAR.md) | CURRENT | The contract. Outranks everything. |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | CURRENT | Attacker model, TCB, per-invariant verification. |
| [`ROADMAP.md`](ROADMAP.md) | CURRENT | Phasing and status. In-tree source of truth. |
| `DOCUMENTATION_MAP.md` | CURRENT | This file. |

## Governance

| File | Status | What it is |
|---|---|---|
| [`../PROJECT_RULES.md`](../PROJECT_RULES.md) | CURRENT | Mandatory project-level constraints on architecture, code, CI, and governance. |
| [`../CODE_STANDARDS.md`](../CODE_STANDARDS.md) | CURRENT | Naming, function size, and style rules for BraiNIX-authored Rust. |
| [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) | CURRENT | The invariants expanded: enforcement mechanism and evidence strategy per invariant. Restates NORTH_STAR.md, never overrides it. |
| [`security/UNSAFE_CODE_POLICY.md`](security/UNSAFE_CODE_POLICY.md) | CURRENT | Unsafe Rust is prohibited by default; the allowlist and its justification discipline. |
| [`security/TCB_EXCEPTION_001_IN_KERNEL_SQL.md`](security/TCB_EXCEPTION_001_IN_KERNEL_SQL.md) | CURRENT | Approved exception: the in-kernel SQL engine in ring 0. Owner sign-off 2026-06-27. |

**Exceptions in force.** Three, all requiring owner sign-off: **INV-BOOT/AS** and **TCB-AS** (in
NORTH_STAR.md, signed 2026-08-02) and **TCB-EXCEPTION-001** (in-kernel SQL, signed 2026-06-27). There are
no others. Any document claiming an exemption not on this list is drift.

## Architecture

| File | Status | What it is |
|---|---|---|
| [`architecture/HAL.md`](architecture/HAL.md) | CURRENT | Hardware abstraction layer trait design. Delivered by P1-T1. |
| [`architecture/BSP-v1-serving-protocol.md`](architecture/BSP-v1-serving-protocol.md) | CURRENT | The inbound serving protocol: framing, mutual auth, session lifecycle, explicit max lengths. Delivered by P2-T1. |
| [`architecture/CAPABILITY_MODEL.md`](architecture/CAPABILITY_MODEL.md) | CURRENT | Capability types, grant/derive/revoke rules, unforgeability argument. |
| [`architecture/IPC_SPEC.md`](architecture/IPC_SPEC.md) | CURRENT | Synchronous rendezvous IPC: message format, blocking semantics, proof obligations. |
| [`architecture/MEMORY_MODEL.md`](architecture/MEMORY_MODEL.md) | CURRENT | Address-space layout, fixed-pool allocation, W^X enforcement, reserved weight/KV regions, page-size parametricity. |

## Operations

| File | Status | What it is |
|---|---|---|
| [`operations/PLATFORM_SUPPORT_MATRIX.md`](operations/PLATFORM_SUPPORT_MATRIX.md) | CURRENT | Which platforms are supported at which assurance level, and what each one costs in invariant terms. |
| [`operations/ATTESTATION_MODEL.md`](operations/ATTESTATION_MODEL.md) | CURRENT | Measured boot and attestation — including exactly what is unavailable on Apple Silicon. |
| [`operations/DEVICE_ISOLATION_POLICY.md`](operations/DEVICE_ISOLATION_POLICY.md) | CURRENT | DMA confinement policy across VT-d and DART. |
| [`operations/RELEASE_AND_SIGNING_POLICY.md`](operations/RELEASE_AND_SIGNING_POLICY.md) | CURRENT | Reproducible build, Ed25519 signing, and per-platform payload delivery. |

## Subsystem specs and policy

| File | Status | What it is |
|---|---|---|
| [`auth/SSH_AUTH_POLICY.md`](auth/SSH_AUTH_POLICY.md) | UNSCHEDULED | Remote-access policy for the SSH server. The SSH server is scheduled for **deletion** at P2-T6, replaced by the BSP serving path. |
| [`auth/GOOGLE_AUTH_OTP_AND_CONSOLE_USB_LOGIN.md`](auth/GOOGLE_AUTH_OTP_AND_CONSOLE_USB_LOGIN.md) | UNSCHEDULED | Prototype OTP and console USB login design. Not on the roadmap. |
| [`login.md`](login.md) | CURRENT | Development access to a running BraiNIX instance. |
| [`REMOTE_MANAGEMENT_SHELL_SPEC.md`](REMOTE_MANAGEMENT_SHELL_SPEC.md) | UNSCHEDULED | Remote management shell design. Overlaps the serving path; not on the roadmap. |
| [`FILESYSTEM_PLAN.md`](FILESYSTEM_PLAN.md) | UNSCHEDULED | Filesystem design. Not on the roadmap; the serving path needs weight loading, not a general filesystem. |
| [`FILESYSTEM_HARDENING.md`](FILESYSTEM_HARDENING.md) | UNSCHEDULED | Hardening rules for the above. |

## Archived — historical records, deliberately not maintained

These describe what was true when written. They are evidence, not instructions. **Do not edit them to
match current reality.**

Two directory-level index files explain the archives in place:
[`superpowers/ARCHIVED.md`](superpowers/ARCHIVED.md) and `../.planning/planning-keep/ARCHIVED.md`.

> **Not in a fresh clone.** Three paths are excluded locally via `.git/info/exclude` — `/CONTEXT.md`,
> `.planning/`, and `docs/gsd:new-project.md`. They exist in the maintainer's working copy and are listed
> here for completeness, but a clone will not contain them, and links to them will not resolve there. The
> committed equivalents are [`ROADMAP.md`](ROADMAP.md) (for `CONTEXT.md` and the archived planning state)
> and [`NORTH_STAR.md`](NORTH_STAR.md) (for the original project specification).

| Path | What it is |
|---|---|
| [`superpowers/specs/2026-07-08-apple-silicon-baremetal-research.md`](superpowers/specs/2026-07-08-apple-silicon-baremetal-research.md) | The P6-T1 research memo. **Archived but load-bearing**: its technical content (boot chain, ADT, AIC, DART, INV-BOOT analysis) is the reference for all Apple Silicon work. Its *verdicts* — "deferred," "AS-4 NO-GO" — were overridden by the owner on 2026-08-02, but **its cost estimates were not revised**; ROADMAP.md is authoritative on scope. Carries its own detailed banner. |
| [`superpowers/ARCHIVED.md`](superpowers/ARCHIVED.md) | Index and status banner for the whole `superpowers/` tree. |
| `superpowers/specs/*` (others) | Design specs and decision records from completed work: kernel design, ELF loading, in-kernel store, the C.4 and C.6 decisions. |
| `superpowers/plans/*` | Implementation plans and stage reports from completed work. |
| [`../.planning/planning-keep/ARCHIVED.md`](../.planning/planning-keep/ARCHIVED.md) | Index and status banner for the whole GSD milestone record. |
| `../.planning/planning-keep/**` | The GSD milestone record: PROJECT, REQUIREMENTS, ROADMAP, STATE, the v1.0 milestone audit, and 87 phase plan/summary documents. Covers v1.0 (closed 2026-04-19) and the v1.1 shell foundation — **both predate the serving pivot.** ⚠️ That directory contains its own `ROADMAP.md` and `STATE.md`; those are the **old** roadmap and state, superseded by `docs/ROADMAP.md` and `../CONTEXT.md`. Both carry banners. |
| [`archive/HANDOFF-userspace-dispatch.md`](archive/HANDOFF-userspace-dispatch.md) | Session handoff from the userspace-dispatch work. Moved out of the repository root on 2026-08-02 per the repository-hygiene rule. |
| [`gsd:new-project.md`](gsd:new-project.md) | The original project specification that seeded the repository. |

*(`pre-plan-phase-0.md` was an empty file and was deleted on 2026-08-02.)*

## Superseded — replaced, kept as pointers

| File | Superseded by |
|---|---|
| [`security/THREAT_MODEL.md`](security/THREAT_MODEL.md) | [`THREAT_MODEL.md`](THREAT_MODEL.md) — there was a duplicate threat model with conflicting content; the top-level one is authoritative. |
| [`security/PROJECT_DESCRIPTION.md`](security/PROJECT_DESCRIPTION.md) | [`NORTH_STAR.md`](NORTH_STAR.md) + [`../README.md`](../README.md) |
| [`security/SECURITY.md`](security/SECURITY.md) | [`operations/DEVICE_ISOLATION_POLICY.md`](operations/DEVICE_ISOLATION_POLICY.md) — it was a Phase 08 device-isolation note, not a security policy. Disclosure policy is [`../SECURITY.md`](../SECURITY.md). |
| [`dev-rules.md`](dev-rules.md) | [`../PROJECT_RULES.md`](../PROJECT_RULES.md) — near-duplicate, same title inside. |
| [`security-rules.md`](security-rules.md) | [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) |

## Keeping this map honest

- A new document is added to this table in the same commit that creates it.
- A document that contradicts the authority spine is fixed or marked SUPERSEDED — never left ambiguous.
- Archived documents are never edited for consistency. If an archived document is misleading, the fix is a
  status banner at its top, not a rewrite of its body.
- When a platform decision changes, the reconciliation date at the top of this file is updated and every
  CURRENT row is re-checked.
