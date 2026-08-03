# TCB Exception 001 — In-Kernel SQL Engine

**Status:** APPROVED (explicit owner sign-off, 2026-06-27)
**Scope:** A full relational SQL engine (parser, planner, executor, B-tree
storage, write-ahead log / transactions) running in **ring 0**, inside the
kernel address space, as part of the Trusted Computing Base.
**Requested by:** project owner (John Brahy), after being shown the cost twice
and declining the userspace alternative.
**Authored by:** engineering, under the `/goal` (north-star) governance process.

> **Reconciled 2026-08-02.** This exception remains **in force and unchanged**. It is now one of three
> named exceptions; the other two were signed 2026-08-02 and are recorded in
> [`../NORTH_STAR.md`](../NORTH_STAR.md):
>
> | Exception | Scope | Effect |
> |---|---|---|
> | **TCB-EXCEPTION-001** *(this document)* | All platforms | Relational SQL engine in ring 0. |
> | **INV-BOOT/AS** | Apple Silicon | No measurement, remote attestation, or sealing. |
> | **TCB-AS** | Apple Silicon | SecureROM, iBoot1, iBoot2, sepOS in the TCB by force. |
>
> **These compound.** On the primary platform the TCB now contains both a full SQL engine in ring 0 *and*
> four closed-source Apple components we cannot audit — and there is no attestation to detect if any of it
> is subverted. Each exception was justified on its own; the combination was never separately assessed.
> The `db/` reframing at P2-T7 (session table + serving log) is the next change to this engine and is the
> natural point to re-examine whether the ring-0 residency still earns its cost.
>
> Re-derivation of the serving path onto this engine must not silently widen this exception's scope. Its
> scope is what is written below and nothing more.

---

## Why this document exists

`NORTH_STAR.md` records seven hard lines that "do not cross without explicit
sign-off." This feature crosses **three** of them. The north-star principle
*"minimize and **name** the trust"* (NORTH_STAR.md:16) requires that any TCB
expansion be "written down and justified." This record is that justification.
It does not make the violation safe. It makes it **named, bounded, and
non-silent**, which is the minimum the north-star demands of a crossing it
cannot prevent.

This exception is the authoritative record. If it and memory disagree, this
file wins. It may only be amended or revoked by the project owner.

---

## Hard lines waived

| # | Hard line (NORTH_STAR.md) | Invariant endangered | How this feature crosses it |
|---|---|---|---|
| 1 | "No dynamic kernel heap. Fixed-size pool allocators only." (line 42) | **INV-MEM** | A relational engine with joins, transactions, query plans, and result sets is a dynamic-allocation workload by nature. |
| 2 | "No new external crate dependencies." (line 43) + "dependency closure is itself: zero external code" (line 7) | INV-BOOT posture / "zero external dependencies" standing bar (THREAT_MODEL.md:56) | No SQL engine may be vendored (SQLite, gluesql, redb, sled, sqlparser, …). The engine is hand-written in-tree. |
| 3 | "The trusted set only ever shrinks." (line 35) | **INV-AUTH** (worst case) | A SQL engine is among the largest attack surfaces in computing; placing it in ring 0 is the single largest TCB expansion in the project's history. |

## Blast radius accepted

Per THREAT_MODEL.md, **every disk byte is attacker-controlled** (line 9). An
in-kernel engine parses hostile on-disk B-tree and WAL pages **inside the TCB**.
The accepted consequence, drawn from the threat model:

- A single defect anywhere in the parser, planner, executor, B-tree, or WAL is
  a **ring-0 memory-safety defect** → "W^X loss enables code injection… in the
  affected domain" (THREAT_MODEL.md:42), and the affected domain is the kernel.
- That is **full privilege escalation (INV-AUTH worst case)** — "the worst case
  the design exists to prevent" (THREAT_MODEL.md:40).

The owner has accepted this blast radius explicitly. The userspace `dbd`
alternative — which delivers the same features (real SQL, joins, transactions,
local-only) while confining any engine compromise to a single user's data —
was offered and declined.

---

## Binding constraints (the exception is granted ONLY under these)

Crossing the three lines above does **not** suspend the rest of the north-star.
The following are mandatory and CI-enforced; the engine does not land without
them:

1. **No dynamic kernel heap — preserve INV-MEM's letter.** The engine is backed
   by **fixed-size pool allocators only**. No general-purpose heap is introduced
   into the kernel image. Query complexity (max rows, join arity, transaction
   depth, statement length) is **bounded at compile time** by pool capacity. An
   operation that would exceed a pool **fails closed** (returns an error), never
   grows.
2. **Zero external code.** Every byte of the engine is in-tree, owned, and
   reproducibly built. No SQL crate is added to `Cargo.toml`. This does not add
   to the tracked-debt crate list; it must not.
3. **Hostile-input discipline.** The SQL text parser and the on-disk
   page/WAL decoders are treated as **in-tree parsers over attacker input**:
   each is **fuzzed and Kani-checked** (THREAT_MODEL.md:68 bar) before it is
   trusted. No decoder trusts a length, offset, or type tag from disk without
   bounds-checking it.
4. **No new ambient authority (INV-AUTH holds).** Access is **capability-gated,
   default-deny**: a query entry point reachable only by a process holding an
   explicit `CapDb`-style grant. The shell gets it; nothing else does by
   default.
5. **Structurally local-only.** The engine holds **no network capability** and
   exposes **no network endpoint**. "Not accessible to the outside" is a
   property of the capability graph, not of configuration — satisfying
   "structure over secrecy" (NORTH_STAR.md:15) for the one property the owner
   most cares about.
6. **W^X unbroken (INV-MEM, the other half).** No engine page is ever writable
   and executable. Code and data pools are distinct and correctly attributed.
7. **Synchronous only (INV-IPC).** If the engine is reached across a domain
   boundary, it is synchronous rendezvous — no shared-memory result buffers, no
   async queues.
8. **`unsafe` stays governed.** Any `unsafe` the engine needs is added to the
   `UNSAFE_CODE_POLICY.md` allowlist with a `// SAFETY:` contract, like every
   other allowlisted location. The default-deny on `unsafe` is not waived here.

## What is NOT waived

- INV-AUTH's capability discipline (constraint 4).
- INV-IPC synchronous rendezvous (constraint 7).
- W^X (constraint 6).
- The `unsafe` default-prohibition (constraint 8).
- INV-AUDIT and INV-ASSIST confinement — untouched by this feature.

---

## Exit criteria (how this debt is repaid)

This exception is a standing liability, tracked like the vendored-crate debt.
It is considered repaid when **either**:

- the engine is moved out of ring 0 into a capability-confined userspace `dbd`
  server (the originally recommended design), **or**
- the project owner revokes the feature.

Until then, every release notes in its security log that the TCB contains an
in-kernel SQL engine under this exception.

---

## Sign-off

- **Owner approval:** explicit, informed, recorded 2026-06-27. The three waived
  hard lines and the full-escalation blast radius were presented before
  approval; the confining userspace alternative was presented and declined.
- **Engineering:** advised against; proceeding under owner authority with the
  binding constraints above.
