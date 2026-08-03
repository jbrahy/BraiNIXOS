# Platform specs — the clean-room fact tables

This directory holds the **only** documents an implementer is allowed to work from when the behavior
being implemented is documented solely by a reverse-engineering project's source code.

It exists because of the owner decision of 2026-08-02 recorded in [`../ROADMAP.md`](../ROADMAP.md)
(decision #8) and in [`../NORTH_STAR.md`](../NORTH_STAR.md) §*What advancing the goal means*: third-party
reverse-engineering work — notably Asahi Linux — is **reference-only**. Published documentation comes in;
a clean-room implementation goes out. No code is copied, under any license.

**Scope: mandatory for all AS-4 and AS-5 work.** Any other task that would otherwise read
reverse-engineered source follows the same procedure.

## The two roles

The wall is a procedure, not a good intention. Two roles, and no one holds both for the same subsystem.

| Role | May read | Produces |
|---|---|---|
| **Spec author** | Reverse-engineered source, published documentation, hardware, m1n1 register dumps | One file in this directory: **fact tables only** — register offsets, bit fields, struct field layouts, sequence diagrams, state machines, enumerated constants |
| **Implementer** | The spec file, and nothing else | The in-tree Rust implementation |

Rules that make the roles real:

- A spec file carries **no prose argument, no design rationale copied from a source, and no code** — not
  even pseudocode transcribed from a driver. A fact table is a table of facts about hardware.
- **The implementer may not read the sources the spec was derived from.** Not the driver, not the commit
  history, not the mailing-list thread. If the spec is insufficient, the fix is to send the question back
  to the spec author, never to go look.
- A question answered by reading source during implementation **voids the wall for that subsystem**. The
  subsystem is re-derived by a spec author and re-implemented by someone who has not read the source.

## The honest limit

Stated rather than glossed, because [`../NORTH_STAR.md`](../NORTH_STAR.md) requires that every claim be
falsifiable: **this wall protects code provenance, not knowledge provenance.** It makes copying
impossible and the derivation auditable. It does not make the implementer's understanding independent of
the source that produced the spec. We claim the first and do not claim the second.

## Provenance header

**Every file in this directory begins with this header.** A spec file without one is not a spec file and
must not be implemented against.

```markdown
# <Subsystem> — platform fact table

**Sources consulted:** <every document, source tree, commit, or dump the facts were derived from, each
with enough identity to be re-fetched — repository and commit hash, document title and revision, or
capture date>
**Firmware / OS version:** <the macOS release and build, plus the firmware or ABI version the facts were
derived against — e.g. macOS 15.3 (24D60), AGX firmware ABI as shipped with that release>
**Machine / SoC:** <e.g. Mac mini M2 Pro, `Mac14,12`, SoC `T6020`>
**Spec author:** <who derived it>
**Derived:** <date>
**Implementer restriction:** the implementer of this subsystem **may not read the sources named above**.
Work from this file only. If it is insufficient, return the question to the spec author.
```

**The firmware/OS version field is not optional.** The AGX firmware ABI is versioned per macOS release,
and the boot chain below boot-args carries no compatibility promise at all
([`../ROADMAP.md`](../ROADMAP.md) *Honest risks* #3). A fact table with no version recorded is a fact
table about an unknown machine, and it rots silently — the facts stay plausible and stop being true.

When the deployment machine's macOS release changes, every spec file derived against the old one is
**re-qualified or re-derived**, and the implementation is retested. That is a scheduled event, not a
surprise.

## Status

No spec files exist yet. The first ones land with the AS-4 driver chain (RTKit, ANS2 NVMe, PCIe,
Ethernet) and AS-5 (AGX), which is where the clean-room procedure first becomes load-bearing. Until then
this directory holds only this README.
