# AS-1a — First Light: the Apple Silicon boot stub prints

**Status:** design, approved 2026-08-10
**Phase:** AS-1, first slice
**Machine:** Mac mini M2 Pro (`Mac14,12`, SoC `T6020`)

---

## 1. Why this exists

`docs/ROADMAP.md` phase AS-1 is not one project. As written it is a target spec, a linker
script, Image4/Mach-O delivery, entry assembly, an EL2→EL1 drop, MMU and page tables at
16 KiB, exception vectors, a generic timer, SVC syscall entry, RNDR/PAC-BTI, ADT
consumption, a UART console, and watchdog reset. Those are independent subsystems with
different risks, and a single spec over all of them would be written entirely against
unverified assumptions.

AS-1a is the first slice: **the smallest payload that proves the delivery chain end to
end.** Its exit criterion is the ROADMAP's own AS-1 criterion, unchanged — BraiNIX prints
its invariant banner over serial on the M2 Pro mini. Every later slice depends on this
working, and this is the slice most likely to surface an unknown, because Phase 4's QEMU
rehearsal was cancelled (decision #22) and **the first aarch64 instruction BraiNIX ever
executes runs on this hardware.**

AS-0 is complete, so `src/adt/` already provides the device discovery this slice consumes:
`adt_window()`, `DeviceTree::parse`, `find_node`, and `translated_reg`.

## 2. Scope

**In scope.** A `no_std` aarch64 payload that m1n1 loads over USB, which establishes a
stack, writes a banner to the s5l UART, cross-checks the UART base against the ADT, and
spins.

**Explicitly out of scope**, deferred to later AS-1 slices: MMU and page tables, exception
vectors, the EL2→EL1 drop, the generic timer, SVC syscall entry, RNDR and PAC-BTI,
watchdog reset, secondary-CPU release, the framebuffer, and the Mach-O/Image4 wrapper.

## 3. Decisions taken, with their reasons

### 3.1 Delivery is m1n1 chainload, not direct kmutil

Install m1n1 once with `kmutil configure-boot`, then load each BraiNIX build over m1n1's
USB proxy. Iteration becomes seconds with no reboot and no reinstall, and a payload that
hangs means re-running the loader rather than a 1TR recovery trip. m1n1 also hands off
with the UART already initialized, which removes unverified UART *initialization* register
work from the critical path — this slice only has to *write*.

`CONTRIBUTING.md` rule 7 permits this explicitly: running m1n1 as a lab instrument is using
a tool, not incorporating code. No m1n1 code is copied, linked, or vendored.

**Cost, stated plainly:** the first hardware run is not a pure iBoot handoff, so the direct
iBoot path stays unproven until a later slice tests it. That is an accepted deferral, not a
claim that the paths are equivalent.

### 3.2 The stub is a standalone crate, not `arch/aarch64/`

`docs/ROADMAP.md`'s architecture table homes Apple platform code at
`src/kernel/src/arch/aarch64/apple/`. AS-1a deviates: it lands as `src/boot-stub-apple/`,
listed in the workspace `exclude` array exactly as `tools/proof-coverage` already is.

The kernel crate builds only for `x86_64-unknown-none` today, and that build is the frozen
reference (#26) that CI depends on. Making it multi-target means cfg-gating its whole
module tree before a single character has been printed, and every mistake there breaks the
one build that currently works. A standalone crate carries zero risk to it.

The stub is absorbed into `arch/aarch64/` when the kernel itself goes aarch64 and there is
a real MMU and vector table to merge with. **The ROADMAP AS-1 row must record this
deviation and its reason** — an undocumented divergence from the architecture table is
exactly the drift the north star forbids.

### 3.3 No custom target spec is needed yet

The ROADMAP AS-1 row and README both state that Apple Silicon "needs a custom in-tree
aarch64 target spec." **Verified false for this slice:** `rustc --print target-list`
carries a built-in `aarch64-unknown-none-softfloat`, which is correct for a soft-float
`no_std` payload.

A custom spec becomes necessary only when the stub needs `+pauth`/`+bti` (RNDR/PAC-BTI, a
later slice) or M2-specific CPU tuning. Writing one now would be unrequested complexity.
`rust-toolchain.toml` gains `aarch64-unknown-none-softfloat` in its `targets` array; both
docs get corrected.

### 3.4 Two-stage console, because fail-closed has a bootstrapping problem

Deriving the UART base from the ADT and *then* reporting failures is circular: if the ADT
parse denies, there is no console on which to say so, and the payload dies silently. A
silent hang is the single worst outcome on hardware with no debugger.

So the console comes up in two stages:

- **Stage 1 — bootstrap console.** Write the banner to the T6020 UART base as a documented
  constant taken from the fact table of §4.1. No dependencies, no parsing, no failure mode
  beyond the address being wrong. This alone proves the entire delivery chain.
- **Stage 2 — authoritative console.** Re-derive the base through
  `adt_window()` → `DeviceTree::parse` → `find_node` → `translated_reg`, then print whether
  it agrees with stage 1.

The constant is the *bootstrap* console; the ADT-derived value is *authoritative*.
**Disagreement is a loud, named failure, never a silent preference for either value.**

This is deliberately the same shape as AS-0-T4's ADT-versus-boot-args memory-range
cross-check, which also fails closed on disagreement. It is a cross-check, not a hardcoded
address smuggled past the no-hardcoding discipline — and it is the only ordering in which a
parser failure is reportable at all.

## 4. Deliverables

### 4.1 `docs/platform-specs/apple-s5l-uart.md`

A fact table, per the two-role output format in `docs/platform-specs/README.md`: register
offsets (ULCON, UCON, UFCON, UTRSTAT, UTXH), the TX-ready status bit, and the ADT node path
and `compatible` strings for the debug UART.

Carries the mandatory provenance header — sources consulted, the firmware/macOS version the
facts were derived against, machine and SoC, and spec author.

Derived from **published Asahi documentation only.** No Asahi source is read for this file,
and no code is copied regardless of license (`CONTRIBUTING.md` rule 7). The formal two-role
procedure is mandatory for AS-4 and AS-5 work only, so a single session may write both this
table and the code against it; the no-copied-code rule applies regardless.

### 4.2 `src/boot-stub-apple/`

| File | Contents |
|---|---|
| `Cargo.toml` | `no_std`, `panic = "abort"`, `license = "AGPL-3.0-only"`, path dependency on `brainix-adt` |
| `linker.ld` | One loadable segment; 16 KiB alignment throughout. **The load base is an input, not a guess:** it comes from m1n1's documented chainload address and is recorded in the §4.1 fact table alongside the UART registers. If it is wrong the payload never runs, so it is the first thing to confirm against m1n1's own output at §7 step 4. |
| `src/start.S` | `_start`: save `x0` (the boot-args pointer), install SP into a `.bss` stack, zero `.bss`, branch to Rust, spin on return. Included via `core::arch::global_asm!` with `include_str!`, **not** a `build.rs` invoking an external assembler — one fewer build dependency and it keeps the crate buildable with nothing but cargo. |
| `src/uart.rs` | Polling s5l writer: `write_byte` spins on the TX-ready bit, `write_str`. MMIO base is a parameter, never a module constant |
| `src/console.rs` | Stage 1 / stage 2 sequencing and the agreement check of §3.4 |
| `src/main.rs` | `#![no_std] #![no_main]`; panic handler writes a marker to the bootstrap console then spins forever |

Root `Cargo.toml` gains `"src/boot-stub-apple"` in `exclude`.

### 4.3 `bin/as-boot.sh`

Builds the payload and prints the m1n1 chainload invocation. It **runs** m1n1's loader as an
external tool; it does not vendor, copy, or wrap m1n1 code.

### 4.4 Doc corrections this slice forces

- `docs/ROADMAP.md` AS-1 row: record the standalone-crate deviation (§3.2) and that no
  custom target spec is required yet (§3.3), following the file's strike-through-and-annotate
  convention.
- `README.md`: the Requirements section's custom-target-spec claim.
- `rust-toolchain.toml`: add `aarch64-unknown-none-softfloat`.

## 5. Failure behavior

Every failure path ends in a spin, never a silent fall-through into whatever bytes follow
the image, and never a "best effort" continue.

| Failure | Behavior |
|---|---|
| Boot-args pointer invalid, or `adt_window()` denies | Stage 1 already printed. Print the named error, spin. |
| ADT parse denies | Print the `AdtError` discriminant, spin. |
| UART node absent, or `translated_reg` denies | Print the named error, spin. |
| Stage 2 base disagrees with stage 1 | Print **both** values and a disagreement marker, spin. Never pick one. |
| Rust panic | Panic handler writes a fixed marker to the bootstrap console, spins. |

## 6. Verification

**Verifiable now, without the rig:**

1. `cargo build --target aarch64-unknown-none-softfloat` from `src/boot-stub-apple/`
   produces an ELF.
2. `llvm-objdump`/`llvm-readelf` assert `_start` sits at the linker-script address, the
   image has exactly one loadable segment, and it requires no dynamic loader or relocation
   processing.
3. Host unit tests for the UART writer against a fake MMIO buffer: given a base and a byte
   sequence, assert the exact writes and the TX-ready polling order. Pure logic, no
   hardware.
4. Host unit tests for the ADT lookup path against a synthetic tree carrying a UART node,
   reusing the AS-0 test fixtures' construction style, including the deny paths of §5.

**Blocked on the rig, and honestly labelled as such:** the handoff itself. Nothing above
proves that m1n1 hands off in the state we assume, that the linker base is where m1n1 loads
us, or that the UART constant is right. Those are proven only by §7 step 5.

**No claim of equivalence.** Passing every check in this section proves the components, not
the system. The system is proven when the banner appears on a terminal.

## 7. The rig track, in order

Physical work, John's, parallel to all implementation above:

1. 1TR: `bputil` downgrade to Permissive Security (local admin, physical presence, once per
   machine).
2. USB-C debug UART cable, plus a host serial terminal.
3. `kmutil configure-boot` to install m1n1.
4. **Rig acceptance test: m1n1 prints its own console over serial.** This validates steps
   1–3 with zero BraiNIX code involved. If this does not happen, the problem is the rig, and
   no amount of debugging our payload will find it.
5. Chainload the BraiNIX payload. Banner appears. AS-1a is done.

Step 4 is the gate. Do not chainload BraiNIX before m1n1's own console works.

## 8. Definition of done

- The banner appears on a serial terminal attached to the M2 Pro mini, loaded via m1n1.
- Stage 2 reports agreement between the ADT-derived UART base and the bootstrap constant.
- Every check in §6 passes.
- `src/boot-stub-apple/` is excluded from the workspace and the x86-64 reference build is
  byte-unchanged.
- The four doc corrections of §4.4 have landed.
