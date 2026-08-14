# BraiNIX roadmap — secure LLM inference serving on Apple Silicon

Execution plan and current status. Governed by [`NORTH_STAR.md`](NORTH_STAR.md) (the contract) and
[`THREAT_MODEL.md`](THREAT_MODEL.md) (the attacker model). Where this document and those disagree, they
win. See [`DOCUMENTATION_MAP.md`](DOCUMENTATION_MAP.md) for authority order.

**This file is the single in-tree source of truth for phasing and status.** It supersedes the external
planning file it was derived from; do not maintain a roadmap outside the repository.

---

## Locked owner decisions

| # | Decision | Date |
|---|---|---|
| 1 | **Inbound serving** — remote clients reach the model (reverses the former outbound-only posture). | 2026-07-07 |
| 2 | ~~**CPU-inference MVP first**~~; ~~GPU/VRAM deferred~~ — **scope clause superseded by #10**, **"MVP" framing superseded by #11**; the CPU-first *ordering* still stands, restated as "CPU inference first". | 2026-07-07 |
| 3 | **All security invariants kept as the moat** — capabilities, W^X, no kernel heap (weights/KV in fixed reserved regions), synchronous IPC, minimal TCB, ~~**zero external crates**~~ — **qualified by #16**: one permanent named exception, the verify-only Ed25519 stack; everything else in-tree (inference engine and every driver written in-tree, `no_std`). | 2026-07-07 |
| 4 | **Formal-proof-maximal** posture — every hostile-input parser fuzzed *and* Kani-checked; ~~proofs on all security-relevant paths; security audit on every component~~ — **uniform-application clause superseded by #15**; the gate is now tiered by TCB proximity. Honest caveat: maximal assurance under a stated attacker model, **not** a proof of absolute security. | 2026-07-07 |
| 5 | ~~Apple Silicon deferred / out of scope.~~ **SUPERSEDED by #6.** | 2026-07-08 |
| 6 | **Apple Silicon is the PRIMARY platform.** Reference deployment: Mac mini M2 Pro (`Mac14,12`, SoC `T6020`, 32 GB unified memory). ~~x86-64 becomes the secondary and **attested** platform, plus the development/CI target.~~ — **second clause superseded by #20**: x86-64 is no longer a platform at all. | **2026-08-02** |
| 7 | **INV-BOOT/AS signed off** — remote attestation and sealing are permanently unavailable on the primary platform. Recorded in NORTH_STAR.md. **Restated by #24**: with no second platform, INV-BOOT/AS stops being an exception and becomes the boot posture. | **2026-08-02** |
| 8 | **Asahi Linux is reference-only.** Published documentation in, clean-room implementation out. No code copied, regardless of license (m1n1 is MIT, the Asahi kernel is GPL-2.0; the no-vendoring rule forbids both). Running m1n1 as a lab instrument on a development machine is permitted — that is using a tool, not incorporating code. **Enforced as a two-role procedure for all AS-4 and AS-5 work:** a *spec author* role may read reverse-engineered source and emits nothing but fact tables — register offsets, struct field layouts, sequence diagrams, state machines — into `docs/platform-specs/`, each file carrying a provenance header naming its sources **and a firmware-version field** (the AGX firmware ABI is versioned per macOS release); an *implementer* role is denied that source and works only from the spec file. Stated limit: the wall protects **code provenance, not knowledge provenance**. | **2026-08-02** |
| 9 | **Performance is a craft standard** (~~"product requirement"~~ — framing restated by #11), ranked below the invariants and above everything else. "We did not optimize because security" is no longer a sufficient answer; slowness needs a named invariant as its justification. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 10 | **GPU and CPU at maximum.** Apple's **AGX GPU is in scope** — it moves from non-goal to goal. Supersedes decision #2's "GPU deferred" as a *scope* statement; CPU inference is still first as an *ordering* statement. Carries the **TCB-AS/GPU exception** — ~~unsigned~~ **conditionally signed 2026-08-02**, see #14 and AS-5-T0: AGX requires running Apple's opaque, DMA-capable GPU firmware. | **2026-08-02** |
| 11 | **Craft-first.** BraiNIX is a craft project whose artifact is held to product-grade rigor because that is the only honest way to measure the craft. It is **not a market claim**. Product framing — "MVP", "the product ships", "product requirement" — is drift and is restated in craft terms wherever it appears below. Product-grade *standards* stay; product *claims* go. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 12 | **Done = AS-5.** The project's terminal completion criterion is **AS-5: GPU and CPU at maximum, serving inference on the Mac mini M2 Pro.** Not AS-4c, not P3-T9 — those are gates on the way, not the finish line. | **2026-08-02** |
| 13 | ~~**P3-T9 is a mandatory gate.** The x86-64/QEMU end-to-end serving milestone must be complete before AS-4 or AS-5 may be re-rated or started.~~ — **SUPERSEDED by #27.** The gate as written is unreachable: it names an end-to-end run on a platform that no longer exists. It is replaced by host-test and per-component criteria; AS-0 through AS-3 were already permitted before it and remain so. | **2026-08-02** |
| 14 | **GPU tenant-mapping policy.** Model weights are mapped into the GPU's DART window **read-only and permanently** (they are not client data). KV cache is mapped **strictly per session** — mapped on session entry, unmapped and flushed on exit, and **never two tenants resident simultaneously**. The GPU time-slices between clients; cross-tenant batching is forbidden. Consequence: **INV-SERVE is preserved intact and needs no exception.** Cost, stated plainly: the GPU's payoff shrinks from "a large win for serving multiple clients concurrently" to **prefill acceleration plus time-sliced multi-client serving**. | **2026-08-02** |
| 15 | **Proof gate is tiered by TCB proximity**, replacing the uniform per-component gate of #4. **Full tier** (all six artifacts) covers the TCB, every hostile-input parser, and all crypto; **Reduced tier** (tests + security audit report only — no Kani, no Prusti) covers capability-bounded servers whose compromise the capability model contains. Justification is the project's own principle: IOMMU confinement, not driver correctness, is the control. The authoritative per-component assignment is the table in [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16, audited at each phase gate. | **2026-08-02** |
| 16 | **PSK transport; no asymmetric crypto in the serving transport.** BSP uses pre-shared per-client keys, HKDF-SHA256 session-key derivation, and ChaCha20-Poly1305 records. In-tree primitive set: **SHA-256, HKDF, ChaCha20, Poly1305**, which deletes `sha2` and `chacha20` — *specified, not shipped: both are still vendored and the in-tree reimplementation has not landed (X-T4).* **Permanent named exception:** the Ed25519 *verification* stack (`ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle`) stays vendored, **verify-only**, because INV-BOOT's release signature needs curve25519 field arithmetic and hand-rolling it would *lower* assurance. Cost: **wire compatibility with stock OpenSSH clients is forfeited.** | **2026-08-02** |
| 17 | **Administration is a BSP admin channel, not a shell.** A second session *type* on the same authenticated PSK transport, gated by a distinct `CapAdmin` (`Admin=14`), exposing a frozen, enumerated set of **exactly six verbs**: enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. There is no `rotate` verb — rotation is enroll-then-revoke. A general-purpose shell is ambient authority under another name and is forbidden. The **serial console is the break-glass path**, and the break-glass admin PSK authenticates over serial and **nowhere else — never over the network**. | **2026-08-02** |
| 18 | **Keys are runtime-enrolled and ratcheted; no secret ever enters a build artifact.** Enrollment through `boot/credential_store.rs` — ~~virtio-blk on x86-64,~~ ANS2 NVMe on Apple Silicon from AS-4a. Forward secrecy comes from a symmetric HKDF ratchet that deletes the chain key it advanced past; **until the ratchet lands there is no forward secrecy.** ~~**At rest, protection tracks the platform's attestation capability:** the credential store is **specified to be TPM-sealed on x86-64**, where INV-BOOT holds in full, and is~~ **At rest the credential store is plaintext, permanently** (**restated by #25**) — the sealing half died with the platform that could have sealed. See P2-T13. | **2026-08-02** |
| 19 | ~~**Wave 2 is this documentation gate, then P1-T2 ∥ BSP v2 spec.**~~ — **SUPERSEDED by #27.** P1-T2 is cancelled with the HAL, and the P3-T9 critical path it referenced no longer exists. Wave 2 is now this plan; AS-0 is its first code. | **2026-08-02** |
| 20 | **x86-64 is dropped as a platform.** BraiNIX is single-architecture aarch64/Apple Silicon. There is no secondary target, no attested target, and no fallback. Recorded in NORTH_STAR.md *Target platform* and as a Non-goal. | **2026-08-03** |
| 21 | **The HAL is cancelled.** An eleven-trait abstraction layer with one backend is an abstraction over nothing. [`architecture/HAL.md`](architecture/HAL.md) is **SUPERSEDED** (bannered, body preserved). **Phase 1 (P1-T2..T7, P1-A) is cancelled** — struck through below, not deleted. | **2026-08-03** |
| 22 | **No QEMU `virt` harness.** **Phase 4 is cancelled.** Apple hardware is the only bring-up target, so `AS-1` now depends on `AS-0` alone. The cost is real and is stated rather than softened: there is no console-having environment in which to debug aarch64 core code before facing hardware where nothing works until the UART does. | **2026-08-03** |
| 23 | **AS-0 (ADT parser) is the first code.** Host-side, host-testable, no hardware, no HAL dependency. It gates AS-1. It moves out of Wave 3 and becomes the head of the platform track. | **2026-08-03** |
| 24 | **INV-BOOT is restated to what Apple can achieve** — reproducible build, Ed25519 release signature, iBoot-verified payload integrity under the machine's Secure-Enclave-held local policy, and a **self-reported** software measurement log. **Remote attestation, sealing, and runtime-chain measurement are permanently unavailable — not deferred.** INV-BOOT/AS stops being a named exception and becomes the boot posture; it stays listed in every exceptions ledger marked *superseded — now the rule* so the count stays checkable. Every "deployments requiring attestation run on the x86-64 target" escape hatch is **deleted**, because that platform does not exist. | **2026-08-03** |
| 25 | **The credential store is plaintext at rest.** The Apple half of the 2026-08-02 ruling survives verbatim; its x86-64 sealing half dies with the platform. No TPM exists on any supported target, so there is no measured boot state to bind a secret to and no version of P2-T13 that closes the gap. | **2026-08-03** |
| 26 | **The x86-64 code is frozen, not deleted.** `src/kernel/src/arch/**` (4065 LOC), `e1000.rs`, `virtio_blk.rs`, `pci.rs` and the x86 boot path stay in tree and **stay building** as the reference implementation the aarch64 port is written against. They are deleted when aarch64 replaces them, not before. **No task in this plan removes code.** Every row below marked *frozen reference* means exactly this: it still compiles, and nothing is scheduled against it. | **2026-08-03** |
| 27 | **P2 (serving path) and P3 (inference engine) stay architecture-neutral and host-testable** on `aarch64-apple-darwin`, and are **not blocked by any Apple work**. Losing x86-64/QEMU costs the integration target, not the unit-test loop, so **the P3-T9 gate of #13 is replaced by host-test and per-component criteria** (see Phase 3). **Wave 2 is now this plan.** | **2026-08-03** |

### What decision #6 costs, stated plainly

There is **no remote attestation**, anywhere. A client cannot cryptographically
verify what it is talking to; an early kernel compromise is undetectable from outside. Reaching a serving
deployment additionally requires in-tree RTKit, ANS2 NVMe, PCIe, and Ethernet drivers, each reimplemented
clean-room from reverse-engineered documentation — the largest single body of work in this plan, and the
item most likely to consume the schedule. Every Apple Silicon fact below is revocable by an Apple firmware
update, with no upstream remedy. These are accepted costs, not open questions.

### What decisions #20–#27 cost, stated plainly

**There is no runnable BraiNIX** until the development rig exists *and* AS-1 lands — the mini in Permissive
Security via `bputil` from One True Recovery, a debug UART cable, and m1n1 as a lab instrument. Dropping
x86-64 removes the only environment the tree currently boots in, and cancelling Phase 4 removes the QEMU
`virt` harness that would have been the fallback. **AS-0 and the host-tested P2/P3 tracks are the only work
with a verification loop until then**, which is precisely why AS-0 is the first code (#23).

The P3-T9 gate — x86-64 end-to-end serving, locked 2026-08-02 as decision #13 — is **unreachable**, not
late. It is replaced by host-test and per-component criteria (#27). Nothing is deleted from the codebase to
achieve any of this (#26): the x86-64 tree stays building as the frozen reference the aarch64 port is
written against.

---

## Status at a glance

**Wave 1 — COMPLETE** (all five deliverables merged; P2-T1's deliverable was later superseded and the task
re-opened in Wave 2 — see its row below):

| Task | Deliverable | Commit |
|---|---|---|
| P1-T1 | HAL trait design — [`architecture/HAL.md`](architecture/HAL.md) — **SUPERSEDED** by decision #21; the HAL is cancelled and the document is bannered, body preserved | `670e072` |
| P2-T1 | BSP v1 serving protocol spec — [`architecture/BSP-v1-serving-protocol.md`](architecture/BSP-v1-serving-protocol.md) — historical; **superseded by BSP v2** (decision #16), so P2-T1 is re-opened in Wave 2 | `670e072` |
| X-T1 | Proof-coverage tracker — `tools/proof-coverage/` | `670e072` |
| P2-T9 | swtpm measured boot + runtime TPM-presence gating (x86-64) — **frozen reference, not scheduled** (#26); it has no analogue on the only platform | `c01d0ab` |
| P6-T1 | Apple Silicon research memo — [`archive/specs/2026-07-08-apple-silicon-baremetal-research.md`](archive/specs/2026-07-08-apple-silicon-baremetal-research.md) | `670e072` |

**Wave 2 — IN PROGRESS, and it is now this plan (decision #27).** ~~Wave 2 is this documentation gate
first … and then two parallel tracks that share no code: P1-T2 ∥ P2-T1 (BSP v2 spec).~~ That definition
died with the HAL: P1-T2 is cancelled by #21, and the P3-T9 critical path it was sequenced against is
unreachable by #27. Wave 2 is **the single-platform reconciliation of 2026-08-03 and the work it unblocks**.

Status: the 2026-08-02 documentation gate is COMPLETE and **P2-T1 is COMPLETE** —
[`architecture/BSP-v2-serving-protocol.md`](architecture/BSP-v2-serving-protocol.md) supersedes v1.
~~P1-T2 is the only Wave 2 item remaining~~ — cancelled. **AS-0 is the first code (#23)**, and the
architecture-neutral P2/P3 tracks run beside it, host-tested on `aarch64-apple-darwin` and blocked by no
Apple work (#27).

~~**Wave 3 — AS-0** (Apple Device Tree parser). AS-0 slid out of Wave 2 because it is the only former
Wave 2 item not on the critical path to P3-T9 (decision #19)…~~ — **superseded by #23.** That deferral
rested on a P3-T9 critical path that no longer exists. AS-0 is now the head of the platform track and the
only Apple work with a verification loop before the rig exists.

**Wave 3 — AS-0 COMPLETE.** The platform track's host-testable head is done end to end:

| Task | Deliverable | Commit |
|---|---|---|
| AS-0-T1 | ADT binary-format spec — [`platform-specs/apple-device-tree-format.md`](platform-specs/apple-device-tree-format.md) | `981f693`, `b3d2dba` |
| AS-0-T2 | `#![no_std]`, zero-alloc, fail-closed ADT parser — `src/adt/` | `e4c6296`, `f7d8df8` |
| AS-0-T3 | ADT fuzz target (46-input corpus) + Kani harnesses — `src/adt-verify/` | `5c89031` |
| AS-0-T4 | boot-args parser + ADT/boot-args memory-range cross-check | `e89bd34` |

**Wave 3 — the architecture-neutral library track has LANDED.** Every P2/P3 component that is a *library*
rather than a *server* is implemented, host-tested, and committed:

| Task | Deliverable | Commit |
|---|---|---|
| P2-T2 | Transport crypto — PSK handshake FSM, HKDF-SHA256 schedule, ChaCha20-Poly1305 record layer, ratchet — `src/transport-crypto/` (+ 10 Kani proofs, 2 fuzz targets) | `1c290ce`, `40e3e1d` |
| P2-T3 | Fail-closed BSP v2 wire decoder — `src/bsp/` (+ 16 Kani proofs, 89-input fuzz corpus) | `d763089`, `40e3e1d` |
| P3-T1 | BXW1 weight-format spec | `04868c3`, `88f6b62` |
| P3-T3 | Fail-closed BXW1 loader (**decoder only**, not `modeld`) — `src/bxw1/` | `3484e7a`, `982f6ea` |
| P3-T4 | Tensor kernels — matmul (f32 + Q8 dequant), RMSNorm, softmax, RoPE, SiLU/SwiGLU — `src/tensor/` | `ef48866`, `88f6b62` |
| P3-T5 | In-tree BPE tokenizer + fail-closed vocab parser — `src/tokenizer/` | `821f544`, `edc0bfe` |
| P3-T6 | Transformer forward pass, KV cache, decode loop, sampling — `src/transformer/` | `aaa1607`, `982f6ea` |

**What that does *not* mean.** Nothing above is wired to anything. **`servd`, `inferd`, `modeld`, and
`bsp-client` do not exist** — no directory, no crate, no workspace member. The libraries are components
without a system, and the first thing that composes them is P3-T9a, which cannot start until P2-T5,
P2-T4, and P3-T7 do. Proof coverage stands at **62.5% (5/8 invariants, 40 Kani proofs, 11 fuzz targets)**;
INV-AUDIT, INV-GPU, and INV-MODEL are uncovered.

**Terminal criterion (decision #12): the project is done at AS-5** — GPU and CPU at maximum, serving
inference on the Mac mini M2 Pro. AS-4c is a gate on the way, not the finish line. ~~and P3-T9~~ — that
gate is unreachable (#27).

**Substrate that works today — on the frozen x86-64 reference (#26), which is not a platform:** boots under
QEMU x86-64 via GRUB2 ISO to `[OK] BraiNIX: boot complete`; ring-3 userspace shell under KPTI; W^X-correct
ELF loader with guard-protected stacks; capability model; synchronous IPC; decomposed network stack;
fixed-pool in-kernel store; inbound SSH server; outbound SSH client (host-tested only, Stage A). **None of
this runs on Apple Silicon yet**, and that is the honest status: there is no runnable BraiNIX on the only
supported platform until AS-1 lands.

**The AS-0 and library work above changes none of that.** It is host-tested on `aarch64-apple-darwin`
and inside the x86-64 reference build; **there is still not one aarch64 source file in the kernel tree**
(`find src -iname '*aarch64*'` is empty), so AS-1 through AS-5 remain untouched.

**2026-08-14 — CI is green, all thirteen checks, for the first time in the project's history.** What it
took is worth recording, because the plan above cited several of these jobs as evidence for work that was
never actually being checked:

- The **style gate** built bare metal while calling itself a host run — `.cargo/config.toml` sets
  `build.target = "x86_64-unknown-none"`, so three steps that omitted `--target` were not testing what
  they named. Every job behind that gate had therefore never executed on this branch.
- The **integration test could not have passed at any point in its history** — six independent defects,
  each of which alone was fatal, and every one of them in the harness rather than in the kernel:
  `grub-mkrescue` had no `mtools`, so the ISO never built; `swtpm_setup` asked for EK certificates it
  cannot write on a runner; `-nographic` together with `-serial stdio` made two character devices claim
  the same fd, so QEMU exited before executing an instruction; the ISO shipped the bootloader alone with
  no `module2` lines, so the image had no kernel in it; QEMU's TPM chardev pointed at swtpm's `--server`
  socket rather than its control socket, so QEMU blocked in a handshake before starting the CPU; and the
  kernel was built **without `dev-build`**, so the attestation gate correctly halted on an unverifiable
  `TPM2_Quote` before the banner the job asserts. The last two were found by reproducing the whole job in
  an `ubuntu:24.04` container with the same QEMU and the same vTPM, which ended a guess-and-push loop that
  three CI rounds had not.
  **What this cost, stated as the plan's own risk register would:** *the QEMU integration test has never
  provided evidence about this kernel.* Row 10 of *Honest risks* says the platform track has no
  verification loop until hardware; until 2026-08-14 the x86-64 reference had none in CI either, and
  nobody could have known from the job's output, because its output was empty.
- **Eight Kani harnesses never terminate.** Measured with a 700s cap: the two ADT harnesses over the
  96-byte nested blob, and six transport-crypto harnesses that drive a hash or an AEAD over symbolic
  bytes. They are behind a `long-proofs` feature, off by default, with their measurements recorded in the
  crates and a stated gap in [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16.
  The Kani job now runs one parallel job per package, because sequentially one non-converging harness
  starved every package behind it — the BSP, transport-crypto and IPC proof sets had never once run.
- A **line-coverage gate** now holds every uncovered line in the seven library crates to a
  `COVERAGE-EXEMPT:` marker with a stated reason. 118 lines are exempt; zero are unjustified.

**One consequence for the numbers this document quotes.** `tools/proof-coverage` reports **50 Kani
proofs**, and it counts harnesses that *exist* — eight of those do not run in CI. Read it as 42 running
plus 8 recorded-and-excluded until X-T5 splits the two.

**The fuzz targets do now run** (P2-T10, closed 2026-08-14): eleven targets, twenty seconds each, seeded
by the checked-in corpora. That is a smoke test, and this document's "Verify: fuzz soak" criteria are
still unmet — the difference between the two words is the whole reason that row existed.

---

## Architecture target

| Subsystem | Role | Location |
|---|---|---|
| ~~**H — Multi-arch HAL**~~ | ~~Trait layer over arch + hardware-security primitives. Compile-time backends, no dyn dispatch.~~ **CANCELLED (#21)** — one backend is not an abstraction. Apple platform code lands directly under `arch/aarch64/`; `src/kernel/src/arch/x86_64*` is **frozen reference, not scheduled** (#26) and keeps building. | ~~`src/kernel/src/hal/`~~; `src/kernel/src/arch/aarch64/` |
| **AS — Apple Silicon platform** | ADT parser, boot stub, AIC, DART, RTKit, ANS2 NVMe, PCIe, Ethernet | `src/kernel/src/arch/aarch64/apple/`, `src/servers/devd-*/` |
| **N — Secure serving path** | Inbound listener, authenticated transport, fail-closed request parser, per-client sessions | `src/servers/servd/` + `src/brainix-transport-crypto/`; **replaces** `boot/ssh_bridge.rs` |
| **I — In-tree inference engine** | `no_std` transformer: tensor kernels, BPE tokenizer, KV cache in fixed regions; confined tenant | `src/servers/inferd/` + `memory/` reserved-region extensions |
| **W — weight loader** | **One-shot `modeld` (specified 2026-08-03, unbuilt).** Runs **before** `inferd` and exits: reads the BXW1 blob, verifies its signature and every per-tensor digest, populates `WEIGHTS_REGION`, seals it read-only. Holds exactly `{CapEndpoint→devd-ans2, writable CapMemory over WEIGHTS_REGION, CapEndpoint→auditd}` — the storage authority `INV-MODEL-001` denies `inferd`, held by a separate principal bounded in scope *and* lifetime rather than as a fourth capability on the tenant. | `src/servers/modeld/` |
| **G — GPU** | **In scope (decision #10).** Capability-bounded `gpud` holding only `CapGpu`; AGX DMA confined by DART; GPU firmware and its completion records treated as hostile input. | `src/servers/gpud/`, the DART backend's IOMMU trait (#21 note) |
| **A — store** | Fixed-pool store → session table + serving/audit log | `src/kernel/src/db/` (stages 1–4 done) |
| **B — auditor** | Observes the serving stack; manifest unchanged (observe-only) | `src/servers/auditd/` |
| **Caps** | Extend `CapabilityType` (ends at `Frame=10`) with `Serve=11, Model=12, Gpu=13, Admin=14`. `Admin=14` gates the BSP admin session type (decision #17) — six frozen verbs, never a shell. | `capability/capability_type.rs`; proofs in `src/capability-verify/` |

~~HAL trait surface: `hal/{mmu,interrupts,timer,context,syscall,entropy,mitigations,iommu,measure,fpu,bus}.rs`
— one trait per concern, per-backend implementations…~~ **CANCELLED (#21).** With one platform there are no
backends to select between: the aarch64/Apple implementations (**AIC**, **DART**, RNDR, PAC-BTI, and *no*
measurement hardware) are simply the implementations. Where a trait is still worth having — the DART IOMMU
surface carrying the `INV-DEV-006` no-widening proof — it belongs to its own subsystem, not to a
cross-architecture layer.

Serving datapath:

```
client ──TCP──▶ devd-nic ▶ linkd ▶ ipd ▶ transportd ▶ servd (auth + parse + sessions)
                                                          │
                                    CapServe(session_i), synchronous IPC
                                                          ▼
                                          inferd (CapModel; weights RO region; KV slice_i)
```

with `auditd` observing connect / auth / grant / request / response boundaries.

---

## Phases

| Phase | Goal | Hard deps | Status |
|---|---|---|---|
| **0** | NORTH_STAR / THREAT_MODEL rewrite | — | **DONE** |
| ~~**1**~~ | ~~HAL extraction — multi-arch becomes possible; x86-64 behavior byte-identical~~ | ~~none~~ | **CANCELLED (#21)** |
| **AS-0** | Apple Device Tree parser (host-side, fuzz + Kani) | none | ~~**FIRST CODE** (decision #23)~~ — **DONE**, all four tasks |
| **2** | Secure inbound serving path + capability extensions | ~~P1~~ none | **PARTIAL** — T1/T2/T3 done; **no `servd`**, caps not extended |
| **3** | In-tree CPU inference — architecture-neutral serving engine | P2 ~~, P1-fpu~~ | **PARTIAL** — T1/T3/T4/T5/T6 done; **no `inferd`, no `modeld`**, no regions, no FP |
| ~~**4**~~ | ~~aarch64 core + QEMU `virt` bring-up harness~~ | ~~P1~~ | **CANCELLED (#22)** |
| **AS-1..3** | Apple boot stub → AIC → DART on real hardware | ~~P4,~~ AS-0 | **the only platform** — **NOT STARTED**; AS-0 no longer blocks it |
| **AS-4** | RTKit + ANS2 NVMe + PCIe + Ethernet → serving on the mini | AS-3 ~~, **P3-T9 (hard gate, #13)**~~ | **long pole** — **NOT STARTED** |
| **AS-5** | **AGX GPU** — RTKit GPU endpoint, firmware load, command submission, GPU tensor kernels | AS-4, AS-3 DART proven ~~, **P3-T9 (hard gate, #13)**~~ | **largest single effort; terminal criterion (#12)** |
| ~~**5**~~ | ~~GPU on x86-64 (INV-GPU) — discrete accelerator~~ | ~~P3, P1-iommu~~ | **CANCELLED (#20)** — no x86-64 platform to host a discrete accelerator |
| **X** | Proof program, CI, crate burn-down | woven throughout | continuous |

### Critical path to "the Mac mini serves inference"

```
AS-0 (ADT parser) ──▶ AS-1 ──▶ AS-2 ──▶ AS-3 ──▶ AS-4 ──┐
                                                        ├─▶ AS-4c ──▶ AS-5 = DONE (#12)
P2 (serving path) ──▶ P3 (inference engine) ────────────┘
```

Two independent tracks converge at **AS-4c**. The **platform track** (`AS-0 → AS-1 → AS-2 → AS-3 → AS-4`)
is serial and hardware-gated, and AS-0 is its only host-testable member. The **product track**
(`P2 → P3`) is architecture-neutral, developed and unit-tested on `aarch64-apple-darwin`, and **blocked by
no Apple work** (#27). Running both concurrently no longer needs a HAL to justify it — it needs only that
the neutral subsystems stay neutral, which is a north-star rule.

**The P3-T9 hard gate of decision #13 is gone (#27)** — not satisfied, not deferred: **unreachable**. It
named an end-to-end run against QEMU x86-64, and that platform was dropped. AS-4 and AS-5 are therefore
gated on their own dependencies and on the per-component criteria in Phase 3 below, and there is no
substitute integration gate, because there is no second machine to integrate on. Stated plainly: the
first true end-to-end integration of the serving stack now happens **on hardware, at AS-4c**, which is
exactly the risk decision #13 existed to avoid. That risk is accepted, and it is why the per-component
criteria replacing P3-T9 are load-bearing rather than bookkeeping.

Model legend: **S** = Sonnet 5 (default builder) · **O** = Opus (crypto, audits, hardest proofs) ·
**H** = Haiku (docs, tests, boilerplate) · **F** = Fable (planning).

---

### ~~Phase 1 — HAL extraction~~ *(CANCELLED — decision #21)*

**Cancelled 2026-08-03.** An eleven-trait abstraction layer with one backend is an abstraction over
nothing. The rows below are struck through in place rather than deleted, so the cancellation is auditable
and P1-T1's landed deliverable stays traceable. **No code is removed by this cancellation** (#26):
`src/kernel/src/arch/*` stays where it is and stays building as the frozen reference.

- **P1-T1** ~~Design HAL trait set + contracts~~ — **DONE** (`670e072`), deliverable now **SUPERSEDED**: [`architecture/HAL.md`](architecture/HAL.md) carries a ⛔ banner, body preserved.
- ~~**P1-T2** Move `arch/*` → `arch/x86_64/`, implement HAL traits, zero behavior change. **S**. Deps: T1. Verify: `cargo test --lib`; x86 QEMU boot parity against pre-refactor logs.~~ — **CANCELLED.**
- ~~**P1-T3** Refactor `hardware_security/*` to consume HAL traits (x86 backend). **S**. Deps: T1.~~ — **CANCELLED.**
- ~~**P1-T4** Multi-target build plumbing (per-target `.cargo/config.toml`, add `aarch64-unknown-none`, cfg gates, in-tree build scripts). **S**. Deps: T1.~~ — **CANCELLED as HAL work.** The aarch64 target plumbing it described is still needed and is absorbed into **AS-1**, which needs an in-tree target spec of its own regardless.
- ~~**P1-T5** Boot-flow seam: `boot/phases.rs` + `boot/hardware_security_init.rs` call HAL only. **S**. Deps: T2, T3.~~ — **CANCELLED.**
- ~~**P1-T6** Kani: HAL MMU contract preserves W^X and page-table invariants (new `src/hal-verify/`). **O**. Deps: T2.~~ — **CANCELLED as HAL work.** The W^X and page-table proof obligation is not cancelled; it attaches to the aarch64 MMU at AS-1 and stays **Full tier** ([`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16).
- **P1-T7** ~~`docs/architecture/HAL.md`~~ — **DONE** (`670e072`), then **SUPERSEDED** 2026-08-03. ~~Update for Apple-primary ordering.~~
- ~~**P1-A** Security audit of the HAL seam. **O**. Gate.~~ — **CANCELLED**: there is no seam to audit.

### Phase AS-0 — Apple Device Tree parser *(the first code — decision #23)*

No hardware, no dependencies, entirely host-testable. Rated **GO** by the research memo and "useful even if
the stream stops here." ~~**Moved from Wave 2 to Wave 3 by decision #19**…~~ — **superseded by #23.** That
deferral rested on AS-0 being off the critical path to P3-T9; P3-T9 is unreachable and the path is gone.
AS-0 is now the head of the platform track, and with Phase 4's harness cancelled (#22) it is the **only**
Apple work that can be verified before the hardware rig exists.

- **AS-0-T1** **DONE (`981f693`, `b3d2dba`)** — ADT binary-format specification, re-derived from published Asahi documentation. Field widths and flag bits are **not** assumed — anything only documented by source gets specified by one session and implemented by another. **O**. Verify: written spec. Deliverable: [`platform-specs/apple-device-tree-format.md`](platform-specs/apple-device-tree-format.md), 1069 lines.
- **AS-0-T2** **DONE (`e4c6296`, `f7d8df8`)** — `#![no_std]`, zero-allocation, fail-closed ADT parser. Every offset/length/count bounds-checked against its containing region; malformed input denies. **S**. Deps: T1. Verify: host tests. Landed as `src/adt/` with golden and adversarial test suites.
- **AS-0-T3** **DONE (`5c89031`)** — Fuzz target + Kani harness (no-panic, bounds, no allocation driven by ADT-supplied sizes). **S** harness / **O** hardening. Deps: T2. Verify: fuzz soak + Kani green — **INV-MEM**, INV-SERVE discipline. Landed as `src/adt-verify/` plus a 46-input corpus; the no-allocation harness runs in CI behind the `deny-allocation` feature. *Caveat: the Kani harness runs in CI, the fuzz target does not — see P2-T10.*
- **AS-0-T4** **DONE (`e89bd34`)** — boot-args parser + ADT/boot-args memory-range cross-check (disagreement fails closed). **S**. Deps: T2. Verify: host tests with adversarial fixtures. Landed as `src/adt/src/boot_args.rs`.

### Phase 2 — Secure inbound serving path *(architecture-neutral)*

- **P2-T1** **BSP v2 protocol spec — RE-OPENED, and COMPLETE.** ~~BSP v1 protocol spec — DONE (`670e072`)~~ — v1's signature-over-ephemeral-key-agreement handshake is superseded by decision #16's pre-shared-key transport. Deliverable: [`architecture/BSP-v2-serving-protocol.md`](architecture/BSP-v2-serving-protocol.md), covering the PSK handshake, the HKDF-SHA256 key schedule, the retained record layer, the ratchet, and **both session types** (client and admin). **O**. Verify: spec precise enough to drive Kani harnesses and fuzz targets against every parser and every state transition.
- **P2-T2** **DONE (`1c290ce`, proofs `40e3e1d`)** — Factor `ssh/` primitives into `src/transport-crypto/` (`no_std`) + server-side handshake. **Shrunk by decision #16**: no curve arithmetic, no key agreement, no signature verification on this path — the deliverable is the **PSK handshake FSM, HKDF-SHA256 derivation, and the ChaCha20-Poly1305 record layer**, over the in-tree primitive set (SHA-256, HKDF, ChaCha20, Poly1305). **O**. Deps: T1. Verify: Kani (no-panic, length-checked), fuzz handshake FSM, test vectors — 10 Kani proofs in `src/transport-crypto-verify/`, two fuzz targets with 29- and 49-input corpora, four host test suites. **⚠️ Outstanding debt, not a completed claim: `sha2` and `chacha20` are still the *vendored* crates** (`src/transport-crypto/Cargo.toml`). HKDF, HMAC, Poly1305, the schedule, the record layer, and the ratchet are in-tree; the hash and stream cipher are not. Until X-T4 lands, this path **does not satisfy the north star's "dependency closure is itself" rule**, and no doc may describe the primitive set as in-tree.
- **P2-T3** **DONE (`d763089`, proofs `40e3e1d`)** — Fail-closed BSP request parser, `no_std`, zero-alloc, bounded. **S**. Deps: T1 — it parses the wire format T1 now redefines. Verify: fuzz + Kani + audit — **INV-SERVE**. Landed as `src/bsp/` (message, raw, handshake, record, response, session, admin, error) rather than `servd/src/parser.rs`, because `servd` does not exist yet; it is a standalone decoder crate that `servd` will consume. 16 Kani proofs in `src/bsp-verify/`, an 89-input fuzz corpus, and state-machine/valid/adversarial test suites. `src/bsp/src/admin.rs` defines the admin message **shapes only** — the dispatcher is P2-T14 and is not built.
- **P2-T4** `servd`: accept via `transportd`, session manager, per-client frozen capability set. **Both session types** (decision #17): a session is a client session holding `CapServe` or an admin session holding `CapAdmin`, decided at accept and frozen there; nothing promotes one into the other. **S**. Deps: T1, T2, T3, T5. Verify: 2-concurrent-session integration; cross-naming denied; a client session cannot reach an admin verb.
- **P2-T5** **DONE (`enum` + proofs in one commit)** — Capability extensions `Serve`/`Model`/`Gpu`/**`Admin`** + grant/derive/revoke rules; extend `src/capability-verify/`. `Admin=14` follows `Serve=11, Model=12, Gpu=13` and is a distinct grant, never derivable from `CapServe` (decision #17). **O** — INV-AUTH, Full tier. Verify: Kani green, including no derivation path from `CapServe` to `CapAdmin` — **`no_derivation_path_leads_between_serve_and_admin` verifies, symbolic over both directions**, alongside `derivation_never_changes_a_capabilitys_type` (over every type), the escalation-type proof for `CapModel`, and two proofs pinning the discriminants to `CAPABILITY_MODEL.md`. **11/11 harnesses in the crate verify.** *Scope stated honestly: these prove the **kernel** offers no such path. "A session's type is decided at accept and frozen there" is `servd`'s half (P2-T4) and stays unproven until `servd` exists.* **This unblocks P2-T4 — `servd` now has no unmet dependency.**
- **P2-T6** Delete `boot/ssh_bridge.rs` `static mut` session globals; route inbound via servd + capability IPC only. **S**. Deps: T4. Verify: grep-gate (no `static mut` session state); connect e2e.
- **P2-T7** Reframe `db/` for the session table + serving log (fixed pools) + cross-session non-interference Kani. **S** build / **O** proof. Deps: T5. Verify: Kani — no session row readable via another session's capability.
- **P2-T8** `auditd` extension: subscribe to serving events; manifest unchanged. **Admin-session events are in scope** (decision #17): connection accept, selector match or no-match, authentication success or failure, capability grant, **every admin verb**, every denial, and teardown, carrying the credential handle and session id and **never** key material, prompt bytes, or token bytes. Observing an admin verb grants no authority to observe it. **S**. Deps: T4, T14. Verify: manifest diff = zero new capabilities (INV-AUDIT); every verb and every rejection path in T14 produces exactly one attributable event; CTF corpus ≥ 95% TP.
- **P2-T9** ~~vTPM closure~~ — **DONE** (`c01d0ab`). **x86-64 only, and therefore frozen reference, not scheduled** (#26): the code stays and keeps building, and nothing depends on it, because there is no TPM on the only platform. It has no analogue and no successor (#24).
- **P2-T10** **NOT STARTED — and the checked-in corpora must not be read as evidence otherwise.** Fuzz corpus + targets (handshake, parser, session state) into CI. **H** scaffold / **S** corpus. Deps: T2, T3. Eleven fuzz targets and their corpora are committed under `fuzz/`, but **`.github/workflows/ci.yml` contains no `cargo fuzz` invocation at all** — `grep -n "cargo fuzz\|corpus" .github/workflows/ci.yml` returns nothing. The only verification job runs **Kani proofs**, which are a different technique proving different things. Stated plainly: **every fuzz target in this repository is built and never executed.** No task above may cite "fuzz soak" as satisfied until this lands.
- **P2-T11** Host-side test client `tools/bsp-client/` (std, zero crates), **driving both session types**. Grows the admin verb set of decision #17 — **exactly six verbs**: enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. The set is frozen and compile-time-enumerated; there is **no `rotate` verb** (rotation is enroll-then-revoke), no `set-config`, no file or exec verb, and no verb that adds, removes, or widens a capability. The client exercises every verb and every rejection path against the T14 dispatcher. **H**. Deps: T1, T4, T14.
- **P2-T12** Runtime key enrollment + HKDF ratchet (decision #18). Extend `src/kernel/src/boot/credential_store.rs` to enroll and revoke client and admin pre-shared keys at runtime, persisting to ANS2 NVMe on Apple Silicon from AS-4a (`src/kernel/src/arch/virtio_blk.rs` is **frozen reference, not scheduled** — #26); **no secret is ever compiled in** — `src/kernel/src/ssh/client_identity.rs:21` (`const CLIENT_KEY_SEED`) is an acknowledged dev seed and is no longer the model. Forward secrecy comes from a symmetric HKDF chain: session key *n* is derived from chain key *n*, the chain advances, and chain key *n* is zeroized — derivation and advance are one operation with no path that does either alone. **The break-glass admin PSK is provisioned over the serial console and authenticates over serial only; the network listener refuses it outright** (decision #17), so a compromised admin session can neither revoke nor replace it. **O**. Deps: T1, T4, T5. Verify: recorded-traffic test — material captured after an advance must not decrypt records sealed before it; enrollment/revocation are attributable audit events; grep-gate on compile-time key material.
- **P2-T13** Credential store at rest (decisions #18, **#25**) — **there is no sealing task left**. ~~*x86-64:* seal the credential store to the TPM against the measured boot state established by P2-T9…~~ — **CANCELLED with the platform (#20).** The credential store is **plaintext at rest, permanently**. Sealing binds a secret to a measured boot state; the only platform has neither the measurement nor the hardware to bind against, so **no version of this task closes the gap and none is scheduled**. What remains of P2-T13 is documentation and disclosure: the release notes must state the plaintext-at-rest exposure plainly, and a stolen disk yields every client and admin pre-shared key. **O**. Deps: T12. Verify: release notes state the exposure; grep-gate that no code, log line, or protocol field claims the store is sealed. **P2-A passes on the disclosure being correct, not on work having been done** — there is no deliverable here to audit.
- **P2-T14** Server-side admin verb dispatch in `servd` — the other half of decision #17, and the thing P2-T11 drives. A compile-time enumeration of **exactly six** handlers, reachable only from a session holding `CapAdmin`, with no command interpreter, no path or filename anywhere in the surface, and no handler that adds, removes, or widens a capability. `enroll-key` / `revoke-key` delegate to the T12 credential store and both refuse the break-glass handle unconditionally and non-configurably. `load-weights` names a **measured digest and never a path or a byte stream** — the blob does not travel over BSP — and activates the blob the P3-T3 loader measured; until P3-T3 lands it fails closed rather than accepting anything. **It is a reboot-class operation** *(owner decision 2026-08-03)*: the handler **terminates every session, including the one that issued it**, tears down the serving stack, re-runs `modeld` (P3-T3a) against the newly named generation, and relaunches `inferd`. A reload is a **new generation, not a mutation** — no sealed weights page is ever made writable again ([`architecture/MEMORY_MODEL.md`](architecture/MEMORY_MODEL.md) §13), and the handler must not offer, imply, or degrade into a hot swap. **No verb is added for this**: the set stays at exactly six, and the change is to what `load-weights` means. `read-audit-log` is a bounded, read-only cursor over the T7 store; reading grants no authority. `restart-server` takes an **enumerated server identity**, never a name, and relaunches with the target's existing frozen manifest, minting nothing. `reboot` tears down the admin session before proceeding. **O** — this is the network-reachable administrative surface. Deps: T4, T5, T7, T12, **P3-T3a** (the `modeld` the `load-weights` handler re-runs). Verify: fuzz + Kani on the verb decoder (**Full tier — a hostile-input parser**); grep-gate that the handler table has exactly six entries and no `rotate`; a `CapServe` session reaches none of them; every verb and denial emits an attributable event (T8); **`load-weights` leaves zero live sessions and no writable weights mapping — a test asserting that a session survives it is a test asserting a hot swap, and must fail.**
- **P2-A** Security audit. **O**. Gate.

### Phase 3 — In-tree CPU inference *(architecture-neutral)*

- **P3-T0** **Userspace FP/SIMD enablement**: in-tree target spec for `inferd` + FP state save/restore in the context switch. Kernel stays soft-float. **S** impl / **O** review (context-switch ABI is TCB). Deps: ~~P1~~ none — with the HAL cancelled (#21) this is the aarch64 FP/NEON state path directly. Verify: FP-dirty context-switch test; Kani on save-area bounds. *The x86-64 XSAVE/XRSTOR path is frozen reference, not scheduled (#26).*
- **P3-T1** **DONE (`04868c3`, `88f6b62`)** — Weight format spec "BXW1" (header, tensor table, per-tensor SHA-256, hard size bound; Q8_0 + f32). **S** spec / **O** review. Verify: spec; INV-MODEL mapping. Deliverable: [`architecture/BXW1-weight-format.md`](architecture/BXW1-weight-format.md).
- **P3-T2** **NOT STARTED, and it now blocks more than it did.** `grep -rn "WEIGHTS_REGION\|KV_REGION" src/kernel/src/memory/` returns nothing. **`virtual_address_layout.rs` still hardcodes `PAGE_SIZE_IN_BYTES = 4096`** against a platform whose base page is 16 KiB — that constant is the exact `INV-MEM-009` defect this row's own note warns about, and it must be fixed as part of this task rather than alongside it. Reserved regions: extend `memory/virtual_address_layout.rs` + `physical_allocator.rs` with a build-time `WEIGHTS_REGION` (read-only after load, W^X) + per-session `KV_REGION` partitions; no allocator. **S**. Deps: ~~P1~~ none. Verify: Kani (region non-overlap; weights-never-writable-post-seal) — **INV-MEM**. *Sized in **pages**, never bytes: the platform's base page is **16 KiB**. `INV-MEM-009` survives the loss of the second architecture — it is now a rule against hardcoding 16 KiB just as much as 4 KiB, and the frozen 4 KiB reference is the cheapest available second data point.*
- **P3-T3** **DONE as the decoder (`3484e7a`, `982f6ea`) — and *only* the decoder.** Fail-closed BXW1 loader (streaming digest, measured, denies malformed/oversized). **S**. Deps: T1, T2. Verify: fuzz BXW1 header/tensor-table + Kani. Landed as `src/bxw1/` with valid and adversarial test suites. **It touches no `WEIGHTS_REGION` and holds no capability**, because neither exists: the region is P3-T2 (not started) and the host that runs this parser is `modeld`, P3-T3a (not started). Reading this row as "the weight loader is done" is wrong — what is done is the *parsing*, not the *loading*.
- **P3-T3a** **`modeld` — the one-shot weight loader server** *(added 2026-08-03 by owner decision; it closes BXW1 open question 6, which observed that the loader's host was named nowhere in this roadmap).* Hosts the P3-T3 parser in `src/servers/modeld/`. Manifest is **exactly three capabilities** — `CapEndpoint`→`devd-ans2` (read the blob and the vocab blob), writable `CapMemory` over `WEIGHTS_REGION` (populate, then request the seal), `CapEndpoint`→`auditd` (one event per load attempt) — and **no** `CapServe`, `CapModel`, `CapAdmin`, network, or spawn. It runs to completion **before `inferd` launches** and **exits**, so no running process holds storage authority or a writable weights capability while the system serves. The rejected alternative was a **fourth capability on `inferd`**: that degrades `INV-MODEL-001` (written sign-off required) and widens the long-lived, remotely reachable, adversarially prompted component instead of a short-lived one. **Full tier** — it parses a hostile blob; the assignment lives in [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16, which is the only tier table. **O**. Deps: T2 (the region and its seal), T3 (the parser), T5 (the vocab parser it invokes at S9), P2-T14 (which orders the reboot-class reload). Verify: manifest audit — the diff shows exactly the three capabilities and `inferd`'s manifest is unchanged at three; launch-ordering test — `inferd` cannot start until `modeld` has exited and the region is sealed; a Kani obligation shared with T2 that no capability naming `WEIGHTS_REGION` writable outlives `modeld`; grep-gate that no server manifest other than `modeld`'s names a storage endpoint. Deliverable spec: [`architecture/BXW1-weight-format.md`](architecture/BXW1-weight-format.md) §10.0.
- **P3-T4** **DONE (`ef48866`, `88f6b62`)** — Tensor kernels (`no_std`, fixed scratch): matmul (f32 + Q8 dequant), RMSNorm, softmax, RoPE, SiLU/SwiGLU. **S**. ~~Deps: T0~~ — landed **ahead of** T0, which is still not started; the kernels are scalar and soft-float today, so enabling userspace FP/SIMD is a later speed-up, not a prerequisite. Verify: property tests vs reference; no-alloc grep-gate. Landed as `src/tensor/`.
- **P3-T5** **DONE (`821f544`, `edc0bfe`)** — In-tree BPE tokenizer; the vocab blob is hostile input → fail-closed. **S**. Deps: T1. Verify: fuzz + Kani vocab parser; round-trip tests. Landed as `src/tokenizer/` with pretokenize, adversarial, roundtrip, merge-order, and bounded-work suites. *Caveat: no vocab fuzz target exists yet, and per P2-T10 no fuzz target runs in CI regardless.*
- **P3-T6** **DONE (`aaa1607`, `982f6ea`)** — Transformer forward pass + KV cache in per-session slices; decode loop + sampling (CSPRNG from `hardware_security/csprng.rs`). **S**. Deps: T4, T5, T2. Verify: logits parity vs a host f32 reference on a tiny model. Landed as `src/transformer/` with parity, bounds, decode, and sampling suites. **The "per-session slices" are a library abstraction only** — `KV_REGION` does not exist (T2 not started), so nothing enforces the partitioning at the memory level yet.
- **P3-T7** `inferd`: confined-tenant manifest (capabilities = {Model, serving endpoint, own KV slice}; no Spawn, no net, no cross-session); wired to servd over synchronous IPC. **S**. Deps: T6, P2-T4. Verify: manifest audit — the model *cannot name* forbidden capabilities — **INV-MODEL**.
- **P3-T8** Confinement suite: adversarial-prompt harness (injection corpus) — zero escalation under any input. **O**. Deps: T7. Verify: suite green = CI regression bar.
- **P3-T9** ~~e2e: `bsp-client` → QEMU x86-64 → auth → prompt → streamed tokens; 2 isolated clients. **H** scaffold. Deps: T7, P2-A. Verify: **datapath exit criterion — and the hard gate of decision #13.**~~ — **UNREACHABLE, replaced by #27.** The criterion named a QEMU x86-64 run, and x86-64 is not a platform. **It is not restated against Apple Silicon**, because on Apple Silicon the equivalent run *is* AS-4c, which is hardware-gated and sits at the end of the driver chain. Say it plainly: **the serving stack has no integration test until AS-4c.** What replaces P3-T9 as the Phase 3 exit is the per-component host-test set below, run on `aarch64-apple-darwin`, plus the honest note that passing all of it proves the components and not the system.
- **P3-T9a** *(replaces P3-T9)* **Host-run serving datapath, no kernel.** `bsp-client` → `servd` → `inferd` as host binaries over the same synchronous-IPC shapes, on `aarch64-apple-darwin`: PSK handshake, request parse, two isolated sessions, streamed tokens, session teardown. **H** scaffold / **S** wiring. Deps: T7, P2-A. Verify: two concurrent sessions cannot name each other's state; a malformed request denies without allocating; teardown zeroizes the KV partition. *This is a host-level test of the composed components, not a boot, not a kernel, and not an end-to-end system claim — an asserted equivalence to P3-T9 would be exactly the kind of unfalsifiable claim the north star forbids.*
- **P3-T9b** *(replaces P3-T9)* **Per-component exit criteria, each green independently:** the transport handshake FSM against its test vectors; the BSP request parser under fuzz soak and Kani; the BXW1 loader under fuzz soak and Kani; the tokenizer round-trip and vocab fuzz; logits parity against a host f32 reference; the confinement suite at zero escalations. Deps: their owning tasks. Verify: each component's own gate in [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16, with no component permitted to pass on another's evidence.
- **P3-A** Security audit. **O**. Gate. *Now the last audit before hardware, since the integration gate it used to sit beside is gone.*

### ~~Phase 4 — aarch64 core + QEMU `virt` harness~~ *(CANCELLED — decision #22)*

**Cancelled 2026-08-03.** Apple hardware is the only bring-up target, so a QEMU `virt` machine is a second
platform's worth of work — GICv3, PL011, 4 KiB pages, none of which exist on the mini — maintained to
rehearse for a machine it does not resemble. `AS-1` therefore depends on **`AS-0` alone**.

**What this costs, unsoftened:** the harness was described here as "the only way to debug aarch64 core code
with a working console before facing hardware where nothing works until the UART does," and that sentence
was correct. Cancelling it means the first aarch64 instruction BraiNIX ever executes runs on the mini, over
a debug UART cable, with no prior console. The aarch64 core work below is **not deleted — it is absorbed
into AS-1**, which needs every one of these pieces anyway; only the QEMU rehearsal of it is gone. The rows
stay struck through in place so that absorption is auditable.

- ~~**P4-T1** Target plumbing `aarch64-unknown-none` (linker script, QEMU `virt` runner). **S**. Deps: P1.~~ — **absorbed into AS-1** (which needs a custom in-tree target spec regardless); the `virt` runner is cancelled.
- ~~**P4-T2** Boot path: entry assembly, EL2→EL1, MMU init, PL011 UART. **S**. Deps: T1. Verify: QEMU virt boot banner.~~ — **absorbed into AS-1**, against the s5l UART rather than PL011. *The page-size discipline survives and hardens: the platform is **16 KiB**, there is no 4 KiB harness to test against, so `INV-MEM-009` is now enforced by review and by expressing every size in pages.*
- ~~**P4-T3** Exception vectors + a `hal/interrupts` backend (GICv3, harness-only). **S**. Deps: T2.~~ — **CANCELLED.** GICv3 was harness-only and the harness is gone; **AS-2** builds AIC directly.
- ~~**P4-T4** Generic timer + `hal/context` + SVC syscall entry backends. **S**. Deps: T2.~~ — **absorbed into AS-1**: core aarch64, still required, no longer a separate phase.
- ~~**P4-T5** aarch64 `hardware_security` backends: RNDR, PAC/BTI, CSV2/SSBS. **S** build / **O** audit. Deps: T2.~~ — **absorbed into AS-1**.
- ~~**P4-T7** Re-instantiate the W^X / page-table Kani harnesses for the aarch64 MMU in `src/hal-verify/`. **O**. Deps: T2.~~ — **absorbed into AS-1**, in the aarch64 MMU's own verify crate rather than `hal-verify/`. The proof obligation is unchanged and stays **Full tier**.
- ~~**P4-A** Security audit of the aarch64 core. **O**. Gate.~~ — **folded into AS-A**.

*(P4-T6 virtio-mmio and P4-T8 real-metal server checklist were already dropped — superseded by the AS-4
driver chain and the earlier descoping.)*

### Phase AS — Apple Silicon platform *(the only platform)*

Target: Mac mini M2 Pro, `Mac14,12`, SoC `T6020`. Verdicts carried forward from the P6-T1 memo, re-rated under
decision #6 and again under #20–#23.

**Development rig required before AS-1:** the mini in Permissive Security (`bputil` from One True
Recovery — needs local admin credentials and physical presence, once per machine), a debug UART cable, and
m1n1 running as a lab instrument on the machine for register exploration and payload loading. Payload
delivery is `kmutil configure-boot -c <payload> -v <volume>`, which wraps the payload as an Image4 object
under the machine's Secure-Enclave-held local policy — an Apple-supported, documented flow. The full
checklist, including the parts that are owner actions rather than engineering, is in *Deployment
readiness* below.

**Every task in this phase is sliced at the hardware gate**, following AS-1a. The decoding half of each —
ADT-derived discovery, register layouts, PTE encoders, mailbox and NVMe structures — is a pure function
over bytes, is host-testable, and is written *before* the rig exists; only the half that touches silicon
waits. Those slices are enumerated as **Track C** in *The plan from here*, and AS-3a in particular
discharges one of AS-5-T0's five signed preconditions on a laptop.

- **AS-1** **SLICED (2026-08-10).** AS-1 as written below is a dozen independent subsystems, and one spec across all of them would be written entirely against unverified assumptions. It is now delivered in slices, each with its own design doc. **AS-1a is COMPLETE to the hardware gate (`e90ea1e`)**; the rest are unstarted.
  - **AS-1a — first light.** [`architecture/AS-1a-first-light-boot-stub.md`](architecture/AS-1a-first-light-boot-stub.md). The smallest payload that proves the delivery chain: target plumbing, linker script, entry assembly, s5l UART transmit, ADT-derived UART discovery, banner. Landed as **`src/boot-stub-apple/`** with 32 host tests and a linked `aarch64-unknown-none-softfloat` image. **Everything except the hardware run is done**; the run is blocked on the rig, not on code.
  - **AS-1b onward — unstarted.** EL2→EL1, MMU init, exception vectors, generic timer, SVC entry, RNDR/PAC-BTI, watchdog reset, Image4/`kmutil` delivery, secondary-CPU release.

  **Two deviations from this document, recorded rather than left silent:**

  1. ~~aarch64 target spec~~ — **no custom target spec is needed, and this row was wrong to say one is.** `aarch64-unknown-none-softfloat` is a **built-in** rustc target and is correct for a soft-float `no_std` payload. A custom spec becomes necessary only when PAC-BTI or M2-specific CPU tuning does, which is AS-1b at the earliest. `rust-toolchain.toml` carries the built-in target as of `e90ea1e`.
  2. **The stub lives in `src/boot-stub-apple/`, not `arch/aarch64/apple/`** as the *Architecture target* table above states. The kernel crate builds only for `x86_64-unknown-none`, and making it multi-target means cfg-gating its whole module tree before a single character has been printed — putting the frozen reference build (#26) at risk for no gain. The stub is **excluded from the workspace**, exactly as `tools/proof-coverage` is, and is absorbed into `arch/aarch64/` when the kernel itself goes aarch64 and there is a real MMU and vector table to merge with.

  **S** impl / **O** review. **Deps: AS-0 alone** (#22). **Exit criterion: BraiNIX prints its invariant banner over serial on the M2 Pro mini** — unchanged, and still unmet: *the first place any of it runs is hardware.*
- **AS-2** AIC backend + FIQ timer path. **S** impl / **O** review. Deps: AS-1 ~~, P1-T2 stable~~. Notes: AIC is not a GIC — a single packed event word replaces the GIC ack/EOI pair, per-CPU timers arrive as **FIQ** outside the controller entirely, and IPIs go through implementation-defined system registers. Select the AIC revision from ADT compatible strings at runtime; **fail closed on an unknown string.** Verify: timer IRQ + IPI on hardware.
- **AS-3** DART (IOMMU) backend and its own IOMMU trait — the home of the `INV-DEV-006` no-widening proof now that the HAL is cancelled (#21). **S** impl / **O** proof. Deps: AS-2. Notes: dozens of per-device instances discovered from the ADT, not one translation unit; PTE formats differ across SoC generations. **Every discovered instance defaults to deny-all from the first commit**; unknown variants fail closed; locked-DART semantics represented honestly in the trait rather than papered over. Verify: Kani (driver cannot widen its own window); DMA fault injection.
~~**AS-4 is gated on P3-T9 (decision #13).** No task in the AS-4 chain starts… until the x86-64/QEMU serving
path is proven end to end.~~ — **gate removed by #27**, because it named a platform that no longer exists.
What replaces it is weaker and is stated as such: AS-4 starts when AS-3 is done and the **P3-T9a/T9b
host-test criteria** are green. That is a components-green bar, not a system-green bar, so the memo's NO-GO
rating on this chain is re-opened on less evidence than decision #13 demanded.

- **AS-4a** Storage: RTKit co-processor mailbox protocol + ANS2 NVMe (non-standard, tag-based NVMMU quirks). **S** impl / **O** audit. Deps: AS-3. Verify: weights read from disk on hardware. *Interim unblock: payload-embedded weights let AS-4b and the serving path proceed before this lands.*
- **AS-4b** Network: PCIe bring-up + the mini's built-in Ethernet NIC driver, as capability-bounded `devd-*` servers — never in the kernel. **S** impl / **O** audit. Deps: AS-3. Verify: NIC TX/RX on hardware.
- **AS-4c** e2e: remote `bsp-client` → Mac mini M2 Pro → auth → prompt → streamed tokens; 2 isolated clients. Deps: AS-4a, AS-4b, P3-A, ~~**P3-T9**~~ **P3-T9a/T9b**. Verify: **CPU-serving capability demonstrated.** This is a demonstration, not the finish line — the terminal criterion is AS-5 (decision #12). **It is also the project's first true end-to-end integration** (#27), which is why the platform and product tracks converge here.
- **AS-A** Whole-platform security audit, including the TCB-AS enumeration and the INV-BOOT boot posture — reproducible build, release signature, iBoot payload integrity, self-reported log, and **no attestation, no sealing** — restated in the release notes. **O**. Gate.

**Honest rating of AS-4:** the memo rated this chain NO-GO and named it "where the stream can silently
consume the project." Decision #6 overrides that rating; the underlying cost estimate is unchanged. AS-4a
and AS-4b are each plausibly larger than AS-0 through AS-3 combined.

### Phase AS-5 — AGX GPU *(in scope — decision #10)*

**Goal: GPU and CPU at maximum.** The largest single body of work in this plan — larger than the AS-4
driver chain — and the one whose cost is least well understood, because AGX is the biggest
reverse-engineering effort on the platform and none of it may be vendored.

**Hard prerequisite: DART confinement must be proven before any firmware is loaded.** INV-GPU is the
control that makes running Apple's opaque firmware survivable; enforcing it afterward is not an option.

~~**AS-5 is also gated on P3-T9 (decision #13)**~~ — same removal, same reason (#27). AS-5 is gated on AS-4
and on AS-5-T0's five preconditions, which are unchanged and unwaivable.

- **AS-5-T0** DART/GPU confinement proof. **O**. Deps: AS-3. **Gate for everything below**, and the acceptance criteria of the conditionally signed TCB-AS/GPU exception (decision #10, NORTH_STAR.md). All five must be green **before GPU firmware is ever loaded**; each is pass/fail, and none is waivable:
  1. Every GPU-fronting DART instance defaults to **deny-all**.
  2. A **Kani proof on the DART backend's IOMMU trait** that its API surface admits no widening operation — proving that no consumer, `gpud` included, can widen its own DMA window (`INV-DEV-006`). The proof belongs to the confinement (Full tier), **not** to the driver; stating it as a proof about `gpud` would contradict the tiering rule of decision #15.
  3. GPU completion records are **fuzzed and Kani-checked as hostile input** (`INV-PARSE-001`).
  4. The **tenant-mapping policy of decision #14** is enforced: weights read-only and permanent, KV cache per session, **never two tenants resident simultaneously**.
  5. **No iBoot-locked DART on the GPU path** — or, if one exists, its locked semantics are honestly represented in **the DART backend's IOMMU trait** rather than papered over.

  *(History, #21: preconditions 2 and 5 named the HAL IOMMU trait when signed on 2026-08-02; the HAL was cancelled on 2026-08-03, so they now name the AS-3 DART backend's own IOMMU trait directly. The obligation is unchanged in scope; only its home is named differently. Recorded because these are signed pass/fail criteria and a signed criterion should not be edited silently.)*

  **If any precondition proves unsatisfiable on real hardware, the exception self-voids and AS-5 stops.** That is the correct failure mode, not an obstacle to route around. Until all five are green, no build ships with the GPU enabled.
- **AS-5-T1** RTKit GPU endpoint over the mailbox layer built in AS-4a. **S**. Deps: AS-4a.
- **AS-5-T2** GPU firmware load and lifecycle. The blob is Apple-signed, closed, and unauditable — the **conditionally signed TCB-AS/GPU exception**. Load only behind a proven DART window. **S** impl / **O** audit. Deps: T0, T1. **Blocked until all five AS-5-T0 preconditions are green**; the exception is in force for design and implementation work, but firmware load is the line it draws.
- **AS-5-T3** Command submission and completion handling. Completion records are **hostile input** — fuzzed and Kani-checked like any network parser (`INV-PARSE-001`); Full tier by decision #15, wherever they are parsed. **S**. Deps: T2.
- **AS-5-T4** GPU tensor kernels: matmul and attention, targeting **prefill acceleration plus time-sliced multi-client serving** (decision #14). Weights are mapped read-only and permanently; KV cache is mapped per session and unmapped and flushed on exit; **never two tenants resident simultaneously**, so clients take turns rather than share a batch. **Cross-tenant batching is forbidden**, which keeps INV-SERVE intact and needs no exception. Stated honestly: this is a **smaller payoff than "a large win for serving multiple clients concurrently"** — each turn is faster, but they are still turns, and single-stream decode stays bandwidth-bound and gains little. **S**. Deps: T3, P3-T4.
- **AS-5-T5** Scheduling policy across CPU and GPU: which work goes where, how the per-session KV map/unmap boundary is enforced at every time-slice switch, and how a hung or misbehaving GPU fails closed without stalling the serving path. **S** impl / **O** review. Deps: T4.
- **AS-5-A** Security audit, including the TCB-AS/GPU exception write-up and a DMA fault-injection campaign. **O**. Gate.

**Honest note.** Apple's GPU firmware runs concurrently with our kernel, for the life of the system, with
DMA capability, driven by data derived from client requests. That is a materially different trust posture
from SecureROM and iBoot, which run once at boot and then stop. DART is the entire defense.

### ~~Phase 5 — discrete GPU on x86-64~~ *(CANCELLED — decision #20)*

~~P5-T1..T4 unchanged from the original plan; not scheduled. Superseded in priority by AS-5.~~ —
**CANCELLED 2026-08-03**, not merely deferred: a discrete accelerator on a PCIe bus needs an x86-64
platform to sit in, and there is none. The row is kept so the cancellation is auditable. The GPU work that
survives is **AS-5** (AGX), which is a different device, a different bus, and a different threat posture.

### Phase X — Continuous

- **X-T1** ~~Proof-coverage tracker~~ — **DONE** (`670e072`), `tools/proof-coverage/`.
- **X-T2** ~~CI gates **per arch**~~ — **one architecture, one gate set (#20).** `cargo test --lib` on `aarch64-apple-darwin`, `fmt --check`, Kani, fuzz smoke, audit checklist; clippy non-gating. Two bare-metal builds are gated, and they are not peers: the **aarch64 product build** is the target, and the **x86-64 build is the frozen reference (#26) — it must keep compiling, and a break in it is a build regression, not a platform regression.** Nothing is scheduled against it and no new feature is required to work there. **S**. Deps: ~~P1-T4~~ AS-1 for the aarch64 half; the x86-64 half is green today.
- **X-T3** Reproducible build + Ed25519 release signing ~~+ PCR publication~~. **S**. ~~*Split by platform: predicted-vs-attested PCR matching is x86-64 only…*~~ — **removed with the platform (#20, #24).** Predicted-vs-attested PCR matching was an x86-64-only step and there is no x86-64; **X-T3 is now reproducible build + Ed25519 release signature and nothing else.** No PCR is predicted, none is published, and none is matched, because there is no TPM to match against. *Signing is an out-of-tree release step: **in tree, Ed25519 is verify-only** (decision #16) — once the outbound SSH client is removed, nothing in tree holds a private key or signs anything.*
- **X-T4** Vendored-crate burn-down (bitflags, log, multiboot2 first; `sha2` and `chacha20` last, only after the in-tree SHA-256/HKDF/ChaCha20/Poly1305 implementations pass vectors and audit). **Rewritten by decision #16, and the burn-down shrinks substantially as a result:** the Ed25519 verification stack — `ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle` — is **removed from this list entirely**. It is a permanent named exception in NORTH_STAR.md, vendored **verify-only**, and X-T4 no longer targets it. The four hardest crates in the burn-down were exactly those, so what remains of the crypto item is two symmetric primitives with published test vectors — a materially easier task than the one this row previously described. Honest note in the other direction: the remaining `Cargo.lock` floor is now permanent, not a number that reaches zero. **S** impl / **O** crypto. Verify: `Cargo.lock` crate count strictly decreases, measured against a floor that includes the four exception crates.

---

## Per-component "done" gate — tiered

~~Every component ships **all** of the six artifacts below.~~ **The uniform gate was replaced on
2026-08-02 by a gate tiered on TCB proximity (decision #15).** Proof effort moves to the confinement,
following the project's own principle: IOMMU confinement, not driver correctness, is the control.

The six artifacts are:

1. **Invariant mapping** — which INV-* it touches and how.
2. **Fuzz artifact** for every hostile-input parser (libFuzzer target + checked-in corpus + soak before phase exit): BSP parser, handshake FSM, BXW1 loader, tokenizer vocab, **ADT parser**, **boot-args parser**, **GPU completion records**, plus the existing targets kept green.
3. **Kani harness** for every parser *and* every security-relevant path (no-panic + bounds + the stated property: unforgeability, no-widening, non-interference, W^X preservation, region non-overlap, DMA-window non-widening) in `src/{capability,bootloader,serve,infer}-verify/` and the aarch64 MMU/DART verify crates (~~`hal`~~ — the HAL is cancelled, #21; the obligations moved home, not away).
4. ~~**Prusti contracts** where functional (capability derive/revoke, `memory/pool_allocator.rs` bounds), toward the 80% coverage bar.~~ — **REMOVED 2026-08-12 (owner decision).** Full tier is now **five** artifacts, not six. The one Prusti artifact in the tree had never executed and verified a tautology about a copy nothing called; see [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16 for the full record. Its obligation moved to `src/ipc-verify/` — five Kani harnesses over the **real** `perform_rendezvous` — rather than being dropped. INV-IPC-003's timeout-rollback path is now **openly** uncovered by formal methods, which the previous arrangement had masked.
5. **Security audit report** — zero known vulnerabilities, every `unsafe` block justified, constant-time review for key material.
6. **No-regression bars** — auditd ≥ 95% TP, crate count non-increasing, no `static mut` outside the audited allowlist, grep-gates hold.

**Which of them a component owes is decided by
[`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16 and nowhere else.** That section
defines the tiers, states their corollaries, and assigns every component; **this roadmap deliberately
restates none of it**, because two documents stating the same rule in different words is how this gate's
conflict arose. Tier is read off that table at design time — it is not a per-component judgment made at
implementation time — and a component absent from it is **unassessed**, not Reduced. Read §16 before
planning any component's proof work.

**Per-release whole-system audit:** end-to-end over the TCB (kernel, boot stub, capability, IPC, the
aarch64 MMU and DART backends), the full serving datapath, all manifests, and the reproducible build.
~~On x86-64 this includes predicted-vs-attested PCR matching~~ — there is no PCR matching step anywhere
(#24). The release notes must state the boot posture plainly: reproducible build, Ed25519 signature, and
iBoot-verified payload integrity, with **no remote attestation, no sealing, and a self-reported
measurement log that is not evidence**. Release notes state: maximal assurance under the stated attacker
model, not a proof of absolute security.

---

## Verification, per phase

- ~~**P1:** x86 QEMU boot byte-parity vs pre-refactor logs; …HAL Kani harnesses; P1-A.~~ — **cancelled with Phase 1 (#21).**
- **AS-0:** ADT parser fuzz soak + Kani green, entirely on the host, no hardware. **The first and, until AS-1, the only Apple verification loop (#22, #23).**
- **P2:** handshake vectors; parser fuzz soak; 2-client isolation test; cross-session Kani; no derivation path from `CapServe` to `CapAdmin`; ratchet recorded-traffic test; ~~swtpm predicted == attested (x86-64)~~ — **removed, no TPM (#24)**; P2-A. All host-run on `aarch64-apple-darwin`.
- **P3:** logits parity vs host reference; confinement suite (zero escalations under injection); ~~e2e `bsp-client` → QEMU x86-64 → streamed tokens~~ — **unreachable (#27)**, replaced by **P3-T9a** (host-run datapath, two isolated sessions) and **P3-T9b** (per-component criteria); P3-A.
- ~~**P4:** QEMU `virt` aarch64 boot banner; context-switch and syscall tests; per-arch Kani; P4-A.~~ — **cancelled with Phase 4 (#22).** These checks reappear at AS-1, on hardware, over serial.
- **AS-1..3:** serial-verified boot banner on the M2 Pro mini; timer IRQ and IPI on hardware; DART deny-all default proven and DMA faults injected; AS-A.
- **AS-4:** weights loaded from NVMe; NIC TX/RX; e2e remote client → mini → streamed tokens — **the project's first end-to-end run (#27).**

---

## Honest risks

1. **No remote attestation, on the only platform there is (#24).** Unmitigable and permanent. It devalues every other control by making the boot state unprovable to a remote party. ~~Deployments that cannot accept it must run on the x86-64 target.~~ — **that escape hatch is deleted with the platform (#20).** There is nowhere to send such a deployment: BraiNIX cannot prove its boot state to a remote party, ever, and a deployment that requires it cannot use BraiNIX.
2. **The AS-4 driver chain.** RTKit + ANS2 NVMe + PCIe + Ethernet, clean-room, no vendoring. The single largest schedule risk and the most likely place for this plan to stall.
3. **No contract below boot-args.** Boot-args layout, ADT format, AIC/DART registers, and CPU release sequences are reverse-engineered with zero compatibility promise. Every macOS firmware update is a potential breakage, forever, and we re-derive each fix ourselves. Mitigation: pin a known-good macOS stub on the deployment machine; treat firmware updates as re-qualification events.
4. **16 KiB pages, with no second page size to test against.** The platform's base page is 16 KiB. Any 4 KiB assumption leaking into architecture-neutral memory code is an INV-MEM defect (`INV-MEM-009`), and cancelling Phase 4 (#22) removed the 4 KiB harness that would have caught it — so the discipline is now enforced by expressing every size in pages, by review, and by the frozen 4 KiB reference build (#26) as the cheapest available cross-check. Write page-size-parametric from P3-T2 and AS-1 onward.
5. **Inbound is a real posture reversal.** `boot/ssh_bridge.rs` (`static mut` session on 2222, single-core cooperative) is exactly what the threat model forbids at scale — the weakest point in the tree until P2-T6. Fixed pools convert client-driven memory DoS into capacity exhaustion: fail-closed is correct for security but an *availability* loss, so per-client admission limits in servd are load-bearing.
6. **"No new crates" against building an inference engine plus a platform stack from scratch.** Tokenizer, quantized matmul, RoPE, sampling, weight format, AIC, DART, RTKit, ANS2, PCIe, NIC — all hand-rolled. The soft-float kernel target (P3-T0) touches the TCB. The AGX GPU (AS-5) is the largest of these and the least well understood. **The crate burn-down itself is materially smaller than this risk once implied (decision #16):** the Ed25519 verification stack is a permanent named exception rather than debt, so `sha2` and `chacha20` are all that remain of the crypto item — two symmetric primitives with published test vectors. The residual risk is the *drivers and the engine*, not the crates. The honest counterweight: `Cargo.lock` now has a permanent floor, and "zero external crates" is a target the project has formally decided not to reach.
7. **Audit capacity is the pipeline bottleneck.** Expect audit queues and multi-round fix loops on the hardest proofs (non-interference, DMA non-widening). Mitigation: draft Kani harnesses alongside code; batch audits per wave.
8. **Clippy is pre-existing red and non-gating** (200+ `arithmetic_side_effects` across the kernel), which hides new lint signal. Scheduled burn-down so it can eventually gate.
9. **Ratchet desynchronization is an availability risk (P2-T12).** The HKDF chain deletes the key it advanced past, so if the two ends disagree irreconcilably — a client store restored from an older state, a server chain advanced past a client that lost its own advance, or a gap wider than the catch-up bound — the handshake fails closed and the client is locked out. That is the correct behavior and there **must never be a fallback to an un-ratcheted key**, because a fallback any failure can trigger is a downgrade any attacker can trigger. Nothing is disclosed; access is lost. Mitigation, and the reason it is not a remote self-destruct: recovery is re-enrollment over the admin channel, and if the credential authorizing that is itself desynchronized, recovery is over the **serial console and nowhere else** — which is why the serial path is compiled in unconditionally and gated on no network state. Stated plainly: a ratchet bug is a lockout requiring physical presence to repair.
10. **No verification loop for the platform track until hardware (#20, #22).** Dropping x86-64 removed the only environment the tree boots in, and cancelling Phase 4 removed the QEMU `virt` harness that would have replaced it. Between now and AS-1's serial banner, **AS-0 and the host-tested P2/P3 work are the only things that can be shown to work at all.** The first aarch64 instruction BraiNIX executes runs on the mini, over a debug cable, with no prior console — and the first end-to-end serving run is AS-4c, at the end of the driver chain. Mitigation is ordering, not tooling: AS-0 first because it is host-testable, then the rig, then AS-1. There is no mitigation for the missing integration gate; it is an accepted cost of #20 and #22.

## Critical files

- `src/kernel/src/arch/mod.rs` — today: cfg-gated x86 modules. ~~The HAL extraction seam~~ — no seam is being cut (#21); this tree is **frozen reference, not scheduled** (#26) and keeps building. Apple platform code lands under `arch/aarch64/`.
- `src/kernel/src/boot/ssh_bridge.rs` — inbound seed to replace with servd; `static mut` session state to delete.
- `src/kernel/src/capability/capability_type.rs` — `Serve`/`Model`/`Gpu`/`Admin` extension point (ends at `Frame=10`).
- `src/kernel/src/boot/credential_store.rs` — runtime key enrollment and the ratchet's persisted chain state (P2-T12); today it persists to virtio-blk and seals nothing, and **sealing is not coming** (#25).
- `src/kernel/src/memory/virtual_address_layout.rs` — fixed reserved WEIGHTS/KV regions (INV-MEM); today it defines neither, and hardcodes a 4 KiB page against a 16 KiB platform.
- `src/capability-verify/src/lib.rs` — the existing Kani proof pattern, now extended across `src/adt-verify/`, `src/bsp-verify/`, and `src/transport-crypto-verify/`.
- `.github/workflows/ci.yml` — all thirteen checks green as of 2026-08-14. Runs six Kani jobs in parallel
  (one per package, with the eight non-terminating harnesses behind `long-proofs`), a line-coverage gate,
  host and bare-metal clippy, a QEMU boot that now genuinely boots, and **zero fuzz targets** — P2-T10's
  entire scope, unchanged.

## The plan from here

~~Close this single-platform documentation gate first — **it is Wave 2** (#27)…~~ ~~**The next step is
P2-T5**…~~ — **both superseded: the documentation gate closed, AS-0 landed in full, P2-T2/T3 landed with
them, and P2-T5 is DONE** (11/11 harnesses verify, including
`no_derivation_path_leads_between_serve_and_admin`). `servd` has no unmet dependency.

**The organizing rule for everything below: build every line that does not need the mini, before the mini
arrives.** AS-1a already proved this is possible on the platform track, not just the neutral one — it is
"complete to the hardware gate" with 32 host tests and a linked `aarch64-unknown-none-softfloat` image,
and the only thing it is waiting for is a cable. That pattern generalizes further than this document
previously claimed, and the sentence it replaces — *"there is no host-testable Apple work left"* — was
wrong: it read the hardware gate as covering the whole task rather than its last step.

Three tracks. They share no code and no dependencies, so they can run in any order or at once.

### Track A — turn seven finished libraries into a serving system *(no hardware)*

Nothing here needs the mini, a crate, or a proof that does not already exist. **None of these five
directories exists today**, and until they do BraiNIX has components without a system.

| # | Task | Deliverable | Deps | Why it is next |
|---|---|---|---|---|
| A1 | **P2-T4** | `src/servers/servd/` — accept via `transportd`, session manager, per-client frozen capability set, both session types decided at accept | T1, T2, T3, T5 — **all done** | **STARTED 2026-08-14.** The host-testable half landed: the §9.1 fixed session pool, the three admission ceilings counting half-open handshakes (`INV-SERVE-003`), and generation-tagged handles so a released slot is unreachable forever. 18 tests, 100% line coverage, **zero exemptions**. What remains needs a kernel: the `transportd` accept, the minted `CapServe`/`CapAdmin`, and the slot's directional keys and `prompt_buf`. |
| A2 | **P3-T2** | `WEIGHTS_REGION` / `KV_REGION` reserved regions in `memory/`, **and the 4 KiB → 16 KiB page fix** | none | `virtual_address_layout.rs` hardcodes 4096 against a 16 KiB platform — an `INV-MEM-009` defect sitting in the file the regions land in. |
| A3 | **P3-T3a** | `src/servers/modeld/` — one-shot loader hosting the finished `src/bxw1/` parser, exits before `inferd` starts | A2, P3-T3, P3-T5 | Nothing holds storage authority or a writable weights capability while the system serves. |
| A4 | **P3-T7** | `src/servers/inferd/` — the confined tenant wrapping the finished `src/transformer/` | A1, A2, P3-T6 | **Covers INV-MODEL**, one of the three uncovered invariants. |
| A5 | **P2-T11** | `tools/bsp-client/` — host test client driving both session types and all six admin verbs | A1, A7 | The only thing that can exercise the datapath end to end before hardware. |
| A6 | **P3-T9a** | Host-run datapath: `bsp-client` → `servd` → `inferd`, two isolated sessions, streamed tokens | A1, A4, A5 | **The first point at which BraiNIX serves inference at all.** |
| A7 | **P2-T14** | Admin verb dispatch — exactly six handlers, `CapAdmin` only | A1, P2-T5, P2-T7, P2-T12, A3 | The network-reachable administrative surface; Full tier. |
| A8 | **P2-T12** | Runtime key enrollment + HKDF ratchet in the credential store | A1, P2-T5 | **Until this lands there is no forward secrecy** — a disclosed PSK decrypts every recorded session. |
| A9 | **P2-T7** | `db/` reframed for the session table + serving log, with the cross-session non-interference proof | P2-T5 | The proof INV-SERVE's blast radius entry rests on. |
| A10 | **P2-T8** | `auditd` extended to serving and admin events, manifest unchanged | A1, A7 | **Covers INV-AUDIT**, the second uncovered invariant. |
| A11 | **P3-T8** | Confinement suite — adversarial prompts, zero escalation under any input | A4 | The INV-MODEL claim is unfalsifiable without it. |
| A12 | **P2-T6** | Delete `boot/ssh_bridge.rs` and its `static mut` session globals | A1 | Risk 5: the weakest point in the tree until it goes. |
| A13 | **P3-T0** | Userspace FP/SIMD enablement — in-tree FP state save/restore, kernel stays soft-float | A4 | Unblocks NEON in the tensor kernels; the context-switch ABI is TCB, so it is reviewed as such. |
| A14 | **P3-T10** *(new)* | **Serving performance baseline.** Measure tokens/s against the `(model bytes ÷ memory bandwidth)` ceiling, host-side first, and record the gap | A6 | The north star makes performance a craft standard and says slowness must be justified by a **named invariant**. That is not checkable without a number, and no task produced one until this row. |
| A15 | **P3-A** | Phase 3 security audit | A6, A11 | The last audit before hardware. |

**Exit for Track A:** P3-T9a green, two isolated sessions, malformed requests denied without allocating,
teardown zeroizing the KV partition — and stated as what it is: **a host-level test of composed
components, not a boot and not a system claim.**

### Track B — assurance debt that currently contradicts a north-star rule *(no hardware)*

Each row closes a claim the tree makes but cannot presently support. These are cheap relative to Track A
and two of them block *honesty*, not features.

| # | Task | What is wrong today |
|---|---|---|
| B1 | ~~**P2-T10** — fuzz targets into CI~~ | **DONE 2026-08-14.** A `Fuzz Smoke` job runs all eleven targets for twenty seconds each, seeded by the checked-in corpora. Two things were needed, not one: `fuzz/.cargo/config.toml` pointed its vendored source at an absolute path that existed on one laptop, so the crate could not resolve dependencies anywhere else. **Twenty seconds is a smoke test and nothing may cite it as a soak** — the soak criteria in this document stay unmet until something runs long enough to deserve the word. |
| B2 | **X-T4** — in-tree SHA-256 and ChaCha20 | `sha2` and `chacha20` are still the vendored crates, so the serving transport **does not satisfy the dependency-closure rule**. With the Ed25519 stack a permanent named exception, these two symmetric primitives with published test vectors are what remains of the crypto burn-down. |
| B3 | **X-T5** *(new)* — make the proof tracker distinguish **runs** from **exists** | `tools/proof-coverage` reports 50 harnesses; 8 are behind `long-proofs` and never execute. A number that counts unrun proofs is exactly the unfalsifiable claim the north star forbids. Also: attack the cost problem itself — the 96-byte ADT harnesses and the AEAD/hash harnesses are excluded, not solved. |
| B4 | **X-T2** — clippy burn-down so it can gate | Clippy is green on both host architectures and the bare-metal target as of 2026-08-13; the remaining suppressions are scope-allows on the frozen reference and the orphaned trees. Removing those is what lets clippy become a gate rather than a habit. |
| B5 | **X-T3** — reproducible build + Ed25519 release signing | INV-BOOT's two artifact-side clauses. Needed **before** anything is delivered to the mini, not after; see *Deployment readiness* below. |

### Track C — build the platform to the hardware gate *(no hardware, until the last step of each)*

The AS-1a pattern: write the slice, host-test everything that has a checkable contract, and stop at the
line where only the machine can answer. What is host-testable here is larger than it looks, because most
of this work is **decoding and encoding** — ADT-derived discovery, register layouts, page-table entries,
mailbox messages — and every one of those is a pure function over bytes, which is the cheapest thing in
this project to verify and the discipline `INV-PARSE-001` already demands.

| # | Slice | Host-testable now | Needs the machine |
|---|---|---|---|
| C1 | **AS-1b** — EL2→EL1, MMU init, exception vectors, generic timer, SVC entry, RNDR/PAC-BTI, watchdog | Page-table construction and the W^X/page-table Kani proofs (16 KiB, parametric); vector-table layout; register encodings | Whether the transitions actually take, on silicon |
| C2 | **AS-2a** *(new slice)* — AIC decode | ADT `compatible`-string → AIC revision selection, **failing closed on an unknown string**; the packed event-word decoder as a pure function, fuzzed and Kani-checked as firmware input | Timer FIQ and IPI delivery |
| C3 | **AS-3a** *(new slice)* — DART model + **the IOMMU trait** | Per-instance discovery from the ADT; PTE encoders per SoC generation; deny-all default construction; **the `INV-DEV-006` no-widening Kani proof on the trait's API surface** | Programming a real DART; DMA fault injection |
| C4 | **AS-4a1** *(new slice)* — RTKit + ANS2 codecs | Mailbox message encode/decode and the ANS2 command/completion structures, as fail-closed parsers with fuzz targets | Talking to the co-processor |
| C5 | **AS-4b1** *(new slice)* — PCIe/NIC descriptor formats | Descriptor and config-space walkers, including the cyclic-capability-list termination the tier table already requires | Link training, TX/RX |

**C3 is the highest-value row in this table and it is not obvious why.** AS-5-T0 precondition 2 — a Kani
proof that the DART backend's IOMMU trait admits no widening operation — is one of the five **signed,
unwaivable** acceptance criteria of the TCB-AS/GPU exception, and it is a proof about an **API surface**.
It can be discharged on a laptop, years before any GPU firmware exists to be confined. Landing C3 turns
one of the five preconditions green ahead of the hardware it protects.

**What Track C cannot do:** it cannot tell you the ADT you parsed is the ADT that machine emits, that the
register offsets are right, or that a sequence completes. Those are the hardware gate, and every slice
above ends at it. The risk this document already names stands unchanged — *the first aarch64 instruction
BraiNIX executes runs on the mini, over a debug cable, with no prior console* — but the amount of code
meeting that moment untested shrinks with every row here.

---

## Deployment readiness — what "ready for the Mac mini" means

The terminal criterion is AS-5 (#12). **Deployment readiness is earlier and is a different thing**: it is
the point at which a signed payload can be delivered to the machine and serve a remote client. It has four
parts, and two of them are not engineering.

### 1. The rig — owner actions, physical, once per machine

None of this can be done from a repository, and **AS-1's hardware gate cannot open until all of it is
true**:

- [ ] Mac mini M2 Pro downgraded to **Permissive Security** via `bputil` from One True Recovery. Requires
      local admin credentials and physical presence. This is also why **fully headless provisioning is not
      available** on this platform.
- [ ] A **debug UART cable** for the s5l console. Until this exists there is no output from a failing boot,
      and a failing boot is the expected first outcome.
- [ ] **m1n1** installed as a lab instrument, for register exploration and payload loading.
- [ ] A **macOS stub install** left on disk — paired recoveryOS and firmware volumes. "Bare metal" means
      our kernel is the OS, not that Apple software is absent.
- [ ] The stub's **macOS version pinned and recorded**. Risk 3: every firmware update is a potential
      breaking change to reverse-engineered structures, with no upstream remedy. Treat any update as a
      re-qualification event.

### 2. The engineering gates, in order

1. **Track A exit** — P3-T9a green: the serving stack composes and serves, host-side.
2. **AS-1 hardware gate** — the invariant banner over serial on the mini. The first proof that anything we
   wrote runs on this machine.
3. **AS-2, AS-3** — timer and IPI on hardware; DART deny-all proven and DMA faults injected.
4. **AS-4a, AS-4b** — weights read from NVMe; NIC TX and RX.
5. **AS-4c** — remote `bsp-client` → mini → auth → prompt → streamed tokens, two isolated clients.
   **This is the project's first true end-to-end integration** (#27) and the demonstration that BraiNIX
   serves inference on the target machine.
6. **AS-A** — whole-platform audit, including the TCB-AS enumeration and the boot posture.

### 3. Release mechanics — X-T3, and it is not optional

A payload reaches the mini as an **Image4 object via `kmutil configure-boot -c <payload> -v <volume>`**,
wrapped under the machine's Secure-Enclave-held local policy. What INV-BOOT requires of us on the artifact
side is a **reproducible build** a third party can reproduce bit for bit and an **Ed25519 release
signature**. Signing is an out-of-tree release step: in tree, Ed25519 is verify-only, and once the outbound
SSH client is removed nothing in tree holds a private key.

**No secret ever enters the payload.** Client and admin keys are enrolled at runtime (P2-T12); the
break-glass admin key is provisioned over the serial console and authenticates over serial only. A
compile-time secret would mean either publishing the secret or shipping an image nobody can reproduce.

### 4. The disclosures that ship with it

These are not caveats to be softened in release notes; the north star requires them stated:

- **No remote attestation, ever.** A client cannot distinguish a genuine BraiNIX boot from a compromised
  one. There is no configuration, target, or later phase that changes this, and no platform to move a
  deployment to that needs it.
- **The credential store is plaintext at rest, permanently.** Anyone who obtains the disk obtains every
  client and admin pre-shared key. Combined with the forward-secrecy gap until P2-T12 ships, physical
  possession of the machine or a backup retroactively decrypts every session recorded from it. Disk
  disposal is a key-compromise event.
- **The measurement log is self-reported** and is a debugging aid, never evidence.
- **The serial console grants physical-access authority** and must not be present in a production
  configuration.

### What is *not* required for deployment readiness

**AS-5 (the GPU) is not.** It is the terminal criterion for the project, not a precondition for serving:
AS-4c is CPU serving on the target machine, and the GPU's payoff is prefill acceleration plus time-sliced
multi-client serving on top of it. Deploying at AS-4c and adding AS-5 afterwards is the intended order,
and no GPU-enabled build ships until all five AS-5-T0 preconditions are green.
