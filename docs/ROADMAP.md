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
| 6 | **Apple Silicon is the PRIMARY platform.** Reference deployment: Mac mini M2 Pro (`Mac14,12`, SoC `T6020`, 32 GB unified memory). x86-64 becomes the secondary and **attested** platform, plus the development/CI target. | **2026-08-02** |
| 7 | **INV-BOOT/AS signed off** — remote attestation and sealing are permanently unavailable on the primary platform. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 8 | **Asahi Linux is reference-only.** Published documentation in, clean-room implementation out. No code copied, regardless of license (m1n1 is MIT, the Asahi kernel is GPL-2.0; the no-vendoring rule forbids both). Running m1n1 as a lab instrument on a development machine is permitted — that is using a tool, not incorporating code. **Enforced as a two-role procedure for all AS-4 and AS-5 work:** a *spec author* role may read reverse-engineered source and emits nothing but fact tables — register offsets, struct field layouts, sequence diagrams, state machines — into `docs/platform-specs/`, each file carrying a provenance header naming its sources **and a firmware-version field** (the AGX firmware ABI is versioned per macOS release); an *implementer* role is denied that source and works only from the spec file. Stated limit: the wall protects **code provenance, not knowledge provenance**. | **2026-08-02** |
| 9 | **Performance is a craft standard** (~~"product requirement"~~ — framing restated by #11), ranked below the invariants and above everything else. "We did not optimize because security" is no longer a sufficient answer; slowness needs a named invariant as its justification. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 10 | **GPU and CPU at maximum.** Apple's **AGX GPU is in scope** — it moves from non-goal to goal. Supersedes decision #2's "GPU deferred" as a *scope* statement; CPU inference is still first as an *ordering* statement. Carries the **TCB-AS/GPU exception** — ~~unsigned~~ **conditionally signed 2026-08-02**, see #14 and AS-5-T0: AGX requires running Apple's opaque, DMA-capable GPU firmware. | **2026-08-02** |
| 11 | **Craft-first.** BraiNIX is a craft project whose artifact is held to product-grade rigor because that is the only honest way to measure the craft. It is **not a market claim**. Product framing — "MVP", "the product ships", "product requirement" — is drift and is restated in craft terms wherever it appears below. Product-grade *standards* stay; product *claims* go. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 12 | **Done = AS-5.** The project's terminal completion criterion is **AS-5: GPU and CPU at maximum, serving inference on the Mac mini M2 Pro.** Not AS-4c, not P3-T9 — those are gates on the way, not the finish line. | **2026-08-02** |
| 13 | **P3-T9 is a mandatory gate.** The x86-64/QEMU end-to-end serving milestone must be complete before AS-4 or AS-5 may be re-rated or started. AS-0 through AS-3 remain permitted before the gate. This honors the P6-T1 memo's own AS-4 precondition: "Re-evaluate with a fresh memo only after AS-3 ships and the x86-64 serving MVP is done." | **2026-08-02** |
| 14 | **GPU tenant-mapping policy.** Model weights are mapped into the GPU's DART window **read-only and permanently** (they are not client data). KV cache is mapped **strictly per session** — mapped on session entry, unmapped and flushed on exit, and **never two tenants resident simultaneously**. The GPU time-slices between clients; cross-tenant batching is forbidden. Consequence: **INV-SERVE is preserved intact and needs no exception.** Cost, stated plainly: the GPU's payoff shrinks from "a large win for serving multiple clients concurrently" to **prefill acceleration plus time-sliced multi-client serving**. | **2026-08-02** |
| 15 | **Proof gate is tiered by TCB proximity**, replacing the uniform per-component gate of #4. **Full tier** (all six artifacts) covers the TCB, every hostile-input parser, and all crypto; **Reduced tier** (tests + security audit report only — no Kani, no Prusti) covers capability-bounded servers whose compromise the capability model contains. Justification is the project's own principle: IOMMU confinement, not driver correctness, is the control. The authoritative per-component assignment is the table in [`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16, audited at each phase gate. | **2026-08-02** |
| 16 | **PSK transport; no asymmetric crypto in the serving transport.** BSP uses pre-shared per-client keys, HKDF-SHA256 session-key derivation, and ChaCha20-Poly1305 records. In-tree primitive set: **SHA-256, HKDF, ChaCha20, Poly1305**, which deletes `sha2` and `chacha20` — *specified, not shipped: both are still vendored and the in-tree reimplementation has not landed (X-T4).* **Permanent named exception:** the Ed25519 *verification* stack (`ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle`) stays vendored, **verify-only**, because INV-BOOT's release signature needs curve25519 field arithmetic and hand-rolling it would *lower* assurance. Cost: **wire compatibility with stock OpenSSH clients is forfeited.** | **2026-08-02** |
| 17 | **Administration is a BSP admin channel, not a shell.** A second session *type* on the same authenticated PSK transport, gated by a distinct `CapAdmin` (`Admin=14`), exposing a frozen, enumerated set of **exactly six verbs**: enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. There is no `rotate` verb — rotation is enroll-then-revoke. A general-purpose shell is ambient authority under another name and is forbidden. The **serial console is the break-glass path**, and the break-glass admin PSK authenticates over serial and **nowhere else — never over the network**. | **2026-08-02** |
| 18 | **Keys are runtime-enrolled and ratcheted; no secret ever enters a build artifact.** Enrollment through `boot/credential_store.rs` — virtio-blk on x86-64, ANS2 NVMe on Apple Silicon from AS-4a. Forward secrecy comes from a symmetric HKDF ratchet that deletes the chain key it advanced past; **until the ratchet lands there is no forward secrecy.** **At rest, protection tracks the platform's attestation capability:** the credential store is **specified to be TPM-sealed on x86-64**, where INV-BOOT holds in full, and is **plaintext at rest on Apple Silicon**, recorded as a clause of the existing INV-BOOT/AS exception. Sealing is **specified and unimplemented** — see P2-T13. | **2026-08-02** |
| 19 | **Wave 2 is this documentation gate, then P1-T2 ∥ BSP v2 spec.** Nothing else is Wave 2. **AS-0 slides to Wave 3** — it is the only former Wave 2 item not on the critical path to P3-T9, and the P6-T1 memo sets the resourcing rule itself: Apple Silicon tasks "are preemptible by any x86-64 MVP task, hold no reserved capacity, and their slippage is never a release consideration." AS-0 is therefore **unreserved, not blocked**: it may run whenever Wave 2 does not need the capacity, and Wave 2 slippage takes that capacity first. Distinct from #13, which gates AS-4/AS-5 and explicitly *permits* AS-0 through AS-3. | **2026-08-02** |

### What decision #6 costs, stated plainly

There is **no remote attestation** on the primary platform. A client cannot cryptographically
verify what it is talking to; an early kernel compromise is undetectable from outside. Reaching a serving
deployment additionally requires in-tree RTKit, ANS2 NVMe, PCIe, and Ethernet drivers, each reimplemented
clean-room from reverse-engineered documentation — the largest single body of work in this plan, and the
item most likely to consume the schedule. Every Apple Silicon fact below is revocable by an Apple firmware
update, with no upstream remedy. These are accepted costs, not open questions.

---

## Status at a glance

**Wave 1 — COMPLETE** (all five deliverables merged):

| Task | Deliverable | Commit |
|---|---|---|
| P1-T1 | HAL trait design — [`architecture/HAL.md`](architecture/HAL.md) | `670e072` |
| P2-T1 | BSP v1 serving protocol spec — [`architecture/BSP-v1-serving-protocol.md`](architecture/BSP-v1-serving-protocol.md) — historical; **superseded by BSP v2** (decision #16), so P2-T1 is re-opened in Wave 2 | `670e072` |
| X-T1 | Proof-coverage tracker — `tools/proof-coverage/` | `670e072` |
| P2-T9 | swtpm measured boot + runtime TPM-presence gating (x86-64) | `c01d0ab` |
| P6-T1 | Apple Silicon research memo — [`archive/specs/2026-07-08-apple-silicon-baremetal-research.md`](archive/specs/2026-07-08-apple-silicon-baremetal-research.md) | `670e072` |

**Wave 2 — IN PROGRESS.** Wave 2 is **this documentation gate first** — reconciling NORTH_STAR,
THREAT_MODEL, SECURITY_INVARIANTS, BSP, and this file against the 2026-08-02 decisions — and **then two
parallel tracks that share no code: P1-T2 ∥ P2-T1 (BSP v2 spec)**. Nothing else is Wave 2.

**Wave 3 — AS-0** (Apple Device Tree parser). AS-0 slid out of Wave 2 because it is the only former
Wave 2 item **not on the critical path to P3-T9** (decision #19), and because the P6-T1 memo sets the
resourcing rule itself: Apple Silicon tasks "are preemptible by any x86-64 MVP task, hold no reserved
capacity, and their slippage is never a release consideration."

**Terminal criterion (decision #12): the project is done at AS-5** — GPU and CPU at maximum, serving
inference on the Mac mini M2 Pro. AS-4c and P3-T9 are gates on the way, not the finish line.

**Substrate that works today:** boots under QEMU x86-64 via GRUB2 ISO to `[OK] BraiNIX: boot complete`;
ring-3 userspace shell under KPTI; W^X-correct ELF loader with guard-protected stacks; capability model;
synchronous IPC; decomposed network stack; fixed-pool in-kernel store; inbound SSH server; outbound SSH
client (host-tested only, Stage A).

---

## Architecture target

| Subsystem | Role | Location |
|---|---|---|
| **H — Multi-arch HAL** | Trait layer over arch + hardware-security primitives. Compile-time backends, no dyn dispatch. **aarch64/Apple is the primary backend; x86-64 is the reference backend the traits are first proven against.** | `src/kernel/src/hal/` (new); `src/kernel/src/arch/{x86_64,aarch64}/` |
| **AS — Apple Silicon platform** | ADT parser, boot stub, AIC, DART, RTKit, ANS2 NVMe, PCIe, Ethernet | `src/kernel/src/arch/aarch64/apple/`, `src/servers/devd-*/` |
| **N — Secure serving path** | Inbound listener, authenticated transport, fail-closed request parser, per-client sessions | `src/servers/servd/` + `src/brainix-transport-crypto/`; **replaces** `boot/ssh_bridge.rs` |
| **I — In-tree inference engine** | `no_std` transformer: tensor kernels, BPE tokenizer, KV cache in fixed regions; confined tenant | `src/servers/inferd/` + `memory/` reserved-region extensions |
| **G — GPU** | **In scope (decision #10).** Capability-bounded `gpud` holding only `CapGpu`; AGX DMA confined by DART; GPU firmware and its completion records treated as hostile input. | `src/servers/gpud/`, `hal/iommu.rs` |
| **A — store** | Fixed-pool store → session table + serving/audit log | `src/kernel/src/db/` (stages 1–4 done) |
| **B — auditor** | Observes the serving stack; manifest unchanged (observe-only) | `src/servers/auditd/` |
| **Caps** | Extend `CapabilityType` (ends at `Frame=10`) with `Serve=11, Model=12, Gpu=13, Admin=14`. `Admin=14` gates the BSP admin session type (decision #17) — six frozen verbs, never a shell. | `capability/capability_type.rs`; proofs in `src/capability-verify/` |

HAL trait surface: `hal/{mmu,interrupts,timer,context,syscall,entropy,mitigations,iommu,measure,fpu,bus}.rs`
— one trait per concern, per-backend implementations (APIC / GICv3 / **AIC**; VT-d / SMMUv3 / **DART**;
RDRAND / RNDR; IBT-ENDBR64 / PAC-BTI; TPM / software-fallback / **none**). `hardware_security/` modules
become HAL *consumers*, not owners of x86 intrinsics.

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
| **1** | HAL extraction — multi-arch becomes possible; x86-64 behavior byte-identical | none | **NEXT** (Wave 2) |
| **AS-0** | Apple Device Tree parser (host-side, fuzz + Kani) | none | **Wave 3** (decision #19) |
| **2** | Secure inbound serving path + capability extensions | P1 | arch-neutral; P2-T1 is Wave 2 |
| **3** | In-tree CPU inference — architecture-neutral serving engine | P2, P1-fpu | arch-neutral |
| **4** | aarch64 core + QEMU `virt` bring-up harness | P1 | gates AS-1 |
| **AS-1..3** | Apple boot stub → AIC → DART on real hardware | P4, AS-0 | **primary platform** |
| **AS-4** | RTKit + ANS2 NVMe + PCIe + Ethernet → serving on the mini | AS-3, **P3-T9 (hard gate, #13)** | **long pole** |
| **AS-5** | **AGX GPU** — RTKit GPU endpoint, firmware load, command submission, GPU tensor kernels | AS-4, AS-3 DART proven, **P3-T9 (hard gate, #13)** | **largest single effort; terminal criterion (#12)** |
| **5** | GPU on x86-64 (INV-GPU) — discrete accelerator | P3, P1-iommu | deferred |
| **X** | Proof program, CI, crate burn-down | woven throughout | continuous |

### Critical path to "the Mac mini serves inference"

```
P1 (HAL extraction) ──┬─▶ P4 (aarch64 core, QEMU virt) ──▶ AS-1 ──▶ AS-2 ──▶ AS-3 ──┐
                      │                                                             │
AS-0 (ADT parser) ────┘  (Wave 3)                                                   ├─▶ AS-4 ──▶ AS-5
                                                                                    │       = DONE (#12)
P2 (serving path) ──▶ P3 (inference engine) ──▶ ⟦ P3-T9 — HARD GATE ⟧ ──────────────┘
```

Two independent tracks converge. The **platform track** (P1 → P4 → AS-*) is serial and hardware-gated. The
**product track** (P2 → P3) is architecture-neutral, developed and proven on x86-64 under QEMU, and is not
blocked by any Apple work. Running both concurrently is the whole reason the HAL exists.

**P3-T9 is a hard gate, not a milestone (decision #13).** Neither AS-4 nor AS-5 may be started or re-rated
until the x86-64/QEMU end-to-end serving path is green. AS-0 through AS-3 remain permitted before it — the
gate constrains the driver chain and the GPU, not the boot/interrupt/IOMMU bring-up. This honors the P6-T1
memo's own precondition on its AS-4 row: "Re-evaluate with a fresh memo only after AS-3 ships and the
x86-64 serving MVP is done." Starting AS-4 without it would mean debugging an unproven serving stack and
an unproven driver chain simultaneously, on hardware, with no working console for either.

Model legend: **S** = Sonnet 5 (default builder) · **O** = Opus (crypto, audits, hardest proofs) ·
**H** = Haiku (docs, tests, boilerplate) · **F** = Fable (planning).

---

### Phase 1 — HAL extraction

Gates the primary platform. Nothing Apple-specific can begin until the seam exists; two agents refactoring
`arch/` concurrently is a guaranteed merge disaster, so this phase is single-owner for `arch/`.

- **P1-T1** ~~Design HAL trait set + contracts~~ — **DONE** (`670e072`).
- **P1-T2** Move `arch/*` → `arch/x86_64/`, implement HAL traits, zero behavior change. **S**. Deps: T1. Verify: `cargo test --lib`; x86 QEMU boot parity against pre-refactor logs.
- **P1-T3** Refactor `hardware_security/*` to consume HAL traits (x86 backend). **S**. Deps: T1. Verify: hardware_security tests green; boot-log parity.
- **P1-T4** Multi-target build plumbing (per-target `.cargo/config.toml`, add `aarch64-unknown-none`, cfg gates, in-tree build scripts). **S**. Deps: T1. Verify: x86 release build; `cargo check --target aarch64-unknown-none` on the HAL skeleton.
- **P1-T5** Boot-flow seam: `boot/phases.rs` + `boot/hardware_security_init.rs` call HAL only. **S**. Deps: T2, T3. Verify: grep-gate (no `arch::x86_64` outside `arch/` and `hal/`); boot.
- **P1-T6** Kani: HAL MMU contract preserves W^X and page-table invariants (new `src/hal-verify/`). **O**. Deps: T2. Verify: Kani green.
- **P1-T7** ~~`docs/architecture/HAL.md`~~ — **DONE** (`670e072`). Update for Apple-primary ordering.
- **P1-A** Security audit of the HAL seam. **O**. Gate.

### Phase AS-0 — Apple Device Tree parser *(Wave 3)*

No hardware, no HAL dependency. Rated **GO** by the research memo and "useful even if the stream stops
here." **Moved from Wave 2 to Wave 3 by decision #19**: it is the only former Wave 2 item not on the
critical path to P3-T9, and the memo's resourcing rule is that Apple Silicon tasks "are preemptible by any
x86-64 MVP task, hold no reserved capacity." It is not blocked — it is unreserved, and any Wave 2 slippage
takes its capacity first.

- **AS-0-T1** ADT binary-format specification, re-derived from published Asahi documentation. Field widths and flag bits are **not** assumed — anything only documented by source gets specified by one session and implemented by another. **O**. Verify: written spec.
- **AS-0-T2** `#![no_std]`, zero-allocation, fail-closed ADT parser. Every offset/length/count bounds-checked against its containing region; malformed input denies. **S**. Deps: T1. Verify: host tests.
- **AS-0-T3** Fuzz target + Kani harness (no-panic, bounds, no allocation driven by ADT-supplied sizes). **S** harness / **O** hardening. Deps: T2. Verify: fuzz soak + Kani green — **INV-MEM**, INV-SERVE discipline.
- **AS-0-T4** boot-args parser + ADT/boot-args memory-range cross-check (disagreement fails closed). **S**. Deps: T2. Verify: host tests with adversarial fixtures.

### Phase 2 — Secure inbound serving path *(architecture-neutral)*

- **P2-T1** **BSP v2 protocol spec — RE-OPENED, and it is Wave 2.** ~~BSP v1 protocol spec — DONE (`670e072`)~~ — v1's signature-over-ephemeral-key-agreement handshake is superseded by decision #16's pre-shared-key transport. Deliverable: [`architecture/BSP-v2-serving-protocol.md`](architecture/BSP-v2-serving-protocol.md), covering the PSK handshake, the HKDF-SHA256 key schedule, the retained record layer, the ratchet, and **both session types** (client and admin). **O**. Verify: spec precise enough to drive Kani harnesses and fuzz targets against every parser and every state transition.
- **P2-T2** Factor `ssh/` primitives into `src/brainix-transport-crypto/` (`no_std`) + server-side handshake. **Shrunk by decision #16**: no curve arithmetic, no key agreement, no signature verification on this path — the deliverable is the **PSK handshake FSM, HKDF-SHA256 derivation, and the ChaCha20-Poly1305 record layer**, over the in-tree primitive set (SHA-256, HKDF, ChaCha20, Poly1305). **O**. Deps: T1. Verify: Kani (no-panic, length-checked), fuzz handshake FSM, test vectors.
- **P2-T3** Fail-closed BSP request parser (`servd/src/parser.rs`, `no_std`, zero-alloc, bounded). **S**. Deps: T1 — it parses the wire format T1 now redefines. Verify: `fuzz_servd_request_parser` + Kani + audit — **INV-SERVE**.
- **P2-T4** `servd`: accept via `transportd`, session manager, per-client frozen capability set. **Both session types** (decision #17): a session is a client session holding `CapServe` or an admin session holding `CapAdmin`, decided at accept and frozen there; nothing promotes one into the other. **S**. Deps: T1, T2, T3, T5. Verify: 2-concurrent-session integration; cross-naming denied; a client session cannot reach an admin verb.
- **P2-T5** Capability extensions `Serve`/`Model`/`Gpu`/**`Admin`** + grant/derive/revoke rules; extend `src/capability-verify/`. `Admin=14` follows `Serve=11, Model=12, Gpu=13` and is a distinct grant, never derivable from `CapServe` (decision #17). **O** — INV-AUTH, Full tier. Verify: Kani green, including no derivation path from `CapServe` to `CapAdmin`.
- **P2-T6** Delete `boot/ssh_bridge.rs` `static mut` session globals; route inbound via servd + capability IPC only. **S**. Deps: T4. Verify: grep-gate (no `static mut` session state); connect e2e.
- **P2-T7** Reframe `db/` for the session table + serving log (fixed pools) + cross-session non-interference Kani. **S** build / **O** proof. Deps: T5. Verify: Kani — no session row readable via another session's capability.
- **P2-T8** `auditd` extension: subscribe to serving events; manifest unchanged. **Admin-session events are in scope** (decision #17): connection accept, selector match or no-match, authentication success or failure, capability grant, **every admin verb**, every denial, and teardown, carrying the credential handle and session id and **never** key material, prompt bytes, or token bytes. Observing an admin verb grants no authority to observe it. **S**. Deps: T4, T14. Verify: manifest diff = zero new capabilities (INV-AUDIT); every verb and every rejection path in T14 produces exactly one attributable event; CTF corpus ≥ 95% TP.
- **P2-T9** ~~vTPM closure~~ — **DONE** (`c01d0ab`). **x86-64 only**; has no analogue on the primary platform (INV-BOOT/AS).
- **P2-T10** Fuzz corpus + targets (handshake, parser, session state) into CI. **H** scaffold / **S** corpus. Deps: T2, T3.
- **P2-T11** Host-side test client `tools/bsp-client/` (std, zero crates), **driving both session types**. Grows the admin verb set of decision #17 — **exactly six verbs**: enroll-key, revoke-key, load-weights, read-audit-log, restart-server, reboot. The set is frozen and compile-time-enumerated; there is **no `rotate` verb** (rotation is enroll-then-revoke), no `set-config`, no file or exec verb, and no verb that adds, removes, or widens a capability. The client exercises every verb and every rejection path against the T14 dispatcher. **H**. Deps: T1, T4, T14.
- **P2-T12** Runtime key enrollment + HKDF ratchet (decision #18). Extend `src/kernel/src/boot/credential_store.rs` to enroll and revoke client and admin pre-shared keys at runtime, persisting through `src/kernel/src/arch/virtio_blk.rs` on x86-64 and to ANS2 NVMe on Apple Silicon from AS-4a; **no secret is ever compiled in** — `src/kernel/src/ssh/client_identity.rs:21` (`const CLIENT_KEY_SEED`) is an acknowledged dev seed and is no longer the model. Forward secrecy comes from a symmetric HKDF chain: session key *n* is derived from chain key *n*, the chain advances, and chain key *n* is zeroized — derivation and advance are one operation with no path that does either alone. **The break-glass admin PSK is provisioned over the serial console and authenticates over serial only; the network listener refuses it outright** (decision #17), so a compromised admin session can neither revoke nor replace it. **O**. Deps: T1, T4, T5. Verify: recorded-traffic test — material captured after an advance must not decrypt records sealed before it; enrollment/revocation are attributable audit events; grep-gate on compile-time key material.
- **P2-T13** Credential store at rest (decision #18) — **split by platform, and stated as unbuilt today**. *x86-64:* seal the credential store to the TPM against the measured boot state established by P2-T9, so a stolen disk does not yield the keys. This is **specified and unimplemented**; the store persists to virtio-blk and seals nothing. *Apple Silicon (primary):* the store is **plaintext at rest, permanently** — a clause of the existing INV-BOOT/AS exception. Sealing binds a secret to a measured boot state, and the platform has neither the measurement nor the hardware to bind against; there is no version of this task that closes the gap there. **O**. Deps: T12, P2-T9. Verify (x86-64 only): sealed blob does not unseal under a divergent PCR set; the release notes state the primary platform's plaintext-at-rest exposure plainly. **P2-A is satisfied on the primary platform by the INV-BOOT/AS clause, not by the work** — there is no Apple Silicon deliverable here to audit, and the gate passes on the exception being correctly recorded and restated in the release notes.
- **P2-T14** Server-side admin verb dispatch in `servd` — the other half of decision #17, and the thing P2-T11 drives. A compile-time enumeration of **exactly six** handlers, reachable only from a session holding `CapAdmin`, with no command interpreter, no path or filename anywhere in the surface, and no handler that adds, removes, or widens a capability. `enroll-key` / `revoke-key` delegate to the T12 credential store and both refuse the break-glass handle unconditionally and non-configurably. `load-weights` names a **measured digest and never a path or a byte stream** — the blob does not travel over BSP — and activates the blob the P3-T3 loader measured; until P3-T3 lands it fails closed rather than accepting anything. `read-audit-log` is a bounded, read-only cursor over the T7 store; reading grants no authority. `restart-server` takes an **enumerated server identity**, never a name, and relaunches with the target's existing frozen manifest, minting nothing. `reboot` tears down the admin session before proceeding. **O** — this is the network-reachable administrative surface. Deps: T4, T5, T7, T12. Verify: fuzz + Kani on the verb decoder (**Full tier — a hostile-input parser**); grep-gate that the handler table has exactly six entries and no `rotate`; a `CapServe` session reaches none of them; every verb and denial emits an attributable event (T8).
- **P2-A** Security audit. **O**. Gate.

### Phase 3 — In-tree CPU inference *(architecture-neutral)*

- **P3-T0** **Userspace FP/SIMD enablement**: in-tree target spec for `inferd` + FP state save/restore in the context switch via `hal/fpu.rs`. Kernel stays soft-float. **S** impl / **O** review (context-switch ABI is TCB). Deps: P1. Verify: FP-dirty context-switch test; Kani on save-area bounds. *Per-arch: XSAVE/XRSTOR on x86-64; the aarch64 FP/NEON state path on the primary platform.*
- **P3-T1** Weight format spec "BXW1" (header, tensor table, per-tensor SHA-256, hard size bound; Q8_0 + f32). **S** spec / **O** review. Verify: spec; INV-MODEL mapping.
- **P3-T2** Reserved regions: extend `memory/virtual_address_layout.rs` + `physical_allocator.rs` with a build-time `WEIGHTS_REGION` (read-only after load, W^X) + per-session `KV_REGION` partitions; no allocator. **S**. Deps: P1. Verify: Kani (region non-overlap; weights-never-writable-post-seal) — **INV-MEM**. *Must be written page-size-agnostic: 16 KiB on the primary platform, 4 KiB on x86-64.*
- **P3-T3** Fail-closed BXW1 loader (streaming digest, measured, denies malformed/oversized). **S**. Deps: T1, T2. Verify: fuzz BXW1 header/tensor-table + Kani.
- **P3-T4** Tensor kernels (`no_std`, fixed scratch): matmul (f32 + Q8 dequant), RMSNorm, softmax, RoPE, SiLU/SwiGLU. **S**. Deps: T0. Verify: property tests vs reference; no-alloc grep-gate.
- **P3-T5** In-tree BPE tokenizer; the vocab blob is hostile input → fail-closed. **S**. Deps: T1. Verify: fuzz + Kani vocab parser; round-trip tests.
- **P3-T6** Transformer forward pass + KV cache in per-session slices; decode loop + sampling (CSPRNG from `hardware_security/csprng.rs`). **S**. Deps: T4, T5, T2. Verify: logits parity vs a host f32 reference on a tiny model.
- **P3-T7** `inferd`: confined-tenant manifest (capabilities = {Model, serving endpoint, own KV slice}; no Spawn, no net, no cross-session); wired to servd over synchronous IPC. **S**. Deps: T6, P2-T4. Verify: manifest audit — the model *cannot name* forbidden capabilities — **INV-MODEL**.
- **P3-T8** Confinement suite: adversarial-prompt harness (injection corpus) — zero escalation under any input. **O**. Deps: T7. Verify: suite green = CI regression bar.
- **P3-T9** e2e: `bsp-client` → QEMU x86-64 → auth → prompt → streamed tokens; 2 isolated clients. **H** scaffold. Deps: T7, P2-A. Verify: **datapath exit criterion — and the hard gate of decision #13.** Until this is green, AS-4 and AS-5 may be neither started nor re-rated.
- **P3-A** Security audit. **O**. Gate.

### Phase 4 — aarch64 core + QEMU `virt` harness

**Descoped from the original "aarch64 server bring-up."** With Apple as the primary target, GICv3, SMMUv3,
and the Graviton/Ampere real-metal checklist are no longer product goals. What survives is the part Apple
shares — the aarch64 *core* — plus the QEMU `virt` machine as a bring-up harness. That harness matters: it
is the only way to debug aarch64 core code with a working console before facing hardware where nothing
works until the UART does.

- **P4-T1** Target plumbing `aarch64-unknown-none` (linker script, QEMU `virt` runner). **S**. Deps: P1.
- **P4-T2** Boot path: entry assembly, EL2→EL1, MMU init, PL011 UART. **S**. Deps: T1. Verify: QEMU virt boot banner. *Note: QEMU virt uses 4 KiB pages; the primary platform uses **16 KiB**. The MMU code is written page-size-parametric from the start and tested both ways — a 4 KiB assumption that reaches production is an INV-MEM defect.*
- **P4-T3** Exception vectors + a `hal/interrupts` backend (GICv3, harness-only). **S**. Deps: T2. Verify: timer IRQ; IPC tests.
- **P4-T4** Generic timer + `hal/context` + SVC syscall entry backends. **S**. Deps: T2. Verify: context-switch + syscall tests. *Shared with Apple — this is core aarch64, not platform.*
- **P4-T5** aarch64 `hardware_security` backends: RNDR, PAC/BTI, CSV2/SSBS. **S** build / **O** audit. Deps: T2. Verify: boot-time hardware_security report.
- **P4-T7** Re-instantiate the W^X / page-table Kani harnesses for the aarch64 MMU in `src/hal-verify/`. **O**. Deps: T2. Verify: per-arch Kani green.
- **P4-A** Security audit of the aarch64 core. **O**. Gate.

*(P4-T6 virtio-mmio and P4-T8 real-metal server checklist are dropped — superseded by the AS-4 driver
chain and the descoping above.)*

### Phase AS — Apple Silicon platform *(PRIMARY)*

Target: Mac mini M2 Pro, `Mac14,12`, SoC `T6020`. Verdicts carried forward from the P6-T1 memo, re-rated under
decision #6.

**Development rig required before AS-1:** the mini in Permissive Security (`bputil` from One True
Recovery — needs local admin credentials and physical presence, once per machine), a debug UART cable, and
m1n1 running as a lab instrument on the machine for register exploration and payload loading. Payload
delivery is `kmutil configure-boot -c <payload> -v <volume>`, which wraps the payload as an Image4 object
under the machine's Secure-Enclave-held local policy — an Apple-supported, documented flow.

- **AS-1** Boot stub: Image4/kmutil delivery, entry state, own MMU and exception vectors established immediately (inherit nothing), boot-args + ADT consumption, s5l UART console, watchdog reset. **S** impl / **O** review. Deps: AS-0, P4-T2/T4. **Exit criterion: BraiNIX prints its invariant banner over serial on the M2 Pro mini.**
- **AS-2** AIC backend + FIQ timer path, feeding `hal/interrupts`. **S** impl / **O** review. Deps: AS-1, P1-T2 stable. Notes: AIC is not a GIC — a single packed event word replaces the GIC ack/EOI pair, per-CPU timers arrive as **FIQ** outside the controller entirely, and IPIs go through implementation-defined system registers. Select the AIC revision from ADT compatible strings at runtime; **fail closed on an unknown string.** Verify: timer IRQ + IPI on hardware.
- **AS-3** DART (IOMMU) backend feeding `hal/iommu`. **S** impl / **O** proof. Deps: AS-2. Notes: dozens of per-device instances discovered from the ADT, not one translation unit; PTE formats differ across SoC generations. **Every discovered instance defaults to deny-all from the first commit**; unknown variants fail closed; locked-DART semantics represented honestly in the trait rather than papered over. Verify: Kani (driver cannot widen its own window); DMA fault injection.
**AS-4 is gated on P3-T9 (decision #13).** No task in the AS-4 chain starts, and the memo's NO-GO rating is
not re-opened, until the x86-64/QEMU serving path is proven end to end.

- **AS-4a** Storage: RTKit co-processor mailbox protocol + ANS2 NVMe (non-standard, tag-based NVMMU quirks). **S** impl / **O** audit. Deps: AS-3. Verify: weights read from disk on hardware. *Interim unblock: payload-embedded weights let AS-4b and the serving path proceed before this lands.*
- **AS-4b** Network: PCIe bring-up + the mini's built-in Ethernet NIC driver, as capability-bounded `devd-*` servers — never in the kernel. **S** impl / **O** audit. Deps: AS-3. Verify: NIC TX/RX on hardware.
- **AS-4c** e2e: remote `bsp-client` → Mac mini M2 → auth → prompt → streamed tokens; 2 isolated clients. Deps: AS-4a, AS-4b, P3-A, **P3-T9**. Verify: **CPU-serving capability demonstrated on the primary platform.** This is a demonstration, not the finish line — the terminal criterion is AS-5 (decision #12).
- **AS-A** Whole-platform security audit, including the TCB-AS enumeration and the INV-BOOT/AS degradation restated in the release notes. **O**. Gate.

**Honest rating of AS-4:** the memo rated this chain NO-GO and named it "where the stream can silently
consume the project." Decision #6 overrides that rating; the underlying cost estimate is unchanged. AS-4a
and AS-4b are each plausibly larger than AS-0 through AS-3 combined.

### Phase AS-5 — AGX GPU *(in scope — decision #10)*

**Goal: GPU and CPU at maximum.** The largest single body of work in this plan — larger than the AS-4
driver chain — and the one whose cost is least well understood, because AGX is the biggest
reverse-engineering effort on the platform and none of it may be vendored.

**Hard prerequisite: DART confinement must be proven before any firmware is loaded.** INV-GPU is the
control that makes running Apple's opaque firmware survivable; enforcing it afterward is not an option.

**AS-5 is also gated on P3-T9 (decision #13)** and on AS-4, for the same reason AS-4 is.

- **AS-5-T0** DART/GPU confinement proof. **O**. Deps: AS-3. **Gate for everything below**, and the acceptance criteria of the conditionally signed TCB-AS/GPU exception (decision #10, NORTH_STAR.md). All five must be green **before GPU firmware is ever loaded**; each is pass/fail, and none is waivable:
  1. Every GPU-fronting DART instance defaults to **deny-all**.
  2. A **Kani proof on the DART backend / HAL IOMMU trait** that its API surface admits no widening operation — proving that no consumer, `gpud` included, can widen its own DMA window (`INV-DEV-006`). The proof belongs to the confinement (Full tier), **not** to the driver; stating it as a proof about `gpud` would contradict the tiering rule of decision #15.
  3. GPU completion records are **fuzzed and Kani-checked as hostile input** (`INV-PARSE-001`).
  4. The **tenant-mapping policy of decision #14** is enforced: weights read-only and permanent, KV cache per session, **never two tenants resident simultaneously**.
  5. **No iBoot-locked DART on the GPU path** — or, if one exists, its locked semantics are honestly represented in the HAL trait rather than papered over.

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

### Phase 5 — discrete GPU on x86-64 *(deferred)*

P5-T1..T4 unchanged from the original plan; not scheduled. Superseded in priority by AS-5.

### Phase X — Continuous

- **X-T1** ~~Proof-coverage tracker~~ — **DONE** (`670e072`), `tools/proof-coverage/`.
- **X-T2** CI gates per arch (`cargo test --lib`, `fmt --check`, bare-metal release build, Kani, fuzz smoke, audit checklist; clippy non-gating). **S**. Deps: P1-T4.
- **X-T3** Reproducible build + Ed25519 release signing + PCR publication. **S**. *Split by platform: predicted-vs-attested PCR matching is x86-64 only; on Apple Silicon this reduces to reproducible build + release signature (INV-BOOT/AS).* *Signing is an out-of-tree release step: **in tree, Ed25519 is verify-only** (decision #16) — once the outbound SSH client is removed, nothing in tree holds a private key or signs anything.*
- **X-T4** Vendored-crate burn-down (bitflags, log, multiboot2 first; `sha2` and `chacha20` last, only after the in-tree SHA-256/HKDF/ChaCha20/Poly1305 implementations pass vectors and audit). **Rewritten by decision #16, and the burn-down shrinks substantially as a result:** the Ed25519 verification stack — `ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle` — is **removed from this list entirely**. It is a permanent named exception in NORTH_STAR.md, vendored **verify-only**, and X-T4 no longer targets it. The four hardest crates in the burn-down were exactly those, so what remains of the crypto item is two symmetric primitives with published test vectors — a materially easier task than the one this row previously described. Honest note in the other direction: the remaining `Cargo.lock` floor is now permanent, not a number that reaches zero. **S** impl / **O** crypto. Verify: `Cargo.lock` crate count strictly decreases, measured against a floor that includes the four exception crates.

---

## Per-component "done" gate — tiered

~~Every component ships **all** of the six artifacts below.~~ **The uniform gate was replaced on
2026-08-02 by a gate tiered on TCB proximity (decision #15).** Proof effort moves to the confinement,
following the project's own principle: IOMMU confinement, not driver correctness, is the control.

The six artifacts are:

1. **Invariant mapping** — which INV-* it touches and how.
2. **Fuzz artifact** for every hostile-input parser (libFuzzer target + checked-in corpus + soak before phase exit): BSP parser, handshake FSM, BXW1 loader, tokenizer vocab, **ADT parser**, **boot-args parser**, **GPU completion records**, plus the existing targets kept green.
3. **Kani harness** for every parser *and* every security-relevant path (no-panic + bounds + the stated property: unforgeability, no-widening, non-interference, W^X preservation, region non-overlap, DMA-window non-widening) in `src/{capability,bootloader,hal,serve,infer}-verify/`.
4. **Prusti contracts** where functional (capability derive/revoke, `memory/pool_allocator.rs` bounds), toward the 80% coverage bar.
5. **Security audit report** — zero known vulnerabilities, every `unsafe` block justified, constant-time review for key material.
6. **No-regression bars** — auditd ≥ 95% TP, crate count non-increasing, no `static mut` outside the audited allowlist, grep-gates hold.

**Which of them a component owes is decided by
[`security/SECURITY_INVARIANTS.md`](security/SECURITY_INVARIANTS.md) §16 and nowhere else.** That section
defines the tiers, states their corollaries, and assigns every component; **this roadmap deliberately
restates none of it**, because two documents stating the same rule in different words is how this gate's
conflict arose. Tier is read off that table at design time — it is not a per-component judgment made at
implementation time — and a component absent from it is **unassessed**, not Reduced. Read §16 before
planning any component's proof work.

**Per-release whole-system audit:** end-to-end over the TCB (kernel, boot stub, capability, IPC, HAL
backends in use), the full serving datapath, all manifests, and the reproducible build. On x86-64 this
includes predicted-vs-attested PCR matching; on Apple Silicon the release notes must state the INV-BOOT/AS
degradation plainly. Release notes state: maximal assurance under the stated attacker model, not a proof of
absolute security.

---

## Verification, per phase

- **P1:** x86 QEMU boot byte-parity vs pre-refactor logs; full `cargo test --lib`; aarch64 HAL-skeleton `cargo check`; HAL Kani harnesses; P1-A.
- **AS-0:** ADT parser fuzz soak + Kani green, entirely on the host, no hardware.
- **P2:** handshake vectors; parser fuzz soak; 2-client isolation test; cross-session Kani; no derivation path from `CapServe` to `CapAdmin`; ratchet recorded-traffic test; swtpm predicted == attested (x86-64); P2-A.
- **P3:** logits parity vs host reference; confinement suite (zero escalations under injection); e2e `bsp-client` → QEMU x86-64 → streamed tokens, 2 isolated clients; P3-A.
- **P4:** QEMU `virt` aarch64 boot banner; context-switch and syscall tests; per-arch Kani; P4-A.
- **AS-1..3:** serial-verified boot banner on the M2 Pro mini; timer IRQ and IPI on hardware; DART deny-all default proven and DMA faults injected; AS-A.
- **AS-4:** weights loaded from NVMe; NIC TX/RX; e2e remote client → mini → streamed tokens.

---

## Honest risks

1. **No remote attestation on the primary platform (INV-BOOT/AS).** Unmitigable and permanent. It devalues every other control by making the boot state unprovable to a remote party. Deployments that cannot accept it must run x86-64.
2. **The AS-4 driver chain.** RTKit + ANS2 NVMe + PCIe + Ethernet, clean-room, no vendoring. The single largest schedule risk and the most likely place for this plan to stall.
3. **No contract below boot-args.** Boot-args layout, ADT format, AIC/DART registers, and CPU release sequences are reverse-engineered with zero compatibility promise. Every macOS firmware update is a potential breakage, forever, and we re-derive each fix ourselves. Mitigation: pin a known-good macOS stub on the deployment machine; treat firmware updates as re-qualification events.
4. **16 KiB pages.** Apple's base page size differs from x86-64's. Any 4 KiB assumption leaking into supposedly architecture-neutral memory code is an INV-MEM defect. Write page-size-parametric from P3-T2 and P4-T2 onward, and test both.
5. **Inbound is a real posture reversal.** `boot/ssh_bridge.rs` (`static mut` session on 2222, single-core cooperative) is exactly what the threat model forbids at scale — the weakest point in the tree until P2-T6. Fixed pools convert client-driven memory DoS into capacity exhaustion: fail-closed is correct for security but an *availability* loss, so per-client admission limits in servd are load-bearing.
6. **"No new crates" against building an inference engine plus two platform stacks.** Tokenizer, quantized matmul, RoPE, sampling, weight format, AIC, DART, RTKit, ANS2, PCIe, NIC — all hand-rolled. The soft-float kernel target (P3-T0) touches the TCB. The AGX GPU (AS-5) is the largest of these and the least well understood. **The crate burn-down itself is materially smaller than this risk once implied (decision #16):** the Ed25519 verification stack is a permanent named exception rather than debt, so `sha2` and `chacha20` are all that remain of the crypto item — two symmetric primitives with published test vectors. The residual risk is the *drivers and the engine*, not the crates. The honest counterweight: `Cargo.lock` now has a permanent floor, and "zero external crates" is a target the project has formally decided not to reach.
7. **Audit capacity is the pipeline bottleneck.** Expect audit queues and multi-round fix loops on the hardest proofs (non-interference, DMA non-widening). Mitigation: draft Kani harnesses alongside code; batch audits per wave.
8. **Clippy is pre-existing red and non-gating** (200+ `arithmetic_side_effects` across the kernel), which hides new lint signal. Scheduled burn-down so it can eventually gate.
9. **Ratchet desynchronization is an availability risk (P2-T12).** The HKDF chain deletes the key it advanced past, so if the two ends disagree irreconcilably — a client store restored from an older state, a server chain advanced past a client that lost its own advance, or a gap wider than the catch-up bound — the handshake fails closed and the client is locked out. That is the correct behavior and there **must never be a fallback to an un-ratcheted key**, because a fallback any failure can trigger is a downgrade any attacker can trigger. Nothing is disclosed; access is lost. Mitigation, and the reason it is not a remote self-destruct: recovery is re-enrollment over the admin channel, and if the credential authorizing that is itself desynchronized, recovery is over the **serial console and nowhere else** — which is why the serial path is compiled in unconditionally and gated on no network state. Stated plainly: a ratchet bug is a lockout requiring physical presence to repair.

## Critical files

- `src/kernel/src/arch/mod.rs` — the HAL extraction seam (today: cfg-gated x86 modules, no trait layer).
- `src/kernel/src/boot/ssh_bridge.rs` — inbound seed to replace with servd; `static mut` session state to delete.
- `src/kernel/src/capability/capability_type.rs` — `Serve`/`Model`/`Gpu`/`Admin` extension point (ends at `Frame=10`).
- `src/kernel/src/boot/credential_store.rs` — runtime key enrollment and the ratchet's persisted chain state (P2-T12); today it persists to virtio-blk and seals nothing (P2-T13).
- `src/kernel/src/memory/virtual_address_layout.rs` — fixed reserved WEIGHTS/KV regions (INV-MEM).
- `src/capability-verify/src/lib.rs` — the existing Kani proof pattern to extend across the new `*-verify` crates.

## Immediate next step

Close this documentation gate first. Then two Wave 2 tasks start in parallel, sharing no code:

1. **P1-T2** — move `arch/*` → `arch/x86_64/` behind the HAL traits, zero behavior change. Single-owner for `arch/`.
2. **P2-T1** — the BSP v2 protocol spec: PSK handshake, HKDF-SHA256 key schedule, retained record layer, ratchet, and both session types. Design only; no implementation.

**AS-0-T1/T2 is Wave 3** (decision #19) — unblocked but unreserved, and any Wave 2 slippage takes its
capacity first.

Before AS-1 can begin, the hardware rig must exist: the Mac mini M2 in Permissive Security, a debug UART
cable, and m1n1 installed as a lab instrument.
