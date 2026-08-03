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
| 2 | **CPU-inference MVP first**; ~~GPU/VRAM deferred~~ — **scope clause superseded by #10**; the CPU-first *ordering* still stands. | 2026-07-07 |
| 3 | **All security invariants kept as the moat** — capabilities, W^X, no kernel heap (weights/KV in fixed reserved regions), synchronous IPC, minimal TCB, **zero external crates** (inference engine and every driver written in-tree, `no_std`). | 2026-07-07 |
| 4 | **Formal-proof-maximal** posture — every hostile-input parser fuzzed *and* Kani-checked; proofs on all security-relevant paths; security audit on every component. Honest caveat: maximal assurance under a stated attacker model, **not** a proof of absolute security. | 2026-07-07 |
| 5 | ~~Apple Silicon deferred / out of scope.~~ **SUPERSEDED by #6.** | 2026-07-08 |
| 6 | **Apple Silicon is the PRIMARY platform.** Reference deployment: Mac mini M2 Pro (`Mac14,12`, SoC `T6020`, 32 GB unified memory). x86-64 becomes the secondary and **attested** platform, plus the development/CI target. | **2026-08-02** |
| 7 | **INV-BOOT/AS signed off** — remote attestation and sealing are permanently unavailable on the primary platform. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 8 | **Asahi Linux is reference-only.** Published documentation in, clean-room implementation out. No code copied, regardless of license (m1n1 is MIT, the Asahi kernel is GPL-2.0; the no-vendoring rule forbids both). Running m1n1 as a lab instrument on a development machine is permitted — that is using a tool, not incorporating code. | **2026-08-02** |
| 9 | **Performance is a product requirement**, ranked below the invariants and above everything else. "We did not optimize because security" is no longer a sufficient answer; slowness needs a named invariant as its justification. Recorded in NORTH_STAR.md. | **2026-08-02** |
| 10 | **GPU and CPU at maximum.** Apple's **AGX GPU is in scope** — it moves from non-goal to goal. Supersedes decision #2's "GPU deferred" as a *scope* statement; the MVP is still CPU-first as an *ordering* statement. Carries the **pending TCB-AS/GPU exception** (unsigned): AGX requires running Apple's opaque, DMA-capable GPU firmware. | **2026-08-02** |

### What decision #6 costs, stated plainly

The product ships **without remote attestation** on its primary platform. A client cannot cryptographically
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
| P2-T1 | BSP v1 serving protocol spec — [`architecture/BSP-v1-serving-protocol.md`](architecture/BSP-v1-serving-protocol.md) | `670e072` |
| X-T1 | Proof-coverage tracker — `tools/proof-coverage/` | `670e072` |
| P2-T9 | swtpm measured boot + runtime TPM-presence gating (x86-64) | `c01d0ab` |
| P6-T1 | Apple Silicon research memo — [`superpowers/specs/2026-07-08-apple-silicon-baremetal-research.md`](superpowers/specs/2026-07-08-apple-silicon-baremetal-research.md) | `670e072` |

**Wave 2 — NOT STARTED.** This is where work resumes.

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
| **Caps** | Extend `CapabilityType` (ends at `Frame=10`) with `Serve=11, Model=12, Gpu=13` | `capability/capability_type.rs`; proofs in `src/capability-verify/` |

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
| **1** | HAL extraction — multi-arch becomes possible; x86-64 behavior byte-identical | none | **NEXT** |
| **AS-0** | Apple Device Tree parser (host-side, fuzz + Kani) | none | **NEXT** (parallel with P1) |
| **2** | Secure inbound serving path + capability extensions | P1 | arch-neutral |
| **3** | In-tree CPU inference MVP | P2, P1-fpu | arch-neutral |
| **4** | aarch64 core + QEMU `virt` bring-up harness | P1 | gates AS-1 |
| **AS-1..3** | Apple boot stub → AIC → DART on real hardware | P4, AS-0 | **primary platform** |
| **AS-4** | RTKit + ANS2 NVMe + PCIe + Ethernet → serving on the mini | AS-3, P3 | **long pole** |
| **AS-5** | **AGX GPU** — RTKit GPU endpoint, firmware load, command submission, GPU tensor kernels | AS-4, AS-3 DART proven | **largest single effort** |
| **5** | GPU on x86-64 (INV-GPU) — discrete accelerator | P3, P1-iommu | deferred |
| **X** | Proof program, CI, crate burn-down | woven throughout | continuous |

### Critical path to "the Mac mini serves inference"

```
P1 (HAL extraction) ──┬─▶ P4 (aarch64 core, QEMU virt) ──▶ AS-1 ──▶ AS-2 ──▶ AS-3 ──▶ AS-4 ──┐
                      │                                                                       ├─▶ MVP
AS-0 (ADT parser) ────┘                                                                       │
P2 (serving path) ──▶ P3 (inference engine) ──────────────────────────────────────────────────┘
```

Two independent tracks converge. The **platform track** (P1 → P4 → AS-*) is serial and hardware-gated. The
**product track** (P2 → P3) is architecture-neutral, developed and proven on x86-64 under QEMU, and is not
blocked by any Apple work. Running both concurrently is the whole reason the HAL exists.

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

### Phase AS-0 — Apple Device Tree parser

Starts immediately; no hardware, no HAL dependency. Rated **GO** by the research memo and "useful even if
the stream stops here."

- **AS-0-T1** ADT binary-format specification, re-derived from published Asahi documentation. Field widths and flag bits are **not** assumed — anything only documented by source gets specified by one session and implemented by another. **O**. Verify: written spec.
- **AS-0-T2** `#![no_std]`, zero-allocation, fail-closed ADT parser. Every offset/length/count bounds-checked against its containing region; malformed input denies. **S**. Deps: T1. Verify: host tests.
- **AS-0-T3** Fuzz target + Kani harness (no-panic, bounds, no allocation driven by ADT-supplied sizes). **S** harness / **O** hardening. Deps: T2. Verify: fuzz soak + Kani green — **INV-MEM**, INV-SERVE discipline.
- **AS-0-T4** boot-args parser + ADT/boot-args memory-range cross-check (disagreement fails closed). **S**. Deps: T2. Verify: host tests with adversarial fixtures.

### Phase 2 — Secure inbound serving path *(architecture-neutral)*

- **P2-T1** ~~BSP v1 protocol spec~~ — **DONE** (`670e072`).
- **P2-T2** Factor `ssh/` primitives into `src/brainix-transport-crypto/` (`no_std`) + server-side handshake. **O**. Verify: Kani (no-panic, length-checked), fuzz handshake FSM, test vectors.
- **P2-T3** Fail-closed BSP request parser (`servd/src/parser.rs`, `no_std`, zero-alloc, bounded). **S**. Verify: `fuzz_servd_request_parser` + Kani + audit — **INV-SERVE**.
- **P2-T4** `servd`: accept via `transportd`, session manager, per-client frozen capability set. **S**. Deps: T2, T3, T5. Verify: 2-concurrent-session integration; cross-naming denied.
- **P2-T5** Capability extensions `Serve`/`Model`/`Gpu` + grant/derive/revoke rules; extend `src/capability-verify/`. **O** — INV-AUTH, hardest tier. Verify: Kani green.
- **P2-T6** Delete `boot/ssh_bridge.rs` `static mut` session globals; route inbound via servd + capability IPC only. **S**. Deps: T4. Verify: grep-gate (no `static mut` session state); connect e2e.
- **P2-T7** Reframe `db/` for the session table + serving log (fixed pools) + cross-session non-interference Kani. **S** build / **O** proof. Deps: T5. Verify: Kani — no session row readable via another session's capability.
- **P2-T8** `auditd` extension: subscribe to serving events; manifest unchanged. **S**. Deps: T4. Verify: manifest diff = zero new capabilities (INV-AUDIT); CTF corpus ≥ 95% TP.
- **P2-T9** ~~vTPM closure~~ — **DONE** (`c01d0ab`). **x86-64 only**; has no analogue on the primary platform (INV-BOOT/AS).
- **P2-T10** Fuzz corpus + targets (handshake, parser, session state) into CI. **H** scaffold / **S** corpus. Deps: T2, T3.
- **P2-T11** Host-side test client `tools/bsp-client/` (std, zero crates). **H**. Deps: T1.
- **P2-A** Security audit. **O**. Gate.

### Phase 3 — In-tree CPU inference MVP *(architecture-neutral)*

- **P3-T0** **Userspace FP/SIMD enablement**: in-tree target spec for `inferd` + FP state save/restore in the context switch via `hal/fpu.rs`. Kernel stays soft-float. **S** impl / **O** review (context-switch ABI is TCB). Deps: P1. Verify: FP-dirty context-switch test; Kani on save-area bounds. *Per-arch: XSAVE/XRSTOR on x86-64; the aarch64 FP/NEON state path on the primary platform.*
- **P3-T1** Weight format spec "BXW1" (header, tensor table, per-tensor SHA-256, hard size bound; Q8_0 + f32). **S** spec / **O** review. Verify: spec; INV-MODEL mapping.
- **P3-T2** Reserved regions: extend `memory/virtual_address_layout.rs` + `physical_allocator.rs` with a build-time `WEIGHTS_REGION` (read-only after load, W^X) + per-session `KV_REGION` partitions; no allocator. **S**. Deps: P1. Verify: Kani (region non-overlap; weights-never-writable-post-seal) — **INV-MEM**. *Must be written page-size-agnostic: 16 KiB on the primary platform, 4 KiB on x86-64.*
- **P3-T3** Fail-closed BXW1 loader (streaming digest, measured, denies malformed/oversized). **S**. Deps: T1, T2. Verify: fuzz BXW1 header/tensor-table + Kani.
- **P3-T4** Tensor kernels (`no_std`, fixed scratch): matmul (f32 + Q8 dequant), RMSNorm, softmax, RoPE, SiLU/SwiGLU. **S**. Deps: T0. Verify: property tests vs reference; no-alloc grep-gate.
- **P3-T5** In-tree BPE tokenizer; the vocab blob is hostile input → fail-closed. **S**. Deps: T1. Verify: fuzz + Kani vocab parser; round-trip tests.
- **P3-T6** Transformer forward pass + KV cache in per-session slices; decode loop + sampling (CSPRNG from `hardware_security/csprng.rs`). **S**. Deps: T4, T5, T2. Verify: logits parity vs a host f32 reference on a tiny model.
- **P3-T7** `inferd`: confined-tenant manifest (capabilities = {Model, serving endpoint, own KV slice}; no Spawn, no net, no cross-session); wired to servd over synchronous IPC. **S**. Deps: T6, P2-T4. Verify: manifest audit — the model *cannot name* forbidden capabilities — **INV-MODEL**.
- **P3-T8** Confinement suite: adversarial-prompt harness (injection corpus) — zero escalation under any input. **O**. Deps: T7. Verify: suite green = CI regression bar.
- **P3-T9** e2e: `bsp-client` → QEMU x86-64 → auth → prompt → streamed tokens; 2 isolated clients. **H** scaffold. Deps: T7, P2-A. Verify: **datapath exit criterion**.
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
- **AS-4a** Storage: RTKit co-processor mailbox protocol + ANS2 NVMe (non-standard, tag-based NVMMU quirks). **S** impl / **O** audit. Deps: AS-3. Verify: weights read from disk on hardware. *Interim unblock: payload-embedded weights let AS-4b and the serving path proceed before this lands.*
- **AS-4b** Network: PCIe bring-up + the mini's built-in Ethernet NIC driver, as capability-bounded `devd-*` servers — never in the kernel. **S** impl / **O** audit. Deps: AS-3. Verify: NIC TX/RX on hardware.
- **AS-4c** e2e: remote `bsp-client` → Mac mini M2 → auth → prompt → streamed tokens; 2 isolated clients. Deps: AS-4a, AS-4b, P3-A. Verify: **MVP exit criterion.**
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

- **AS-5-T0** DART/GPU confinement proof: every DART instance fronting the GPU deny-all by default; Kani proof that `gpud` cannot widen its own window (`INV-DEV-006`). **O**. Deps: AS-3. **Gate for everything below.**
- **AS-5-T1** RTKit GPU endpoint over the mailbox layer built in AS-4a. **S**. Deps: AS-4a.
- **AS-5-T2** GPU firmware load and lifecycle. The blob is Apple-signed, closed, and unauditable — the **pending TCB-AS/GPU exception**. Load only behind a proven DART window. **S** impl / **O** audit. Deps: T0, T1. **Blocked until the exception is signed.**
- **AS-5-T3** Command submission and completion handling. Completion records are **hostile input** — fuzzed and Kani-checked like any network parser (`INV-PARSE-001`). **S**. Deps: T2.
- **AS-5-T4** GPU tensor kernels: matmul and attention, targeting **prefill** and **multi-client concurrency**, which is where the GPU actually wins. Single-stream decode stays bandwidth-bound and gains less. **S**. Deps: T3, P3-T4.
- **AS-5-T5** Scheduling policy across CPU and GPU: which work goes where, and how a hung or misbehaving GPU fails closed without stalling the serving path. **S** impl / **O** review. Deps: T4.
- **AS-5-A** Security audit, including the TCB-AS/GPU exception write-up and a DMA fault-injection campaign. **O**. Gate.

**Honest note.** Apple's GPU firmware runs concurrently with our kernel, for the life of the system, with
DMA capability, driven by data derived from client requests. That is a materially different trust posture
from SecureROM and iBoot, which run once at boot and then stop. DART is the entire defense.

### Phase 5 — discrete GPU on x86-64 *(deferred)*

P5-T1..T4 unchanged from the original plan; not scheduled. Superseded in priority by AS-5.

### Phase X — Continuous

- **X-T1** ~~Proof-coverage tracker~~ — **DONE** (`670e072`), `tools/proof-coverage/`.
- **X-T2** CI gates per arch (`cargo test --lib`, `fmt --check`, bare-metal release build, Kani, fuzz smoke, audit checklist; clippy non-gating). **S**. Deps: P1-T4.
- **X-T3** Reproducible build + Ed25519 signing + PCR publication. **S**. *Split by platform: predicted-vs-attested PCR matching is x86-64 only; on Apple Silicon this reduces to reproducible build + release signature (INV-BOOT/AS).*
- **X-T4** Vendored-crate burn-down (bitflags, log, multiboot2 first; crypto crates last, only after in-tree implementations pass vectors and audit). **S** impl / **O** crypto. Verify: `Cargo.lock` crate count strictly decreases.

---

## Per-component "done" gate

Every component ships **all** of:

1. **Invariant mapping** — which INV-* it touches and how.
2. **Fuzz artifact** for every hostile-input parser (libFuzzer target + checked-in corpus + soak before phase exit): BSP parser, handshake FSM, BXW1 loader, tokenizer vocab, **ADT parser**, **boot-args parser**, plus the existing targets kept green.
3. **Kani harness** for every parser *and* every security-relevant path (no-panic + bounds + the stated property: unforgeability, no-widening, non-interference, W^X preservation, region non-overlap, DMA-window non-widening) in `src/{capability,bootloader,hal,serve,infer}-verify/`.
4. **Prusti contracts** where functional (capability derive/revoke, `memory/pool_allocator.rs` bounds), toward the 80% coverage bar.
5. **Security audit report** — zero known vulnerabilities, every `unsafe` block justified, constant-time review for key material.
6. **No-regression bars** — auditd ≥ 95% TP, crate count non-increasing, no `static mut` outside the audited allowlist, grep-gates hold.

**Per-release whole-system audit:** end-to-end over the TCB (kernel, boot stub, capability, IPC, HAL
backends in use), the full serving datapath, all manifests, and the reproducible build. On x86-64 this
includes predicted-vs-attested PCR matching; on Apple Silicon the release notes must state the INV-BOOT/AS
degradation plainly. Release notes state: maximal assurance under the stated attacker model, not a proof of
absolute security.

---

## Verification, per phase

- **P1:** x86 QEMU boot byte-parity vs pre-refactor logs; full `cargo test --lib`; aarch64 HAL-skeleton `cargo check`; HAL Kani harnesses; P1-A.
- **AS-0:** ADT parser fuzz soak + Kani green, entirely on the host, no hardware.
- **P2:** handshake vectors; parser fuzz soak; 2-client isolation test; cross-session Kani; swtpm predicted == attested (x86-64); P2-A.
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
6. **"No new crates" against building an inference engine plus two platform stacks.** Tokenizer, quantized matmul, RoPE, sampling, weight format, AIC, DART, RTKit, ANS2, PCIe, NIC — all hand-rolled. The soft-float kernel target (P3-T0) touches the TCB. The AGX GPU (AS-5) is the largest of these and the least well understood.
7. **Audit capacity is the pipeline bottleneck.** Expect audit queues and multi-round fix loops on the hardest proofs (non-interference, DMA non-widening). Mitigation: draft Kani harnesses alongside code; batch audits per wave.
8. **Clippy is pre-existing red and non-gating** (200+ `arithmetic_side_effects` across the kernel), which hides new lint signal. Scheduled burn-down so it can eventually gate.

## Critical files

- `src/kernel/src/arch/mod.rs` — the HAL extraction seam (today: cfg-gated x86 modules, no trait layer).
- `src/kernel/src/boot/ssh_bridge.rs` — inbound seed to replace with servd; `static mut` session state to delete.
- `src/kernel/src/capability/capability_type.rs` — `Serve`/`Model`/`Gpu` extension point (ends at `Frame=10`).
- `src/kernel/src/memory/virtual_address_layout.rs` — fixed reserved WEIGHTS/KV regions (INV-MEM).
- `src/capability-verify/src/lib.rs` — the existing Kani proof pattern to extend across the new `*-verify` crates.

## Immediate next step

Two tasks start in parallel, sharing no code:

1. **P1-T2** — move `arch/*` → `arch/x86_64/` behind the HAL traits, zero behavior change. Single-owner for `arch/`.
2. **AS-0-T1/T2** — specify and implement the ADT parser on the host. No hardware, no HAL dependency.

Before AS-1 can begin, the hardware rig must exist: the Mac mini M2 in Permissive Security, a debug UART
cable, and m1n1 installed as a lab instrument.
