# Apple Silicon bare-metal research memo (P6-T1)

> ## ⚠️ Verdicts superseded 2026-08-02 — technical content still authoritative
>
> **This memo's engineering analysis is the reference for all Apple Silicon work and remains accurate.**
> Its *scope recommendations* were overridden by the owner:
>
> | This memo said | Now |
> |---|---|
> | Apple Silicon **deferred / out of active scope** | **Primary platform** — Mac mini M2 (`Mac14,3`, `T8112`, 32 GB) |
> | AS-4 (end-to-end serving on M-series) **NO-GO** | **In scope** — the MVP exit criterion |
> | "must never block the x86-64 MVP" (§8) | x86-64 is now the **secondary**, attested platform |
> | INV-BOOT/AS "must be surfaced to the owner before any implementation phase is funded" (risk 2) | **Surfaced and signed off** — see `docs/NORTH_STAR.md` |
>
> **The cost estimates behind those verdicts were not revised — only the decision about whether to pay
> them.** §6 risk 3 (the RTKit + ANS2 NVMe + PCIe + NIC chain, "where the stream can silently consume the
> project") remains the most accurate statement of the schedule risk in the tree. Read it as a live
> warning, not a historical one.
>
> Authoritative scope and phasing: [`docs/ROADMAP.md`](../../ROADMAP.md). Authoritative invariants and the
> INV-BOOT/AS and TCB-AS exceptions: [`docs/NORTH_STAR.md`](../../NORTH_STAR.md).

**Status:** research memo — go/no-go assessment, no code. **Verdicts superseded; technical content current.**
**Scope:** native bare-metal BraiNIX on Apple Silicon (M-series) — now the primary platform.
**Companions:** `docs/NORTH_STAR.md` (invariants), `docs/THREAT_MODEL.md` (attacker model, measured-boot posture), `docs/ROADMAP.md` (scope).

**Epistemic note.** Almost nothing below the iBoot handoff is documented by Apple. What we "know" about Apple Silicon bring-up comes from the Asahi Linux project's reverse engineering (m1n1, the Asahi kernel trees, and docs.asahilinux.org). This memo flags, per topic, what is *contractual* (Apple-supported), what is *reverse-engineered but stable in practice*, and what is *unknown/uncertain*. Where register-level specifics are uncertain, this memo says so rather than inventing them; all register maps must be re-derived and verified on hardware before any code claims them.

---

## 1. Boot chain: iBoot handoff and the custom-kernel path

### 1.1 The chain

Apple Silicon Macs boot: **SecureROM (Boot ROM) → iBoot1 (system firmware) → iBoot2 (per-OS loader in the boot volume) → payload**. There is no UEFI, no ACPI, no PSCI, and no EL3 — Apple removed the secure monitor level entirely (its role is taken by proprietary "Guarded Execution" modes, GXF/SPRR, which we do not need to touch for a basic port). SecureROM and iBoot are Apple-signed and immutable to us. **We can never own the first instructions on this platform.** That is a permanent, named exception to the "every byte that runs is in-tree" dependency-closure rule and must be recorded in the TCB list for this target: SecureROM, iBoot1/2, and sepOS (the Secure Enclave OS, which always runs) join the trusted set whether we like it or not.

### 1.2 The supported path to a custom kernel (this part is contractual)

Apple deliberately supports third-party kernels. Per-boot-volume security policy is set from recoveryOS ("One True Recovery"/1TR, the paired local recovery environment):

- `bputil` downgrades the volume to **Permissive Security** (requires local admin credentials and physical presence; FileVault/Activation Lock still gate it).
- `kmutil configure-boot -c <payload> -v <volume>` installs a custom kernel object as that volume's boot object. The payload is wrapped/signed as an **Image4 (IMG4)** object under the machine's **local policy**: the Secure Enclave holds a device-local signing key, and iBoot2 verifies the payload's digest/signature against that local policy at every boot.
- This is exactly how Asahi Linux installs m1n1. It is the realistic delivery mechanism for a BraiNIX payload: build payload on a dev machine → install via kmutil from macOS/recoveryOS on the target → reboot.

Consequences: a macOS stub install (the paired recoveryOS and firmware volumes) must remain on disk; "bare metal" here means "our kernel is the OS," not "Apple software is absent." Fully headless fleet provisioning is awkward (1TR requires physical presence for the downgrade step, once per machine).

### 1.3 The handoff (reverse-engineered but stable in practice)

What Asahi has established and m1n1 relies on:

- iBoot loads the payload (a Mach-O — m1n1 embeds its raw image in a thin Mach-O wrapper) into physical memory and jumps to its entry point on a **single CPU** with **interrupts masked**, passing a pointer to a **boot-args structure** in `x0`.
- The boot-args structure carries: physical/virtual memory base and size, a pointer to the **Apple Device Tree** (ADT, §2), framebuffer parameters (base, stride, width, height, depth) for the iBoot-initialized display, and a command line. The structure is **versioned and has changed across iBoot releases** — the exact field layout per version must be taken from current m1n1 behavior and verified on hardware; this memo does not assert field offsets.
- Entry is at a high exception level (EL2 on the machines Asahi supports, with an option to drop to EL1). **Uncertain:** the exact MMU/cache state at handoff and its stability across iBoot versions; m1n1 conservatively re-establishes its own MMU state immediately, and we must do the same — assume nothing about inherited translation state.
- Secondary CPUs are **not** started via PSCI (there is none). They are parked and released via Apple-specific per-core reset-vector registers (RVBAR-style, plus implementation-defined chickens bits) described only by Asahi's work. **Uncertain at register level** — re-derive from hardware + Asahi docs.
- There is no runtime firmware interface after handoff (no UEFI runtime services, no SMC calls in the ARM sense). Power/reboot involve the Apple SMC co-processor or the watchdog; the watchdog-reset path is the simple one for early bring-up.

**Knowable vs reverse-engineered-only, summarized:** the *installation and signing flow* (bputil/kmutil/Image4/local policy) is Apple-documented and stable. The *handoff ABI* (boot-args, entry state, CPU release) and everything at register level below it is reverse-engineered-only, has changed across iBoot/macOS releases, and carries no compatibility promise from Apple. Every macOS update that touches firmware is a potential breaking event for our boot stub.

### 1.4 Practical bring-up rig

Asahi's development model — m1n1 exposing a USB proxy so a host machine can poke registers, load payloads, and hypervise macOS to trace MMIO — is the reason their reverse engineering was tractable. We cannot ship their code (§4), but we *can* use m1n1 as a lab instrument on a dev machine (running m1n1 to explore hardware is using a tool, not linking code). Recommended: dedicated M-series dev machine in Permissive mode + UART/USB debug rig; the Samsung-lineage (s5l) UART is the earliest console and is among the simplest blocks on the SoC.

---

## 2. Apple Device Tree (ADT)

**What it is.** iBoot passes a device tree describing the SoC: nodes with properties for MMIO ranges, interrupts, clocks, per-device configuration, and boot-time data (including some values iBoot patches in at boot, e.g. memory sizing and per-device calibration). It is **not** the standard Flattened Device Tree (FDT/DTB). It is Apple's own binary format — structurally a tree of nodes where each node carries a property count and child count, and properties carry a fixed-width name field and a length-prefixed value — with no published specification. The concrete binary layout is known only from Asahi's reverse engineering; exact field widths and flag bits must be re-derived (Asahi's *documentation* of the format may be consulted; their parser code may not — §4).

**Threat posture.** The ADT arrives from firmware we do not control and cannot audit. Under the threat model's rules, firmware-supplied bytes get the same treatment as network bytes: the ADT parser is a `#![no_std]`, fail-closed hostile-input parser. Concretely:

- Every offset/length/count is bounds-checked against the containing region; malformed → deny (halt boot with a diagnostic, never "best effort").
- No allocation driven by ADT-supplied sizes (INV-MEM: fixed pools; an ADT claiming 2^32 children denies, it does not grow anything).
- Fuzz target and Kani harness from day one, exactly like the network request decoder (THREAT_MODEL "per-invariant verification", INV-SERVE discipline). The parser is pure and host-testable — this is the *easiest* Apple-specific component to verify, because it needs no hardware.
- Cross-checks where possible: memory ranges from boot-args vs ADT must agree or we fail closed.

**Where it sits in bring-up.** Immediately after the boot stub establishes a stack, exception vectors, and its own page tables: parse ADT → locate UART (console), memory map, AIC, timers, DART instances. Everything downstream of the boot stub consumes ADT output, so the parser is on the critical path and should be built first, on the host, before any hardware work.

---

## 3. AIC and DART: what the HAL backends must abstract

Both feed the arch-neutral HAL traits (interrupt-controller and IOMMU traits) that the realignment defines for x86-64 first. The value of this stream to the main line is precisely that these two backends force the traits to be honest abstractions rather than thin wrappers over APIC and VT-d.

### 3.1 AIC (Apple Interrupt Controller)

Not a GIC. A memory-mapped, Apple-proprietary controller, reverse-engineered only. What the HAL interrupt trait must be able to express, based on AIC's known shape:

- **Single "event" read for IRQ acknowledgment**: AIC delivers a packed event word (type + source) from one MMIO read, rather than GIC-style ack/EOI register pairs. The trait's `ack → dispatch → eoi` flow must not assume distinct ack/EOI operations.
- **FIQ is outside the controller.** The per-CPU timers (ARM generic timers, virtual/physical) and some other per-CPU sources are hardwired to **FIQ**, which AIC does not mediate. The kernel must take FIQs and demultiplex them by reading timer/system-register state. The HAL trait therefore needs a notion of "CPU-local sources not owned by the controller" — x86-64's LAPIC-timer path has an analogous local/remote split, so this generalizes, but the trait must not bake in "all interrupts flow through the controller."
- **IPIs** are sent via Apple implementation-defined system registers (a "fast IPI" path) and/or AIC registers depending on SoC generation. Trait needs `send_ipi(cpu, vector)` without assuming a controller doorbell.
- **Affinity/distribution and versioning:** at least two major AIC revisions exist across M-series generations (widely referred to as AICv1 and AICv2), with different register layouts and capacities. **Uncertain:** the exact generation-to-revision mapping and register maps — take from ADT compatible strings at runtime and re-derived docs. Backend must select by ADT, fail closed on unknown compatible strings.
- Masking/unmasking per source, per-CPU enable, and a bounded number of sources sized from the ADT at boot into fixed tables (no dynamic allocation).

### 3.2 DART (Device Address Resolution Table — Apple's IOMMU)

Not an SMMU. Per-device-cluster IOMMU instances scattered across the SoC, each fronting one device or a small group; reverse-engineered only, with **multiple incompatible variants across SoC generations** (different PTE formats, different register layouts — commonly distinguished in Asahi work by SoC family, e.g. t8103-era vs t6000-era vs t8110-era). **Uncertain:** PTE bit layouts per variant; do not trust any memory of them, re-derive.

What the HAL IOMMU trait must abstract:

- **Many small IOMMUs, not one big one.** VT-d presents a small number of translation units covering the PCIe hierarchy; DART is dozens of instances, one per device/cluster, discovered via ADT. Trait must be instance-oriented: `for each protection domain, map/unmap/flush on a specific IOMMU instance`, not a global address-space registry.
- **Stream/sub-device selection is narrow.** A DART instance typically serves a handful of stream IDs. The trait's (device → domain) binding must allow very small ID spaces.
- **Bypass exists and must be structurally off.** DARTs have bypass modes; INV-GPU's philosophy (IOMMU confinement, not driver correctness, is the control) demands the backend initialize every discovered DART to a **blocked/deny-all default** and never expose a bypass knob through the trait. Fail closed: an ADT-discovered DART we cannot drive means the device behind it stays unusable, not unconfined.
- **Locked DARTs.** iBoot locks some instances (notably display-path DARTs) — their config registers are read-only after boot, with page tables that must be adopted rather than replaced. The trait needs to express "pre-existing, immutable mapping owned by firmware" without granting the kernel the illusion it controls it. This concept has no x86-64 analogue and is a genuine abstraction test.
- Page size: Apple SoCs natively favor 16K pages on the DMA path (and the CPU side commonly runs 16K). The trait must not hardcode 4K granules. **Uncertain:** exact per-variant supported granule sets.
- TLB/translation cache invalidation sequences are per-variant and reverse-engineered; the trait exposes `flush(domain)` and the backend owns the sequence.

DMA confinement on this platform is not optional hardening — NVMe, USB, and (on Ethernet-equipped machines) the NIC all sit behind DARTs, and several are driven by co-processors running Apple firmware (RTKit-based, §6 risk 3). The DART backend is what keeps INV-MEM meaningful against those devices.

---

## 4. m1n1 / Asahi Linux: reference-only, and what that costs

The north-star's rule is absolute: zero external code, no vendoring, drivers written in-tree. m1n1 (MIT-licensed) and the Asahi Linux kernel (GPL-2.0) are therefore **reference-only**: we study their *documentation* (docs.asahilinux.org, the Asahi wiki, blog writeups, mailing-list descriptions) and reimplement from understanding. Practical rules for this stream:

- Prefer prose documentation over source. Where only source documents a behavior, the person reading it writes a *specification* (register map, sequence description) and a different implementation session codes from the spec — a lightweight clean-room discipline. This matters more for the GPL kernel code than for MIT m1n1, but the in-tree rule forbids copying either, so apply it uniformly.
- Running m1n1 as a lab tool on a dev machine (hypervisor tracing, register exploration) is permitted use of a tool, not incorporation of code.

**The cost, stated honestly:** Asahi is a multi-year effort by specialists with a purpose-built reverse-engineering toolchain, and we are choosing to re-derive their results without reusing a line. For the narrow set in this memo (boot stub, ADT, AIC, DART, UART, timers) the surface is small enough that reimplementation-from-docs is a bounded cost — these are exactly the components Asahi has documented best. For everything past that (RTKit mailboxes, ANS2/NVMe, PCIe, USB, SMC, and above all AGX), the rule multiplies cost by a large factor and is the main input to the no-go lines below. The rule also means every future SoC generation re-imposes the cost. This is accepted as the price of the dependency-closure principle; it is why this stream is capped in scope and can never sit on the critical path (§7).

---

## 5. INV-BOOT on Apple Silicon: the honest degradation

INV-BOOT as written requires: measurement into a **TPM**, reproducible build, Ed25519 signature, published PCR predictions. **Apple Silicon has no TPM and no way to add one meaningfully** (no LPC/SPI TPM, and a USB TPM is not a root of trust). The Secure Enclave (SEP) is not a TPM: it exposes no PCR-style extend/quote/seal interface to third-party software, its protocol is proprietary and undocumented, and driving it from a non-Apple kernel is deep, unsupported reverse-engineering territory — **out of scope**.

What remains on this target:

- **Boot-time payload integrity, rooted in Apple's chain.** In the kmutil/local-policy flow, iBoot2 verifies the Image4-wrapped payload against the SEP-held local policy at every boot. A tampered on-disk payload fails to boot. This is real and hardware-rooted — but the root is Apple's, the policy key is device-local (not our release key), and it attests nothing to anyone.
- **Reproducible build + Ed25519 release signature** — unchanged; these are properties of the artifact, not the platform. Third parties can still verify that a published payload matches source bit-for-bit.
- **A software-only measurement log**: the kernel can hash what it loads (weights, servers) and record/report the log — the same honest fallback the threat model already adopts for the currently-unmet vTPM dependency on x86-64 (THREAT_MODEL §deployment: "degrade to an honest software-only fallback").

What is **lost**, permanently, on this target:

- **Remote attestation.** No quote; a remote party cannot distinguish a genuine BraiNIX boot from a compromised one. 
- **Sealing.** No secrets bound to boot state; anything at rest is protected only by what the kernel does at runtime.
- **Runtime-chain measurement.** The software measurement log is self-reported: a kernel compromised early lies about it. Detection of a divergent chain — the exact property INV-BOOT's blast-radius entry exists for — is gone.

**Required posture:** a written, named invariant exception — "INV-BOOT/AS: on Apple Silicon, INV-BOOT is satisfied only in its reproducible-build and release-signature clauses plus iBoot local-policy payload integrity; measurement, attestation, and sealing are structurally unavailable" — recorded in THREAT_MODEL and the platform support matrix, with owner sign-off (per the north-star's hard-line rule). Deployments needing attestation must use the x86-64 target. No papering over.

---

## 6. Top risks

1. **No contract below boot-args — unbounded maintenance.** Everything past the kmutil flow (boot-args layout, entry state, ADT format, AIC/DART registers, CPU release) is reverse-engineered with zero compatibility promise. Apple has changed these across iBoot/macOS releases and changes them per SoC generation; each firmware update or new M-generation is a potential breakage, forever, and our zero-vendoring rule (§4) means we re-derive fixes ourselves rather than pulling Asahi's.
2. **INV-BOOT is structurally unsatisfiable (§5).** No TPM, no attestation, no sealing — a *permanent invariant exception* on this target, not a gap that closes later. If any deployment story for this stream assumes attestation, the stream is dead on arrival; this must be surfaced to the owner before any implementation phase is funded.
3. **The hidden dependency chain behind "serving".** "CPU-only serving" quietly requires storage (weights) and network (clients). On Apple Silicon those mean: RTKit co-processor mailbox protocol + ANS2 NVMe (non-standard, tag-based NVMMU quirks) for disk, and PCIe bring-up + a NIC driver (Ethernet-equipped machines) or a very large Broadcom Wi-Fi firmware stack for network. Each is a major reverse-engineered subsystem Asahi spent person-years on, and §4 forbids reuse. This chain — not AIC or DART — is where the stream can silently consume the project. (Interim containment: netboot-style delivery of weights via the boot payload and a USB-gadget or UART transport for early serving experiments — degraded, but avoids the chain until it is deliberately funded.)

Secondary risks, noted: per-generation AIC/DART variant divergence multiplying test-hardware needs; 1TR physical-presence requirement complicating any fleet story; 16K-page assumptions leaking into supposedly arch-neutral memory code; SoC errata/chicken-bit lore that exists only as constants in Asahi source, which is awkward under clean-room rules.

---

## 7. Phased go/no-go

Recommendation per subcomponent. "GO" means fund as a background stream; nothing here may ever gate or delay the x86-64 MVP (§8).

| Phase | Subcomponent | Verdict | Rationale / gate |
|---|---|---|---|
| AS-0 | ADT parser (host-side, `#![no_std]`, fuzz + Kani) | **GO** | Pure hostile-input parser; no hardware needed; directly exercises the project's parser discipline; useful even if the stream stops here. First deliverable. |
| AS-1 | Boot stub (kmutil delivery, entry, MMU/vectors, UART console, boot-args + ADT consumption, watchdog reset) | **GO** | Delivery path is Apple-supported; handoff is Asahi-documented; small surface. Gate: requires a dedicated dev machine in Permissive mode + debug rig. Exit criterion: serial "hello, invariant banner" from BraiNIX on M-series. |
| AS-2 | AIC backend + FIQ timer path (feeds HAL interrupt trait) | **CONDITIONAL GO** | Reverse-engineered registers; FIQ split and IPIs are the tricky parts. Condition: AS-1 shipped, and the HAL interrupt trait exists and is stable on x86-64 first. Fail closed on unknown AIC compatible strings. |
| AS-3 | DART backend (feeds HAL IOMMU trait) | **CONDITIONAL GO** | Highest security value (DMA confinement) but most variant-fragmented. Condition: AS-2 shipped; deny-all default for every discovered instance from day one; locked-DART semantics represented honestly in the trait. |
| AS-4 | CPU-only serving end-to-end (storage + network + serving path on M-series) | **NO-GO for now** | Blocked on the hidden dependency chain (risk 3): RTKit + ANS2 NVMe + PCIe/NIC are each larger than AS-0..3 combined under the no-vendoring rule. Re-evaluate with a fresh memo only after AS-3 ships and the x86-64 serving MVP is done. Interim: payload-embedded weights + UART/USB-gadget transport for experiments only. |
| — | AGX GPU (inference on Apple GPU) | **OUT OF SCOPE** | Firmware-driven, enormous, the single largest Asahi effort; INV-GPU is deferred even on x86-64. CPU-only inference is the realistic M-series target — unified-memory bandwidth makes M-series CPUs a genuinely credible CPU-inference platform, which is why the stream is worth keeping alive at all. Do not revisit before INV-GPU lands on x86-64. |

Net: **conditional go** for the stream as a research/HAL-hardening track through AS-3, **no-go** on committing to Apple Silicon serving, **out of scope** for AGX.

## 8. Why this stream must never block the x86-64 MVP

- The **product** invariant set (INV-BOOT with real measurement, INV-GPU eventually) is only satisfiable on x86-64; Apple Silicon is structurally a degraded-INV-BOOT platform (§5). The MVP's security story lives on x86-64.
- Every Apple Silicon fact is revocable by an Apple firmware release (risk 1); scheduling anything critical on revocable ground is planning malpractice.
- The stream's real near-term value to the main line is **portability pressure on the HAL traits** (AIC's FIQ split, DART's many-instances/locked-instance model) and a second consumer for the hostile-input parser discipline (ADT). That value is delivered by AS-0 through AS-3 as background work; it requires no serving milestone.
- Resourcing rule, stated for the plan: Apple Silicon tasks are preemptible by any x86-64 MVP task, hold no reserved capacity, and their slippage is never a release consideration.
