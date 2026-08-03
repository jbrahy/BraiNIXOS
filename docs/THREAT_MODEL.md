# BraiNIX threat model

Companion to NORTH_STAR.md. The north-star states the invariants as a contract. This document states who
the contract defends against, what is trusted to uphold it, how each invariant is verified, and what a
violation costs. Phasing and status live in ROADMAP.md.

BraiNIX **serves LLM inference to remote network clients**, which makes the inbound serving path the
largest attack surface in the system. As of the owner decision of 2026-08-02 the **primary platform is
Apple Silicon** (Mac mini M2, `Mac14,3`, SoC `T8112`), with x86-64 retained as the secondary and
**attested** platform. That decision materially changes the trust boundary and the boot-integrity story;
this document is written around both realities and marks every claim that is platform-specific.

## Attacker model

Assumed capabilities of the adversary:

- Is a remote network client, or controls one. Supplies arbitrary inbound bytes to the serving path:
  connection setup, authentication attempts, and — once authenticated — arbitrary request payloads and
  arbitrary prompt content.
- Drives the served model with adversarial prompts, including content crafted to elicit privilege
  escalation, to exfiltrate another client's session or the weights, or to make the model reach outside
  its serving channel.
- Supplies arbitrary disk and filesystem content, including malformed model-weight blobs and session/log
  data.
- Fully controls any userspace process it compromises, including device-driver servers and the serving
  front end.
- Observes timing and any published artifact (payload image, PCR predictions where published, source).
- **On Apple Silicon:** may present a modified or hostile Apple Device Tree, boot-args structure, or any
  other firmware-supplied blob to the kernel, to the extent it can influence the boot environment.

Assumed not available to the adversary:

- Defeating the CPU, IOMMU (VT-d or DART), or — on x86-64 — the TPM as hardware, or breaking Ed25519,
  SHA-256, ChaCha20, X25519, or AES-256-GCM as primitives.
- Possession of the release-signing private key.
- Defeating Apple's SecureROM/iBoot signature chain, or extracting the device-local policy key from the
  Secure Enclave.
- Physical glitching and side channels below the architectural level are out of scope for v1 and tracked
  separately.

Explicitly **in** scope as an operational threat, not a cryptographic one: **Apple firmware updates**.
The boot-args layout, ADT binary format, AIC/DART register maps, and CPU-release sequences are
reverse-engineered with no compatibility promise from Apple, and have changed across iBoot and macOS
releases. Every macOS update that touches firmware is a potential breaking event for the boot stub. This
is a permanent availability and maintenance risk on the primary platform, and the zero-vendoring rule
means each break is re-derived in-tree rather than pulled from upstream.

## Trust boundary

In the TCB, where a single defect can break security:

- The kernel and the boot stub.
- The CPU and the IOMMU (VT-d on x86-64; the DART instances on Apple Silicon).
- The Ed25519 release-signing key.
- The in-tree model weights of the served model and the auditor.
- **x86-64 only:** the TPM 2.0, and the UEFI Secure Boot and measured-boot chain.
- **Apple Silicon only (TCB-AS, unavoidable):** **SecureROM**, **iBoot1**, **iBoot2**, and **sepOS**.

### TCB-AS: the components we cannot remove

On Apple Silicon we never own the first instructions. SecureROM, iBoot1, and iBoot2 are Apple-signed and
immutable; sepOS always runs. All four are closed source, unauditable by us, and unreplaceable. They are
in the TCB by force, not by choice, and they permanently violate the north-star's dependency-closure rule
on the primary platform.

The relationship is not purely a cost. iBoot2 verifies our Image4-wrapped payload against a
Secure-Enclave-held device-local policy at every boot, so a tampered on-disk payload does not boot — real
integrity, rooted in hardware. But the root is **Apple's**, keyed to **that machine**, and it attests
nothing to anyone. It protects the payload at rest; it proves nothing to a remote party.

A macOS stub install (paired recoveryOS and firmware volumes) must remain on disk. Downgrading the
volume to Permissive Security requires local admin credentials and physical presence via One True
Recovery, once per machine — which also means fully headless fleet provisioning is not available.

The served model's weights are trusted deliberately and uncomfortably: they are loaded, measured, and
run, and a compromised or poisoned weight set cannot be ruled out by structure. That is exactly why
INV-MODEL and INV-SERVE exist — they cap the blast radius of a bad or hijacked model to a single client's
session and deny it any authority, spawn, cross-session read, or network reach outside the serving
channel. The model is central to the product and central to nothing in the TCB's authority.

Outside the TCB, assumed hostile:

- Every remote client, every inbound byte, every prompt, and every token the served model emits.
- Every userspace process, including the serving front end and any operator console.
- Every disk byte, including model-weight blobs and the session/log store.
- **Every byte of firmware-supplied data on Apple Silicon** — the ADT, boot-args, and any structure iBoot
  hands us. Firmware we do not control gets exactly the treatment network bytes get.
- Every device driver, including the GPU driver on the deferred hardware milestone. Drivers run as
  ordinary servers with bounded device capabilities and no special standing.

## Per-invariant verification and blast radius

**INV-AUTH.** How we know: Kani proofs on the capability and IPC paths, backed by types that make a
forged or widened capability unrepresentable. If violated: a process or a client gains authority it was
never granted; this is full escalation and is the worst case the design exists to prevent.

**INV-MEM.** How we know: a structural page-table invariant plus the absence of any heap allocator in the
kernel image; model weights and KV-cache occupy fixed reserved regions, not a growable allocator. If
violated: W^X loss enables code injection in the affected domain; a reintroduced allocator reopens a
whole class of use-after-free and allocator-corruption bugs the fixed-pool discipline forecloses.
Platform note: Apple Silicon uses **16 KiB** base pages against x86-64's 4 KiB. Any page-size assumption
that leaks out of the HAL into supposedly architecture-neutral memory code is an INV-MEM defect, not a
portability inconvenience.

**INV-IPC.** How we know: types that make a shared-memory channel or async queue unrepresentable in tree,
plus proofs on the rendezvous path. If violated: shared mutable state between domains reopens TOCTOU and
confused-deputy patterns the synchronous model forecloses.

**INV-BOOT.** Platform-split; see INV-BOOT/AS in NORTH_STAR.md for the signed exception.

- *x86-64 (attested):* published PCR predictions matched against attested values, plus a reproducible
  build any third party can reproduce bit for bit. If violated: an attacker can ship or boot an image
  that does not match its attestation; measured boot is what makes that detectable rather than silent.
- *Apple Silicon (primary, degraded):* reproducible build and Ed25519 release signature hold unchanged;
  payload-at-rest integrity is enforced by iBoot2 against the device-local policy. Measurement,
  attestation, and sealing are **structurally unavailable**. If violated: **there is no detection
  mechanism.** A remote client cannot distinguish a genuine BraiNIX boot from a compromised one, and a
  kernel compromised early can report an arbitrary software measurement log. This is the accepted cost of
  the primary-platform decision and is the largest residual risk in the system.

**INV-SERVE.** How we know: the inbound request decoder is a `#![no_std]` hostile-input parser with a
fuzz target and a Kani harness, fail-closed on any malformed length/offset/type tag; per-client session
capabilities are frozen at grant and cannot name another session. If violated: one client reads or
corrupts another client's session, weights view, or KV state — a cross-tenant breach and the primary
failure the serving design defends against.

**INV-MODEL.** How we know: the same capability-manifest discipline as the auditor — the served model
*physically cannot name* the capabilities it lacks, so no prompt can make it spawn, mutate the kernel,
read another session, or reach the network outside the serving channel. Weight integrity is checked
against a measured digest before first use. Backed by a confinement suite the model runtime must pass
under active prompt injection with no escalation under any input. If violated: the model could act
outside its session or exfiltrate across the boundary; the capability manifest is the structural backstop
that a bad model cannot defeat by reasoning. Platform note: on Apple Silicon the weight digest is
anchored only to the software measurement log, not to a hardware quote.

**INV-AUDIT.** How we know: the auditor's frozen capability manifest is the proof. It physically cannot
name the capabilities it lacks, so it cannot spawn, mutate the kernel, or reach the network regardless of
what its model decides. It observes the serving stack — connections, capability grants, request/response
boundaries — and reports. If violated (only possible via a manifest error): audit visibility is lost;
privilege is not, by construction.

**INV-GPU** *(deferred milestone)*. How we know: the accelerator's DMA windows are confined by IOMMU
mappings the driver cannot widen, and the driver holds only bounded device capabilities. Until the GPU
milestone lands, inference is CPU-only and this is a stated target, not a shipped guarantee. If violated:
a driver or device DMA escapes its window into kernel or cross-domain memory — which is why the IOMMU
confinement, not driver correctness, is the control. Apple's AGX GPU is out of scope entirely, so on the
primary platform inference is CPU-only for the foreseeable future.

Standing bars, enforced in CI and never allowed to regress:

- Auditor true-positive rate above 95% on the released CTF corpus, measured against the serving stack.
- Machine-checked coverage of kernel invariants driven toward 80%.
- Zero external dependencies in cargo metadata is the target; the current crate list is tracked debt that
  only decreases. The inference engine, the platform backends, and the GPU driver add none.

## Firmware-supplied input on Apple Silicon

A new hostile-input class introduced by the primary-platform decision, ranked alongside network input
because it is parsed earlier and with more authority.

The **Apple Device Tree** arrives from firmware we do not control and cannot audit. It is not FDT/DTB; it
is Apple's own undocumented binary format, known only through reverse engineering. Under the rules above
it gets the network-byte treatment:

- Every offset, length, and count is bounds-checked against its containing region; malformed input halts
  the boot with a diagnostic and never proceeds best-effort.
- No allocation is ever driven by ADT-supplied sizes. An ADT claiming an absurd child count denies; it
  does not grow anything (INV-MEM).
- A fuzz target and a Kani harness exist from the first commit, exactly as for the network request
  decoder. The parser is pure and host-testable, which makes it the cheapest component in the system to
  verify and therefore the first one built.
- Cross-checks are mandatory where two sources overlap: memory ranges reported by boot-args and by the
  ADT must agree, or the boot fails closed.

The same discipline applies to the boot-args structure itself, whose layout is versioned and has changed
across iBoot releases.

## Trusted path and any operator console

Under the former design the trusted path existed so a local user could consent to an internal assistant
*acting on the system*. The served model does not act on the system — it answers client prompts within
its confined session — so a per-action consent path is no longer the central concern. What survives is
the terminal-safety rule for any operator console that renders untrusted bytes (model output, client
data, filenames, disk or network bytes):

- Color and structure are decisions the trusted renderer makes about semantically-tagged output, never
  in-band codes interpreted from an untrusted byte stream.
- The terminal is strictly one-way. It never writes to its input under any sequence. Reflection sequences
  (answerback, device status report, device attributes, cursor-position report, OSC clipboard) are not
  implemented, so untrusted output can never forge a keystroke.
- If in-band SGR is ever allowed, it is a closed whitelist grammar implemented as a small state machine,
  fuzzed and Kani-checked like every other in-tree parser, with everything outside the set rendered as
  literal bytes.

On Apple Silicon the early console is the SoC's Samsung-lineage (s5l) UART, reached over a debug cable.
It is a development interface, is not authenticated, and grants whoever holds the cable physical-access
authority. It must not be present in any production configuration.

If a future feature reintroduces a consent-gated action on the local system, it re-inherits the
kernel-intercepted secure-attention-sequence design (a kernel context the console server cannot observe
or forge), so any such consent rests on the kernel, not on console correctness.

## Deployment threat profile (inbound-serving · multi-client · network-facing)

This section re-ranks the general model above for the deployment BraiNIX ships in, so design effort is
spent where the residual risk concentrates. The general model remains authoritative.

**Deployment, stated.** The reference deployment is a **Mac mini M2 (`Mac14,3`, T8112, 32 GB unified
memory)** running BraiNIX as the sole OS, delivered as an Image4 payload via `kmutil` under Permissive
Security. Inference is **CPU-only** — AGX is out of scope — so throughput is bounded by CPU and memory
bandwidth, and the MVP proves the secure datapath rather than competitive performance. x86-64 under QEMU
remains the development, CI, and attested-deployment target. The runtime profile is **network-facing with
a single authenticated, capability-gated inbound serving socket**, serving one or more remote clients
whose sessions are mutually isolated.

**Dominant threats, re-ranked for this deployment (highest first):**

1. **No remote attestation on the primary platform.** Ranked first because it is unmitigable and it
   changes what every other control is worth. On Apple Silicon a client cannot verify what it is talking
   to, and an early kernel compromise is undetectable from outside. Every downstream guarantee is
   conditional on a boot state that cannot be proven. Deployments that cannot accept this must run
   x86-64. See INV-BOOT/AS.
2. **Hostile remote clients and the inbound protocol.** The connection/auth/request path parses
   attacker-controlled bytes reachable from the network. It must be `#![no_std]`, fuzzed, and
   Kani-checked, fail-closed on any malformed length/offset/type tag, and never grow a pool from
   client-supplied sizes. The authenticated transport reuses only already-vendored crypto primitives; no
   new crate.
3. **Hostile prompts against the served model.** Prompt injection targets the trusted-but-uncomfortable
   weights to escape the session. INV-MODEL + INV-SERVE cap the blast radius to the attacker's own
   session; the confinement is manifest-enforced and must hold under the injection suite with no
   escalation under any input.
4. **Firmware-supplied structures (ADT, boot-args).** Parsed before anything else exists to defend the
   system, on the primary platform, in the most privileged context. Covered above.
5. **Model-weight provenance.** The served weights are trusted-but-huge; a poisoned or swapped blob is a
   supply-chain and integrity concern. Weights are measured against a known digest before use — anchored
   to a hardware quote on x86-64, to a self-reported log on Apple Silicon — and the loader fails closed on
   any malformed or oversized blob.
6. **DMA confinement across many small IOMMUs.** DART is not one translation unit but dozens of
   per-device instances discovered from the ADT, with incompatible PTE formats across SoC generations. A
   single instance left in a permissive state is a full DMA escape. Every discovered instance defaults to
   deny-all from the first commit, and an unrecognized DART variant fails closed rather than falling back.
7. **Hostile data at rest / on disk.** Model-weight blobs and the session/log store are
   attacker-influenceable byte streams parsed in ring 0 or adjacent; the same `#![no_std]`, fuzzed,
   Kani-checked, fail-closed discipline applies.
8. **Platform contract revocation.** An Apple firmware update silently changing a reverse-engineered
   structure is an availability threat with no upstream remedy. Mitigation is pinning a known-good macOS
   stub version on the deployment machine and treating any firmware update as a re-qualification event.
9. **Storage and network bring-up surface.** Reaching a serving deployment on Apple Silicon requires
   in-tree RTKit mailbox, ANS2 NVMe, PCIe, and Ethernet drivers, all clean-room. Each is a large new
   attack surface written from reverse-engineered documentation, and each lands in a driver server with
   bounded device capabilities — never in the kernel.
