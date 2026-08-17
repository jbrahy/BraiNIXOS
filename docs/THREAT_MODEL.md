# BraiNIX threat model

Companion to NORTH_STAR.md. The north-star states the invariants as a contract. This document states who
the contract defends against, what is trusted to uphold it, how each invariant is verified, and what a
violation costs. Phasing and status live in ROADMAP.md.

---

> **RANKING CHANGE, 2026-08-17. The contract this document defends is now subordinate to throughput.**
>
> The north-star inverted its ranking: performance outranks the invariants, and each invariant yields to a
> measured throughput win recorded in *What this ranking costs*. This document does **not** change what an
> attacker can do — the attacker model below is unaffected by an owner decision — but it changes what the
> system promises to stop.
>
> **How to read this document now.** Every "Consequence of compromise" below remains accurate. What is no
> longer guaranteed is that the corresponding control will be present. Before relying on any control here,
> check the north-star ledger for that property's status: `DEFAULT` means it holds, `TRADED` means it has
> been given up for a recorded win, `AT RISK` means a design is pending that would give it up.
>
> **The one thing this inversion cannot do is make an attack go away.** A trade removes a control, not the
> adversary. The threat model is therefore the *stable* half of the pair and the north-star is the
> negotiable half — which is the opposite of how the two were related before 2026-08-17, and is worth
> holding onto: it is what stops a performance decision from quietly rewriting the attacker.

BraiNIX **serves LLM inference to remote network clients**, which makes the inbound serving path the
largest attack surface in the system. As of the owner decision of 2026-08-02 the **primary platform is
Apple Silicon** (Mac mini M2 Pro, `Mac14,12`, SoC `T6020`); as of **2026-08-03 it is the only platform** —
x86-64 was dropped, and the x86-64 code remains in tree solely as a frozen reference implementation that
nothing is deployed from. This document is written around **one** platform. Claims that used to be marked
"degraded on the primary platform" are now simply the attacker model: there is no second machine, no
attested variant, and no configuration in which the losses below do not apply.

## Attacker model

Assumed capabilities of the adversary:

- Is a remote network client, or controls one. Supplies arbitrary inbound bytes to the serving path:
  connection setup, authentication attempts, and — once authenticated — arbitrary request payloads and
  arbitrary prompt content.
- Drives the served model with adversarial prompts, including content crafted to elicit privilege
  escalation, to exfiltrate another client's session or the weights, or to make the model reach outside
  its serving channel.
- Supplies arbitrary disk and filesystem content, including malformed model-weight blobs and session/log
  data — and, given physical possession of the machine, its storage, or a backup of it, **reads** arbitrary
  disk content, including the credential store's backing blocks.
- Fully controls any userspace process it compromises, including device-driver servers and the serving
  front end.
- Records the full ciphertext of every session it can observe and retains it indefinitely, against the
  possibility of obtaining a key later.
- Observes timing and any published artifact (payload image, PCR predictions where published, source).
- May present a modified or hostile Apple Device Tree, boot-args structure, or any
  other firmware-supplied blob to the kernel, to the extent it can influence the boot environment.

Assumed not available to the adversary:

- Defeating the CPU or the IOMMU (the DART instances) as hardware, or breaking Ed25519, SHA-256,
  HKDF-SHA256, ChaCha20, or Poly1305 as primitives. *(There is no TPM in the model, because there is none
  in the machine.)*
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

- The kernel and the boot stub, including the kernel's **credential store**, which holds every client and
  admin pre-shared key — **in plaintext on disk**, see *The serving transport* below.
- The CPU and the IOMMU (the DART instances).
- The Ed25519 release-signing key, and the **Ed25519 verification stack** that decides whether a signature
  over a release is accepted: `ed25519-dalek`, `curve25519-dalek`, `fiat-crypto`, `subtle`, vendored
  permanently and verify-only under the named crypto exception in NORTH_STAR.md.
- The serving transport's cryptographic primitives — **SHA-256, HKDF, ChaCha20, Poly1305** — which are
  specified to be in-tree; `sha2` and `chacha20` are still vendored until that reimplementation lands.
- The in-tree model weights of the served model and the auditor.
- ~~**x86-64 only:** the TPM 2.0, and the UEFI Secure Boot and measured-boot chain.~~ — **removed
  2026-08-03 with the platform.** No TPM and no Secure Boot chain is in the TCB, because neither exists on
  the machine. The trusted set shrank here, and the shrinkage bought nothing: what those components
  provided is not replaced, it is gone (see INV-BOOT below).
- **TCB-AS, unavoidable:** **SecureROM**, **iBoot1**, **iBoot2**, and **sepOS**.

Two of those entries are vendored code, and they are there for opposite reasons. The **Ed25519
verification stack** is permanent and deliberate: it decides whether a signature over a release is
accepted, so a defect in its point decompression or verification equation means **accepting a forged
release**, and every guarantee INV-BOOT makes rests on a check that silently returned true. No secret
passes through it — there is no key to leak and no side-channel argument for owning it — so the entire
cost of the exception is correctness. That is also the reason it stays: `fiat-crypto`'s field arithmetic
is machine-verified against a formal specification, and a hand-written replacement would trade a
machine-checked property for an unchecked one. Owning the code would satisfy the dependency-closure rule
and *lower* the assurance that rule exists to protect. The residual gap is stated rather than closed —
Kani cannot be produced for code we do not own, so its Full-tier row in
`docs/security/SECURITY_INVARIANTS.md` §16 names those two artifacts as missing. `sha2` and `chacha20` are
the opposite case: vendored today, specified to be reimplemented in-tree, and tracked debt until they are.

The credential store is not a new member of the trusted set — it is in-kernel, so it was always inside
"the kernel and the boot stub." It is named separately because that label is too coarse for the one
component whose disclosure is retroactive: it holds the secret that authenticates every client, and its
at-rest exposure is modelled below.

### TCB-AS: the components we cannot remove

We never own the first instructions. SecureROM, iBoot1, and iBoot2 are Apple-signed and
immutable; sepOS always runs. All four are closed source, unauditable by us, and unreplaceable. They are
in the TCB by force, not by choice, and they permanently violate the north-star's dependency-closure rule.
With one platform there is no build of BraiNIX that does not include them.

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
- Every userspace process, including the serving front end and any operator console. `servd` is outside
  the TCB and stays there: it terminates the transport, holds session keys, and mints every per-session
  capability, so a defect in it crosses all tenants at once — which is why
  `docs/security/SECURITY_INVARIANTS.md` §16 puts it at **Full** proof tier. That is the alternative to
  trusting it, not evidence that we do. Proof tier tracks blast radius, not TCB residency; §16 assigns
  Full to parsers living inside Reduced-tier drivers for the same reason.
- Every disk byte, including model-weight blobs and the session/log store.
- **Every byte of firmware-supplied data on Apple Silicon** — the ADT, boot-args, and any structure iBoot
  hands us. Firmware we do not control gets exactly the treatment network bytes get.
- Every device driver, including the GPU driver. Drivers run as ordinary servers with bounded device
  capabilities and no special standing.

## Per-invariant verification and blast radius

**INV-AUTH.** How we know: Kani proofs on the capability and IPC paths, backed by types that make a
forged or widened capability unrepresentable. If violated: a process or a client gains authority it was
never granted; this is full escalation and is the worst case the design exists to prevent.

**INV-MEM.** How we know: a structural page-table invariant plus the absence of any heap allocator in the
kernel image; model weights and KV-cache occupy fixed reserved regions, not a growable allocator. If
violated: W^X loss enables code injection in the affected domain; a reintroduced allocator reopens a
whole class of use-after-free and allocator-corruption bugs the fixed-pool discipline forecloses.
Platform note: the base page is **16 KiB**. Any page-size assumption that leaks into supposedly
architecture-neutral memory code is an INV-MEM defect, not a portability inconvenience — and with the
4 KiB QEMU `virt` harness cancelled on 2026-08-03, a hardcoded **16 KiB** is now the likelier defect and
the harder one to catch, because nothing left in CI disagrees with it.

**INV-IPC.** How we know: types that make a shared-memory channel or async queue unrepresentable in tree,
plus proofs on the rendezvous path. If violated: shared mutable state between domains reopens TOCTOU and
confused-deputy patterns the synchronous model forecloses.

**INV-BOOT.** No longer platform-split — there is one platform, and INV-BOOT/AS has become the rule rather
than an exception (NORTH_STAR.md).

How we know, and it is a short list: a **reproducible build** any third party can reproduce bit for bit; an
**Ed25519 release signature**; **payload-at-rest integrity** enforced by iBoot2 against the machine's
Secure-Enclave-held device-local policy; and a **self-reported software measurement log** that is a
debugging aid and is never evidence.

**Measurement, remote attestation, and sealing are structurally unavailable, permanently.** If violated:
**there is no detection mechanism.** A remote client cannot distinguish a genuine BraiNIX boot from a
compromised one, and a kernel compromised early can report an arbitrary measurement log. This is the
largest residual risk in the system and it is unmitigable.

~~Deployments needing attestation run x86-64.~~ **That escape hatch is deleted, not repointed** — the
platform it named no longer exists. There is nowhere to move such a deployment, and no later phase closes
this. The absence of sealing has a second consequence, now unconditional: the credential store is
**plaintext at rest** — see *The serving transport* below.

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
that a bad model cannot defeat by reasoning. Anchoring note: the weight digest is
anchored only to the self-reported software measurement log. There is no hardware quote to anchor it to,
so it detects corruption and accidental substitution and **not** an attacker who already controls the
kernel.

**INV-AUDIT.** How we know: the auditor's frozen capability manifest is the proof. It physically cannot
name the capabilities it lacks, so it cannot spawn, mutate the kernel, or reach the network regardless of
what its model decides. It observes the serving stack — connections, capability grants, request/response
boundaries — and reports. If violated (only possible via a manifest error): audit visibility is lost;
privilege is not, by construction.

**INV-GPU** *(active as of 2026-08-02; the discrete-accelerator case was cancelled with the x86-64 platform on 2026-08-03)*. How we know: the
accelerator's DMA windows are confined by IOMMU mappings the driver cannot widen, and the driver holds
only bounded device capabilities. If violated: a driver or device DMA escapes its window into kernel or
cross-domain memory — which is why the IOMMU confinement, not driver correctness, is the control.

**Apple's AGX GPU is in scope** (owner ruling: "GPU and CPU at maximum"). This changes INV-GPU from a
stated target into a load-bearing control, because using AGX means **loading and running an Apple-signed,
closed, unauditable firmware blob on a coprocessor with DMA access to system memory** — the **TCB-AS/GPU**
exception, conditionally signed by the owner on 2026-08-02.

That firmware differs from the rest of TCB-AS in a way that matters for this threat model: SecureROM and
iBoot run once, at boot, and then stop. **GPU firmware runs concurrently with our kernel, for the entire
life of the system, driven by data derived from client requests.** An attacker who can influence prompts
can influence GPU workloads. The defenses are, in order:

1. **DART confinement** — every instance fronting the GPU deny-all by default; the window is programmed by
   the granting authority and `gpud` cannot widen it (`INV-DEV-004`, `INV-DEV-006`). Proven before any
   firmware is loaded (AS-5-T0 gates AS-5-T2). This is the whole defense; everything else is depth.
2. **`gpud` is an ordinary server** holding only `CapGpu` — no ambient device authority, no spawn, no
   network.
3. **GPU output is hostile input.** Completion records and any data the GPU writes back are parsed
   fail-closed, fuzzed, and Kani-checked like network bytes (`INV-PARSE-001`).
4. **Single-tenant residency.** Model weights are mapped into the GPU's DART window read-only and
   permanently — they are not client data and there is nothing to unmap between sessions. KV cache is
   mapped strictly per session: mapped on session entry, unmapped and flushed on exit, and **never two
   tenants resident simultaneously**. The GPU time-slices between clients and **cross-tenant batching is
   forbidden** (`INV-SERVE-006`). This is what keeps INV-SERVE intact with an accelerator in the path, so
   **no INV-SERVE exception is needed** — isolation on the GPU is the same isolation as everywhere else.
   It is paid for in throughput rather than in invariants: the GPU's payoff is prefill acceleration plus
   time-sliced multi-client serving, not the concurrency win batching would have bought.

**The exception is conditional, and the conditions are its whole content.** TCB-AS/GPU is in force now, so
AGX design and implementation may proceed, but five preconditions must all be green **before GPU firmware
is ever loaded**; they are AS-5-T0's acceptance criteria.

1. Every GPU-fronting DART instance defaults to deny-all (`INV-DEV-004`).
2. A Kani proof on **the DART backend's IOMMU trait** that its API surface admits no widening
   operation, proving no consumer — `gpud` included — can widen its own DMA window (`INV-DEV-006`). The
   proof is an obligation of the confinement, not of the driver.
3. GPU completion records are fuzzed and Kani-checked as hostile input (`INV-PARSE-001`).
4. The tenant mapping policy above is enforced: weights read-only and permanent, KV cache per session,
   never two tenants resident (`INV-SERVE-006`).
5. No iBoot-locked DART on the GPU path — or, if one exists, its locked semantics honestly represented in
   **the DART backend's IOMMU trait** rather than papered over.

*(History, 2026-08-03: preconditions 2 and 5 named the HAL IOMMU trait when signed on 2026-08-02. The
HAL was cancelled the next day, so the criteria now name the DART backend's own IOMMU trait directly.
The obligation is unchanged in scope; only its home is named differently.)*

**If any precondition proves unsatisfiable on real hardware, the exception self-voids and AS-5 stops.**
Until all five are green, no build ships with the GPU enabled. That is the correct failure mode: the
alternative is loading opaque firmware into a DMA-capable coprocessor on the strength of a confinement we
could not prove.

Standing bars, enforced in CI and never allowed to regress:

- Auditor true-positive rate above 95% on the released CTF corpus, measured against the serving stack.
- Machine-checked coverage of kernel invariants driven toward 80%.
- Zero external dependencies in cargo metadata is the target; the current crate list is tracked debt that
  only decreases. The inference engine, the platform backends, and the GPU driver add none.

## The serving transport: pre-shared keys, enrollment, and the admin channel

Owner decision, 2026-08-02. The BSP transport uses **pre-shared per-client keys** with HKDF-SHA256
session-key derivation and ChaCha20-Poly1305 records. There is **no asymmetric cryptography in the serving
transport at all**: mutual authentication is proof of possession of the pre-shared key in both directions,
not a signature and not a key agreement. The Ed25519 verification stack named in the TCB above exists for
INV-BOOT's release signature and is reachable from no network path.

**What a stolen PSK yields.** A client PSK is the whole of that client's identity. An attacker holding one
opens sessions as that client and decrypts and forges that client's records. It does **not** yield another
client's sessions — every client has its own key, and INV-SERVE's confinement is enforced after
authentication regardless of which key authenticated, so a stolen key buys the thief exactly the authority
of the client it was stolen from. A stolen *admin* PSK yields the `CapAdmin` verb set and nothing outside
it; that blast radius is bounded below.

**What the ratchet denies.** Session key *n* is derived from chain key *n*; the chain then advances and
chain key *n* is deleted (`INV-BOOT-007`). Once the chain has advanced past a session, that session's
traffic is no longer derivable from anything the system still holds, so a later disclosure of the PSK does
not decrypt it. Forward secrecy from symmetric primitives alone is why dropping asymmetric crypto from the
transport costs nothing here — *once the ratchet ships*.

**Stated plainly: until the ratchet ships there is no forward secrecy.** A disclosed PSK retroactively
decrypts every recorded session for the entire lifetime of that key. An attacker who records ciphertext
today and obtains the key at any later date reads all of it. This is the current state of the system, not
a hypothetical future risk, and it compounds with the at-rest exposure below.

**Key distribution and enrollment.** Keys are enrolled at runtime and never compiled in (`INV-BOOT-006`,
`INV-BUILD-004`). There are exactly two enrollment paths, and each is its own attacker surface:

- **Over the admin channel**, which makes an enrollment exactly as trustworthy as the `CapAdmin` session
  that requested it. An attacker holding an admin PSK can enroll a client key of its own choosing and
  thereafter authenticate as a legitimate client. Enrollment and revocation are attributable events
  (`INV-AUTH-008`), so this is visible in the audit record — but visibility is detection after the fact,
  not prevention.
- **Over the serial console**, which grants whoever holds the cable physical-access authority. The
  break-glass admin PSK is provisioned this way and only this way (`INV-BOOT-008`). It is long-lived by
  construction and cannot be replaced over the network, so its disclosure is repairable only by physical
  presence.

**Ratchet desynchronization is an availability failure, not a confidentiality one.** If the two ends
disagree about chain position — a lost record, a crash between advance and use, a credential store
restored from an older state — records do not decrypt and the session fails closed (`INV-FAIL-003`).
Nothing is disclosed; the client is locked out. Recovery is re-enrollment, and if the key that would
authorize that re-enrollment is itself desynchronized, recovery is over the serial console and nowhere
else. That is the intended failure mode, and it is why the serial path is compiled in unconditionally: a
ratchet with no out-of-band repair path is a remote self-destruct.

**The credential store at rest: plaintext, permanently.** Owner ruling, 2026-08-02, made unconditional on
2026-08-03. The ruling used to have two halves that tracked the platform's attestation capability;
~~the x86-64 half — *the credential store is specified to be TPM-sealed*~~ — **died with that platform.**
It was never implemented, and there is now no target on which it could be.

The credential store is **plaintext at rest**. Sealing means binding a secret to a measured boot state, and
the only platform has neither the measurement nor the hardware to bind against. iBoot2's device-local
policy protects the *payload* at rest and seals nothing of ours. `src/kernel/src/boot/credential_store.rs`
persists to disk and seals nothing, `INV-BOOT-006` does not require sealing, and **no version of P2-T13
closes this** — it is not unimplemented work, it is unavailable work.

The consequence, unsoftened: **anyone who obtains the disk obtains every client and admin pre-shared key.**
Combined with the forward-secrecy gap above, physical possession of the machine — or of a decommissioned
drive, or of a backup of its storage — retroactively decrypts every session ever recorded from it. This
ranks with the absence of remote attestation as an unmitigable cost, and it has the same structural cause:
the platform cannot bind a secret to a state it cannot measure. ~~Deployments that cannot accept it run
x86-64.~~ **There is nowhere to send them.** A deployment that cannot accept plaintext keys at rest cannot
use BraiNIX; the only mitigations are physical control of the machine and its media, and treating disk
disposal as a key-compromise event.

**The admin channel's blast radius.** Administration is a second session *type* on the same authenticated
transport, gated by `CapAdmin` and exposing a fixed, enumerated verb set — enroll-key, revoke-key,
load-weights, read-audit-log, restart-server, reboot (`INV-AUTH-009`). Six verbs, frozen at accept. A
compromised admin session can therefore enroll a key it controls, revoke any client's key, replace the
served weights, read the audit log, and restart or reboot the machine. That is a serious compromise:
weight replacement substitutes the model every client is talking to, and mass revocation denies service to
every legitimate client at once.

What it *cannot* do is what bounds it. No verb executes a command, reads or writes an arbitrary file,
opens a network connection, or grants a capability outside the six. There is no `rotate` verb — rotation
is `enroll-key` followed by `revoke-key`, so it names no authority the set does not already contain. And
neither `enroll-key` nor `revoke-key` will touch the break-glass identity (`INV-BOOT-008`), so a
compromised admin session **cannot lock the owner out**: physical presence at the serial console wins.

**"Not a shell" is a security property, not an ergonomic one.** A general-purpose remote shell can do
whatever the process hosting it can do. Its blast radius is not enumerable, which means it cannot be
reviewed and cannot be bounded — ambient authority wearing an admin badge, which is the exact thing the
capability model exists to forbid. The enumerated set is what makes the paragraph above possible to write
at all: the compromise is bad, and it is *finite*, and the finiteness is checkable by reading a
compile-time table. A verb needing authority the six do not cover requires a new named capability, never a
widened `CapAdmin`.

## Firmware-supplied input

A hostile-input class introduced by the platform decision, ranked alongside network input
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

The early console is the SoC's Samsung-lineage (s5l) UART, reached over a debug cable.
It is a development interface, is not authenticated, and grants whoever holds the cable physical-access
authority. It must not be present in any production configuration.

If a future feature reintroduces a consent-gated action on the local system, it re-inherits the
kernel-intercepted secure-attention-sequence design (a kernel context the console server cannot observe
or forge), so any such consent rests on the kernel, not on console correctness.

## Deployment threat profile (inbound-serving · multi-client · network-facing)

This section re-ranks the general model above for the deployment BraiNIX ships in, so design effort is
spent where the residual risk concentrates. The general model remains authoritative.

**Deployment, stated.** The reference deployment is a **Mac mini M2 Pro (`Mac14,12`, T6020, 32 GB unified
memory)** running BraiNIX as the sole OS, delivered as an Image4 payload via `kmutil` under Permissive
Security. **Performance is the top-ranked concern** (owner decision, 2026-08-17): CPU and AGX GPU at
maximum. The serving path is CPU-first by ordering, with the GPU landing at AS-5. Single-stream decode is
bounded by unified-memory bandwidth on both engines.

**Cross-tenant batching moved from forbidden to candidate on 2026-08-17.** It was previously ruled out by
INV-SERVE, and clients took turns rather than sharing a batch. It is now the first-ranked candidate trade
in the north-star, because it is the only lever that amortises the weight read — the thing that *is* the
bandwidth ceiling — across concurrent requests. **If it is taken, the isolation between concurrent clients
stops being structural and becomes a property of the batching code**, and a batching defect becomes a
cross-tenant data leak rather than a crash. Threat 4 below (hostile prompts) changes character
correspondingly: a prompt that escapes its session boundary would reach a co-batched client rather than
only its own state. Check the north-star ledger for its current status before assuming either posture. ~~x86-64 under QEMU remains the development, CI, and attested-deployment target.~~ —
**x86-64 was dropped on 2026-08-03**; the code remains in tree as a frozen reference implementation and is
not a deployment of any kind. **This is the only deployment there is.** The
runtime profile is **network-facing with a single authenticated, capability-gated inbound serving
socket**, serving one or more remote clients whose sessions are mutually isolated.

**Dominant threats, re-ranked for this deployment (highest first):**

1. **No remote attestation, anywhere.** Ranked first because it is unmitigable and it
   changes what every other control is worth. A client cannot verify what it is talking
   to, and an early kernel compromise is undetectable from outside. Every downstream guarantee is
   conditional on a boot state that cannot be proven. ~~Deployments that cannot accept this must run
   x86-64.~~ — **deleted 2026-08-03 with the platform; there is nowhere to send them.** See INV-BOOT.
2. **Credential-store disclosure, retroactively.** Ranked second because it shares the first entry's
   structural cause and its unmitigability: the platform cannot bind a secret to a state it cannot
   measure. The credential store is plaintext at rest, so obtaining the disk obtains
   every client and admin pre-shared key; until the HKDF ratchet ships there is no forward secrecy, so
   those keys also decrypt every session an attacker recorded earlier. Physical possession of the machine,
   a decommissioned drive, or a backup is therefore a total, retroactive loss of serving confidentiality.
   ~~On x86-64 sealing is specified but not yet implemented… the difference is that x86-64 can close it.~~
   — **that difference is gone.** Nothing can close it. See *The serving transport* above.
3. **Hostile remote clients and the inbound protocol.** The connection/auth/request path parses
   attacker-controlled bytes reachable from the network. It must be `#![no_std]`, fuzzed, and
   Kani-checked, fail-closed on any malformed length/offset/type tag, and never grow a pool from
   client-supplied sizes. The transport is pre-shared-key only — HKDF-SHA256 derivation,
   ChaCha20-Poly1305 records, no asymmetric crypto and no new crate.
4. **Hostile prompts against the served model.** Prompt injection targets the trusted-but-uncomfortable
   weights to escape the session. INV-MODEL + INV-SERVE cap the blast radius to the attacker's own
   session; the confinement is manifest-enforced and must hold under the injection suite with no
   escalation under any input.
5. **Firmware-supplied structures (ADT, boot-args).** Parsed before anything else exists to defend the
   system, on the primary platform, in the most privileged context. Covered above.
6. **Model-weight provenance.** The served weights are trusted-but-huge; a poisoned or swapped blob is a
   supply-chain and integrity concern. Weights are measured against a known digest before use — anchored
   to a self-reported log and to nothing stronger — and the loader fails closed on
   any malformed or oversized blob.
7. **DMA confinement across many small IOMMUs.** DART is not one translation unit but dozens of
   per-device instances discovered from the ADT, with incompatible PTE formats across SoC generations. A
   single instance left in a permissive state is a full DMA escape. Every discovered instance defaults to
   deny-all from the first commit, and an unrecognized DART variant fails closed rather than falling back.
8. **Hostile data at rest / on disk.** Model-weight blobs and the session/log store are
   attacker-influenceable byte streams parsed in ring 0 or adjacent; the same `#![no_std]`, fuzzed,
   Kani-checked, fail-closed discipline applies.
9. **Platform contract revocation.** An Apple firmware update silently changing a reverse-engineered
   structure is an availability threat with no upstream remedy. Mitigation is pinning a known-good macOS
   stub version on the deployment machine and treating any firmware update as a re-qualification event.
10. **Storage and network bring-up surface.** Reaching a serving deployment on Apple Silicon requires
    in-tree RTKit mailbox, ANS2 NVMe, PCIe, and Ethernet drivers, all clean-room. Each is a large new
    attack surface written from reverse-engineered documentation, and each lands in a driver server with
    bounded device capabilities — never in the kernel.
