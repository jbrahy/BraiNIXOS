# BraiNIX Platform Support Matrix

## Purpose

This document defines the hardware platform requirements for BraiNIX: which platforms are supported, at
what **assurance level**, with which required and recommended CPU features, and with what separation
between development and production environments.

This is an authoritative specification. If code or configuration diverges from this document, the document
must be updated in the same PR that introduces the change.

**Reconciled 2026-08-02** for the Apple-primary platform decision. The previous version of this document
stated "No ARM (AArch64 or AArch32) support" — that is now false, and the reversal is the single most
consequential change in this file.

---

## 1. Supported Platforms

BraiNIX supports exactly **two** platforms, at **different assurance levels**. Naming the platform is
therefore part of describing a deployment; "production BraiNIX" alone is not a meaningful assurance claim.

| | Platform | Role | Assurance |
|---|---|---|---|
| **Primary** | **aarch64 / Apple Silicon** — Mac mini M2 (`Mac14,3`, SoC `T8112`, 32 GB unified memory) | The serving deployment | **Degraded** — INV-BOOT/AS: no measurement, no remote attestation, no sealing |
| **Secondary** | **x86-64 long mode** | Development, CI, and **attested** deployments | **Full** — INV-BOOT holds in all clauses |

Not supported: 32-bit (i386/IA-32), AArch32, RISC-V, generic aarch64 servers (Graviton/Ampere — descoped
2026-08-02), and real or protected mode beyond controlled bootstrap transitions.

Both platforms are **compile-time backends** behind one hardware abstraction layer
([`../architecture/HAL.md`](../architecture/HAL.md)) — never runtime dispatch. Every obligation in this
document must be discharged by both; only the mechanism differs.

### 1.1 The assurance asymmetry, stated plainly

**Deployments requiring remote attestation or sealing must run x86-64.** Apple Silicon has no TPM and none
can be added; the Secure Enclave exposes no PCR-style extend/quote/seal interface to third-party software.
This is structural and permanent — not a gap that closes in a later release. See
[`ATTESTATION_MODEL.md`](ATTESTATION_MODEL.md) and the INV-BOOT/AS exception in
[`../NORTH_STAR.md`](../NORTH_STAR.md).

### 1.2 Page size

| Platform | Base page |
|---|---|
| Apple Silicon | **16 KiB** |
| x86-64 | 4 KiB |
| QEMU `virt` aarch64 (bring-up harness only) | 4 KiB |

The third row is a trap: aarch64 code can pass every harness test at 4 KiB and still be wrong on the
machine it targets. Page size is a HAL parameter (`INV-MEM-009`); see
[`../architecture/MEMORY_MODEL.md`](../architecture/MEMORY_MODEL.md) §12.

---

## 2. Apple Silicon (primary)

### 2.1 Supported hardware

| Model | Identifier | SoC | Status |
|---|---|---|---|
| Mac mini M2 (2023) | `Mac14,3` | `T8112` | **Reference deployment** |

No other Apple model is supported. Each SoC generation has its own AIC revision and DART variants, and
under the no-vendoring rule each must be re-derived; adding a model is a scoped work item, not a
configuration change.

### 2.2 Boot chain and delivery

Apple Silicon boots SecureROM → iBoot1 → iBoot2 → payload. There is no UEFI, no ACPI, no PSCI, and no EL3.
**We never own the first instructions.**

Delivery uses Apple's documented custom-kernel path:

1. Downgrade the volume to **Permissive Security** with `bputil`, from One True Recovery (1TR). Requires
   local admin credentials and **physical presence**, once per machine. FileVault and Activation Lock
   still gate it.
2. Install the payload: `kmutil configure-boot -c <payload> -v <volume>`. The payload is wrapped as an
   **Image4** object under the machine's Secure-Enclave-held **local policy**, and iBoot2 verifies it at
   every boot.

Consequences, stated because they constrain operations:

- A **macOS stub install must remain on disk** (paired recoveryOS and firmware volumes). "Bare metal" here
  means our kernel is the OS, not that Apple software is absent.
- **Headless fleet provisioning is not available** — 1TR requires physical presence for the downgrade.
- The signing root is **Apple's**, and the policy key is **device-local**. This gives genuine
  tamper-resistance for the payload at rest and attests nothing to anyone.

### 2.3 Trusted components we cannot remove (TCB-AS)

**SecureROM, iBoot1, iBoot2, and sepOS** are Apple-signed, immutable, closed-source, and always running.
They are in the TCB by force. This permanently violates the dependency-closure rule on the primary
platform and is recorded as the named exception TCB-AS.

### 2.4 Required platform features

| Obligation | Mechanism | Invariant |
|---|---|---|
| Kernel cannot execute user-mapped pages | PXN | `INV-ARM-002` |
| Kernel cannot implicitly access user pages | PAN | `INV-ARM-002` |
| No-execute mappings for W^X | XN / UXN | `INV-MEM-003` |
| Control-flow integrity | PAC / BTI | `INV-ARM-003` |
| Hardware entropy | RNDR / RNDRRS, **with an explicit failure path** — a failed read blocks crypto start, never falls back silently | `INV-ARM-004`, `INV-BOOT-005` |
| DMA confinement | **DART**, every discovered instance deny-all by default; unknown variant fails closed | `INV-DEV-004`, `INV-DEV-005` |
| Interrupt control | **AIC**, with the FIQ timer path handled outside the controller | `INV-ARM-005` |

### 2.5 Development rig

Required before any hardware bring-up (AS-1):

- The Mac mini M2 in **Permissive Security**.
- A **debug UART cable** for the s5l console — the earliest and simplest console on the SoC.
- **m1n1** installed as a lab instrument (register exploration, payload loading, hypervisor tracing).
  Running m1n1 as a tool is permitted; incorporating its code is not, regardless of license
  (`PROJECT_RULES.md` Rule 6.1a).

The serial console is **development-only**: it is unauthenticated and grants whoever holds the cable
physical-access authority. It must not be present in a production configuration.

### 2.6 Platform stability risk

Everything below the `kmutil`/Image4 flow — boot-args layout, ADT binary format, AIC and DART register
maps, CPU-release sequences — is **reverse-engineered with no compatibility promise from Apple**, and has
changed across iBoot and macOS releases.

**Operational policy:** pin a known-good macOS stub version on the deployment machine, and treat any
firmware update as a **re-qualification event**, not routine maintenance. Under the no-vendoring rule,
every break is re-derived in-tree rather than pulled from upstream.

---

## 3. x86-64 (secondary — attested)

Retained as the development and CI target, and as the **only** platform where INV-BOOT holds in full.
Sections 3.1–3.5 are unchanged from the original specification and remain accurate.

### 3.1 Minimum CPU generations

| Vendor | Generation | Year | Rationale |
|--------|-----------|------|-----------|
| Intel | Haswell (4th gen) | 2013 | Earliest generation with both SMEP and SMAP |
| AMD | Zen 1 (Ryzen 1000 / EPYC Naples) | 2017 | Earliest AMD generation with both SMEP and SMAP |

CPUs older than these lack the hardware enforcement BraiNIX requires. Running on unsupported hardware is
not a degraded mode — it is a **refused boot**. The bootloader checks every required feature via CPUID
before kernel entry; on absence it prints a diagnostic to serial and halts.

### 3.2 Required CPU features

| Feature | Purpose | Detection | Invariant |
|---------|---------|-----------|-----------|
| SMEP | Prevent kernel execution of user-mapped pages | CPUID.07H:EBX[7] | `INV-X86-002` |
| SMAP | Prevent implicit kernel access to user-mapped pages | CPUID.07H:EBX[20] | `INV-X86-003` |
| NX / XD | No-execute protection for W^X | CPUID.80000001H:EDX[20] | `INV-MEM-003` |
| RDRAND or RDSEED | Hardware entropy for CSPRNG seeding | CPUID.01H:ECX[30] or CPUID.07H:EBX[18] | `INV-BOOT-005` |
| Long Mode | 64-bit operation | CPUID.80000001H:EDX[29] | `INV-X86-001` |

Enforcement: SMEP and SMAP are enabled in CR4 by the bootloader before kernel entry; NX via IA32_EFER bit
11. RDRAND absence is fatal — the kernel halts rather than operating with weak entropy.

### 3.3 Recommended CPU features

| Feature | Available on | Purpose | Detection |
|---------|-------------|---------|-----------|
| CET/IBT | Intel Tiger Lake+ (2020) | Hardware CFI for indirect branches | CPUID.07H:EDX[20] |
| TME | Intel Ice Lake+ server (2019) | Transparent memory encryption | CPUID.07H:ECX[13] |
| SME | AMD EPYC (Zen 1+) | Transparent memory encryption | CPUID.8000001FH:EAX[0] |
| RDSEED | Intel Broadwell+ / AMD Zen 1+ | Higher-quality entropy for reseeding | CPUID.07H:EBX[18] |
| IBRS/IBPB | Microcode on Haswell+ / Zen 1+ | Spectre v2 mitigation | CPUID.07H:EDX[26] |
| STIBP | Microcode | SMT side-channel mitigation | CPUID.07H:EDX[27] |

### 3.4 Unsupported: CPL0 shadow stack

Intel CET defines IBT and Shadow Stack. BraiNIX supports **IBT** where available (Tiger Lake+). **Ring-0
shadow stack is not supported on shipping silicon** and will not be implemented until hardware with
verified CPL0 shadow-stack capability is available and tested. Ring-3 shadow stack exists on Tiger Lake+;
IBT is independent of shadow stack. Documented explicitly per Rule 12.5 — security claims must be honest
about hardware constraints.

### 3.5 Microcode requirements

Spectre v1 and v2 require microcode updates on affected processors.

**Intel**

| Generation | F-M-S | Minimum microcode | Mitigations |
|-----------|-------|-------------------|-------------|
| Haswell | 06-3CH, 06-45H, 06-46H | 0x28 | IBRS, IBPB, LFENCE serializing |
| Broadwell | 06-3DH, 06-47H, 06-56H | 0x2000065 | IBRS, IBPB, LFENCE serializing |
| Skylake | 06-4EH, 06-5EH | 0xCC | IBRS, IBPB, STIBP, LFENCE serializing |
| Coffee Lake | 06-9EH | 0xCA | IBRS, IBPB, STIBP, SSBD, LFENCE serializing |
| Tiger Lake | 06-8CH, 06-8DH | 0xA4 | IBRS, IBPB, STIBP, SSBD, CET-IBT |

**AMD**

| Generation | Family-Model | Minimum microcode | Mitigations |
|-----------|-------------|-------------------|-------------|
| Zen 1 | 17h-01h | 0x08001137 | IBPB, LFENCE dispatch-serializing |
| Zen 2 | 17h-31h | 0x0830107A | IBPB, IBRS, STIBP, SSBD, LFENCE dispatch-serializing |
| Zen 3 | 19h-21h | 0x0A201016 | IBPB, IBRS, STIBP, SSBD, LFENCE dispatch-serializing |

The bootloader reads the microcode revision from MSR 0x8B (IA32_BIOS_SIGN_ID) and compares against the
minimum for the detected CPU. Older microcode is a **refused boot**, not a degraded mode.

---

## 4. Development environments

### 4.1 QEMU x86-64 (primary development target today)

```
qemu-system-x86_64 \
  -cpu qemu64,+smep,+smap,+nx,+rdrand,+rdseed \
  -machine q35 \
  -m 256M \
  -nographic \
  -serial mon:stdio
```

The `qemu64` base model with explicit feature flags ensures CPUID checks pass in emulation; `q35` provides
a modern chipset with IOMMU emulation.

**Software TPM (swtpm)** — development attestation only:

```
swtpm socket \
  --tpmstate dir=/tmp/brainix-tpm \
  --ctrl type=unixio,path=/tmp/brainix-tpm/swtpm.sock \
  --tpm2 --log level=0
```

attached via `-chardev socket,id=chrtpm,path=…` + `-tpmdev emulator,id=tpm0,chardev=chrtpm` +
`-device tpm-tis,tpmdev=tpm0`. Wired at P2-T9 (`c01d0ab`).

### 4.2 QEMU `virt` aarch64 (bring-up harness)

Used to develop the aarch64 **core** — exception levels, MMU, generic timers, context switch, SVC entry —
with a working console, before facing hardware where nothing works until the UART does. Uses GICv3 and
PL011, **neither of which exists on the primary platform**; these backends are harness-only and are not
product code.

Runs at 4 KiB pages. See §1.2 — this harness cannot validate 16 KiB behavior.

### 4.3 Docker development container

Runs without `--privileged`, with only the minimum Linux capabilities for QEMU:

- `--cap-drop=ALL`
- `--cap-add=SYS_RAWIO` (QEMU KVM access, when available)
- `--security-opt=no-new-privileges`

When KVM is unavailable (CI), QEMU runs in full emulation (TCG) with no special capabilities.

---

## 5. Production vs development separation

| Property | Development | Production (x86-64) | Production (Apple Silicon) |
|----------|------------|---------------------|----------------------------|
| **Execution environment** | QEMU (q35 / `virt`, TCG or KVM) | Bare-metal x86-64 with UEFI Secure Boot | Mac mini M2 in Permissive Security, Image4 payload via `kmutil` |
| **Root of trust** | None (emulated) | UEFI Secure Boot + hardware TPM 2.0 | **Apple's** SecureROM/iBoot + device-local SEP policy |
| **Measurement** | swtpm (software emulation) | Hardware TPM 2.0 PCRs | **None** — software-only log, self-reported |
| **Remote attestation** | Flow rehearsal only | Trust-anchor-backed quote | **None** (INV-BOOT/AS) |
| **Sealing** | No | Yes | **None** (INV-BOOT/AS) |
| **Signing keys** | Development keys (local keyring) | Production keys (HSM-stored) | Production keys (HSM-stored) for the release signature; Apple's device-local policy for payload integrity |
| **Binary marker** | `DEV_BUILD` present | `DEV_BUILD` absent | `DEV_BUILD` absent |
| **IOMMU** | QEMU intel-iommu / AMD-vi emulation | Hardware VT-d / AMD-Vi | **DART** — all instances deny-all by default |
| **Serial console** | Present | Absent | **Must be absent** (§2.5) |
| **Security claims** | Testing and behavioral validation only | Full structural guarantees | Full structural guarantees **except** measurement, attestation, and sealing |

### Structural enforcement

- A binary built with the `DEV_BUILD` marker is rejected by the production kernel — a compile-time
  structural distinction, not a runtime convention.
- Development signing keys cannot produce signatures accepted by the production verification path. Key
  material never overlaps (`INV-BOOT-003`).
- swtpm results are never presented as production trust. Development and production PCR values use
  distinct trust anchors.
- **On Apple Silicon, no build may emit an attestation claim at all** (`INV-BOOT-AS-001`). The absence of
  attestation is enforced, not merely expected: the serving protocol must not define a field the platform
  cannot populate honestly.

---

*Last reconciled: 2026-08-02 (Apple-primary platform decision).*
*This document is the authoritative specification for BraiNIX platform support.*
