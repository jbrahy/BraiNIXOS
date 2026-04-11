# Brainix Platform Support Matrix

## Purpose

This document defines the hardware platform requirements for Brainix. It specifies the supported architecture, CPU generation requirements, required and recommended CPU features, microcode baselines, and the separation between development and production environments.

This is an authoritative specification. If code or configuration diverges from this document, the document must be updated in the same PR that introduces the change.

---

## 1. Supported Architecture

Brainix supports **x86-64 long mode only**.

- No 32-bit (i386/IA-32) support.
- No ARM (AArch64 or AArch32) support.
- No RISC-V support.
- No real mode or protected mode operation beyond controlled bootstrap transitions.

Single architecture focus enables deep hardware security integration (SMEP, SMAP, CET/IBT, NX, KPTI) without abstraction layers that dilute security guarantees.

---

## 2. CPU Generation Requirements

### Minimum Supported Generations

| Vendor | Generation | Year | Rationale |
|--------|-----------|------|-----------|
| Intel | Haswell (4th gen) | 2013 | Earliest generation with both SMEP and SMAP support |
| AMD | Zen 1 (Ryzen 1000 / EPYC Naples) | 2017 | Earliest AMD generation with both SMEP and SMAP support |

CPUs older than these generations lack the hardware enforcement features Brainix requires for structural security. Running Brainix on unsupported hardware is not a degraded mode -- it is a refused boot.

### Boot Rejection

The Brainix bootloader checks for all required CPU features via CPUID before transferring control to the kernel. If any required feature is absent, the bootloader prints a diagnostic message to the serial console and halts. The kernel never executes on unsupported hardware.

---

## 3. Required CPU Features

All features in this table must be present for Brainix to boot. The bootloader verifies each feature via CPUID before kernel entry.

| Feature | Purpose | Detection Method | Invariant |
|---------|---------|-----------------|-----------|
| SMEP (Supervisor Mode Execution Prevention) | Prevent kernel execution of user-mapped pages | CPUID.07H:EBX.SMEP[bit 7] | INV-X86-002 |
| SMAP (Supervisor Mode Access Prevention) | Prevent implicit kernel access to user-mapped pages | CPUID.07H:EBX.SMAP[bit 20] | INV-X86-003 |
| NX (No-Execute / XD) | No-execute page protection for W^X enforcement | CPUID.80000001H:EDX.NX[bit 20] | INV-MEM-003 |
| RDRAND or RDSEED | Hardware entropy source for CSPRNG seeding | CPUID.01H:ECX.RDRAND[bit 30] or CPUID.07H:EBX.RDSEED[bit 18] | INV-BOOT-005 |
| Long Mode (LM) | 64-bit operation | CPUID.80000001H:EDX.LM[bit 29] | INV-X86-001 |

### Enforcement

- SMEP is enabled in CR4 by the bootloader before kernel entry.
- SMAP is enabled in CR4 by the bootloader before kernel entry.
- NX is enabled via the IA32_EFER MSR (bit 11) by the bootloader before kernel entry.
- RDRAND absence is fatal. The kernel halts rather than operating with weak entropy.
- Long Mode is implicitly required by the x86-64 execution environment.

---

## 4. Recommended CPU Features

These features are used when available but are not required for boot. The kernel detects them at runtime and enables them if present.

| Feature | Available On | Purpose | Detection Method |
|---------|-------------|---------|-----------------|
| CET/IBT (Indirect Branch Tracking) | Intel Tiger Lake+ (11th gen, 2020) | Hardware control-flow integrity for indirect branches | CPUID.07H:EDX.CET_IBT[bit 20] |
| TME (Total Memory Encryption) | Intel Ice Lake+ (10th gen server, 2019) | Transparent memory encryption against physical attacks | CPUID.07H:ECX.TME[bit 13] |
| SME (Secure Memory Encryption) | AMD EPYC (Zen 1+) | Transparent memory encryption against physical attacks | CPUID.8000001FH:EAX.SME[bit 0] |
| RDSEED | Intel Broadwell+ / AMD Zen 1+ | Higher-quality hardware entropy (reseeding source) | CPUID.07H:EBX.RDSEED[bit 18] |
| IBRS/IBPB (Indirect Branch Prediction Barrier) | Via microcode update on Haswell+ / Zen 1+ | Spectre v2 mitigation | CPUID.07H:EDX.IBRS_IBPB[bit 26] |
| STIBP (Single Thread Indirect Branch Predictors) | Via microcode update | SMT side-channel mitigation | CPUID.07H:EDX.STIBP[bit 27] |

---

## 5. Unsupported Features

### CPL0 Shadow Stack

Intel CET defines two mechanisms: Indirect Branch Tracking (IBT) and Shadow Stack. Brainix supports IBT where available (Tiger Lake and later). However, **CPL0 (ring-0) shadow stack is not supported on current Intel silicon**.

- Shadow stack for ring-3 (userspace) is available on Tiger Lake and later.
- Shadow stack for ring-0 (kernel/supervisor) requires hardware support that is not present on shipping processors as of this specification.
- Brainix will not implement CPL0 shadow stack support until hardware with verified ring-0 shadow stack capability is available and tested.
- IBT (indirect branch tracking) is independent of shadow stack and is supported.

This limitation is documented explicitly per the project rule that security claims must be honest about hardware constraints (Rule 12.5 in PROJECT_RULES.md).

---

## 6. Microcode Requirements

Spectre v1 (bounds check bypass) and Spectre v2 (branch target injection) require microcode updates on affected processors. The following table defines minimum microcode versions for supported CPU generations.

### Intel

| Generation | Family-Model-Stepping | Minimum Microcode | Mitigations Provided |
|-----------|----------------------|-------------------|---------------------|
| Haswell | 06-3CH, 06-45H, 06-46H | 0x28 | IBRS, IBPB, LFENCE serializing |
| Broadwell | 06-3DH, 06-47H, 06-56H | 0x2000065 | IBRS, IBPB, LFENCE serializing |
| Skylake | 06-4EH, 06-5EH | 0xCC | IBRS, IBPB, STIBP, LFENCE serializing |
| Coffee Lake | 06-9EH | 0xCA | IBRS, IBPB, STIBP, SSBD, LFENCE serializing |
| Tiger Lake | 06-8CH, 06-8DH | 0xA4 | IBRS, IBPB, STIBP, SSBD, CET-IBT |

### AMD

| Generation | Family-Model | Minimum Microcode | Mitigations Provided |
|-----------|-------------|-------------------|---------------------|
| Zen 1 | 17h-01h | 0x08001137 | IBPB, LFENCE dispatch-serializing |
| Zen 2 | 17h-31h | 0x0830107A | IBPB, IBRS, STIBP, SSBD, LFENCE dispatch-serializing |
| Zen 3 | 19h-21h | 0x0A201016 | IBPB, IBRS, STIBP, SSBD, LFENCE dispatch-serializing |

### Verification

The bootloader reads the current microcode revision from MSR 0x8B (IA32_BIOS_SIGN_ID) and compares it against the minimum for the detected CPU. If the installed microcode is older than the minimum, the bootloader prints a warning to serial and halts. Running with unpatched microcode is not a degraded mode -- it is a refused boot.

---

## 7. Development Environment

### QEMU Configuration

Development and testing use QEMU with CPU feature emulation:

```
qemu-system-x86_64 \
  -cpu qemu64,+smep,+smap,+nx,+rdrand,+rdseed \
  -machine q35 \
  -m 256M \
  -nographic \
  -serial mon:stdio
```

The `qemu64` base model with explicit feature flags ensures the kernel's CPUID checks pass in emulation. The `q35` machine type provides a modern chipset with IOMMU emulation support.

### Software TPM (swtpm)

Development attestation uses `swtpm` (software TPM 2.0 emulator):

```
swtpm socket \
  --tpmstate dir=/tmp/brainix-tpm \
  --ctrl type=unixio,path=/tmp/brainix-tpm/swtpm.sock \
  --tpm2 \
  --log level=0
```

QEMU connects to swtpm via:

```
-chardev socket,id=chrtpm,path=/tmp/brainix-tpm/swtpm.sock \
-tpmdev emulator,id=tpm0,chardev=chrtpm \
-device tpm-tis,tpmdev=tpm0
```

### Docker Development Container

The Docker development container runs without `--privileged`. It uses only the minimum Linux capabilities required for QEMU execution:

- `--cap-drop=ALL` -- drop all capabilities
- `--cap-add=SYS_RAWIO` -- required for QEMU KVM access (when available)
- `--security-opt=no-new-privileges` -- prevent privilege escalation

When KVM is not available (CI environments), QEMU runs in full emulation mode (TCG) with no special capabilities required.

---

## 8. Production vs Development Separation

| Property | Development | Production |
|----------|------------|------------|
| **Execution environment** | QEMU (q35 machine, TCG or KVM) | Bare-metal x86-64 with UEFI Secure Boot |
| **TPM** | swtpm (software emulation) | Hardware TPM 2.0 |
| **Signing keys** | Development keys (local developer keyring) | Production keys (HSM-stored) |
| **Binary marker** | `DEV_BUILD` marker present | `DEV_BUILD` marker absent |
| **IOMMU** | QEMU intel-iommu or AMD-vi emulation | Hardware IOMMU (VT-d / AMD-Vi) |
| **Security claims** | Testing and behavioral validation only | Full structural security guarantees |
| **Attestation value** | Flow rehearsal and integration testing | Trust-anchor-backed remote attestation |
| **CPU features** | Emulated via QEMU CPU flags | Hardware-verified via CPUID |

### Structural Enforcement

- A binary built with the `DEV_BUILD` marker is rejected by the production kernel. This is a compile-time structural distinction, not a runtime convention.
- Development signing keys cannot produce signatures accepted by the production verification path. Key material never overlaps (INV-BOOT-003).
- swtpm attestation results are never presented as production trust. Development PCR values and production PCR values use distinct trust anchors.

---

*Last updated: 2026-04-11*
*This document is the authoritative specification for Brainix platform support.*
