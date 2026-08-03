# BraiNIX Attestation Model

## Purpose

This document defines the measured boot process, TPM PCR layout, attestation gate, quote format, and rollback protection for BraiNIX. It specifies how the system establishes a chain of trust from firmware through kernel to userspace servers, and how remote verifiers can confirm the integrity of a running BraiNIX instance.

This is an authoritative specification. If code or configuration diverges from this document, the document must be updated in the same PR that introduces the change.

---

## 0. Platform scope — read this first

**Everything in this document applies to x86-64 only.**

As of the owner decision of 2026-08-02, the **primary** platform is Apple Silicon (Mac mini M2, `T8112`),
and on that platform **there is no attestation model at all**. This is not an unimplemented feature. It is
structural: Apple Silicon has no TPM, none can be added (no LPC/SPI header, and a USB TPM is not a root of
trust), and the Secure Enclave exposes no PCR-style extend/quote/seal interface to third-party software.

| Capability | x86-64 (secondary) | Apple Silicon (**primary**) |
|---|---|---|
| PCR measurement (§1, §2) | ✅ | ❌ structurally unavailable |
| TPM quote (§3) | ✅ | ❌ structurally unavailable |
| Attestation gate (§4) | ✅ | ❌ nothing to gate on |
| Rollback protection via monotonic counter (§7) | ✅ | ❌ no TPM counter |
| Sealing secrets to boot state | ✅ | ❌ structurally unavailable |
| Reproducible build | ✅ | ✅ unchanged |
| Ed25519 release signature | ✅ | ✅ unchanged |
| Payload integrity at rest | ✅ UEFI Secure Boot | ✅ iBoot2 vs. device-local SEP policy — *Apple's* root, not ours |

### What Apple Silicon has instead

**iBoot2 verifies the Image4-wrapped payload against a Secure-Enclave-held, device-local policy at every
boot.** A tampered on-disk payload does not boot. This is real, hardware-rooted tamper-resistance **for
the payload at rest** — and it must not be described as attestation. The root is Apple's, the key is
device-local, and it proves nothing to any remote party.

**A software-only measurement log.** The kernel may hash what it loads and record the log. It is
**self-reported**: a kernel compromised early can produce any log it likes. Permitted uses are operational
debugging and accidental-corruption detection. It may **not** be exported as an attestation, presented as
evidence against an attacker, or called a measurement (`INV-BOOT-AS-002`).

### What is permanently lost

- **Remote attestation.** A client cannot distinguish a genuine BraiNIX boot from a compromised one.
- **Sealing.** No secrets bound to boot state; data at rest is protected only by runtime behavior.
- **Runtime-chain measurement.** Detection of a divergent boot chain — the exact property this document's
  §7 and §8 exist to provide — is gone.

### The rule this creates

**No BraiNIX component, protocol field, log line, release note, or document may assert attestation,
sealing, or hardware-anchored measurement on Apple Silicon** (`INV-BOOT-AS-001`, `PROJECT_RULES.md` Rule
13.0). In particular, the BSP serving protocol must not define an attestation field the primary platform
cannot populate honestly — an unfillable field invites a dishonest filling.

**Deployments requiring attestation must run x86-64.** Recorded as the signed exception INV-BOOT/AS in
[`../NORTH_STAR.md`](../NORTH_STAR.md); consequences in
[`../THREAT_MODEL.md`](../THREAT_MODEL.md) and [`PLATFORM_SUPPORT_MATRIX.md`](PLATFORM_SUPPORT_MATRIX.md).

---

## 1. PCR Layout

BraiNIX uses four TPM 2.0 Platform Configuration Registers (PCRs) to record the measurement chain from firmware to userspace servers. Each PCR is a SHA-256 digest (32 bytes) that is extended (not overwritten) with each new measurement.

| PCR | Contents | Measured By | When |
|-----|----------|------------|------|
| PCR[0] | Firmware measurement (UEFI/BIOS hash) | Platform firmware (UEFI) | Before bootloader execution |
| PCR[1] | Bootloader binary hash | Platform firmware or UEFI Secure Boot | Before bootloader handoff |
| PCR[2] | Kernel `.text`/`.rodata` hash + scheduler partition table hash | Bootloader | Before jumping to kernel entry point |
| PCR[3] | Server binary hashes (each server hashed individually, extended in load order) | Kernel | Before spawning each server process |
| PCR[5] | Userspace-ELF-load failure record (SHA-256 of `(process_type, error_variant, source_module_hash)`) | Kernel | Exactly once, only if `create_server_process_from_elf` returns an error during boot; kernel halts immediately after |

### PCR Extension Semantics

PCR extension uses the TPM 2.0 extend operation:

```
PCR[n] = SHA-256(PCR[n] || new_measurement)
```

This is a one-way accumulation. The final PCR value depends on every measurement extended into it and on the order of those measurements. Changing any input or reordering measurements produces a different final PCR value.

### PCR[2] Detailed Contents

PCR[2] receives two measurements in sequence:

1. **Kernel code measurement:** SHA-256 hash of the kernel's `.text` and `.rodata` sections. This is computed by the bootloader after loading the kernel binary into memory but before transferring control.

2. **Scheduler partition table measurement:** SHA-256 hash of the compile-time partition table that defines CPU time slots per security domain. This is extended by the kernel immediately after initialization, before any scheduling begins.

The partition table measurement ensures that any change to the time-partitioning policy (which security domain gets which CPU slots) is reflected in the attestation chain.

### PCR[3] Detailed Contents

PCR[3] receives one measurement per server binary, extended in the order the kernel spawns them:

1. `spawnd` binary hash
2. `auditd` binary hash
3. `linkd` binary hash
4. `ipd` binary hash
5. `transportd` binary hash
6. Device server binary hashes (in device enumeration order)

The ordering is deterministic: the kernel always spawns servers in the same order (defined by the server manifest compiled into the kernel).

### PCR[5] Detailed Contents

PCR[5] is the **userspace-ELF-load failure record slot**. It is extended exactly once if and only if `create_server_process_from_elf` returns an error during boot. The kernel halts immediately after extending PCR[5] (and writing a `[FAIL]` line to the serial console).

The extension payload is `SHA-256(process_type_byte || error_variant_byte || source_module_hash)`, where:

- `process_type_byte` is `process_type as u8` (the failing server's `ProcessType` enum value),
- `error_variant_byte` is a stable 1..=13 tag for each `ElfLoadError` variant (see `process::elf_load_failure::error_variant_to_byte`),
- `source_module_hash` is the SHA-256 of the multiboot2 module bytes the kernel attempted to load.

A remote attester reading PCR[5]:

- **All-zero:** no userspace-ELF-load failure occurred during this boot.
- **Non-zero:** the system attempted boot and a load failure occurred. The exact tuple cannot be recovered from the PCR alone; the attester correlates the value against a precomputed table of `(ProcessType, ElfLoadError, module_hash)` failure records to identify the specific cause.

Claimed by the spec at `docs/superpowers/specs/2026-05-31-userspace-elf-loading-design.md` (Phase 16-A) and implemented in `src/kernel/src/process/elf_load_failure.rs`.

---

## 2. Measurement Process

The measurement chain proceeds in strict sequential order. Each step must complete before the next begins.

### Step A: Firmware Self-Measurement

The platform firmware (UEFI) measures itself into PCR[0]. This step is performed by the firmware before any BraiNIX code executes. BraiNIX trusts this measurement as part of the platform's root of trust.

In production, this measurement corresponds to the UEFI firmware image hash. In development (QEMU), this measurement corresponds to the SeaBIOS or OVMF image hash.

### Step B: Bootloader Measurement

The platform firmware measures the BraiNIX bootloader binary and extends the hash into PCR[1]. This happens before the bootloader receives control.

In UEFI Secure Boot mode, this measurement is performed as part of the Secure Boot verification chain. The bootloader must be signed with a key trusted by the UEFI firmware.

### Step C: Kernel Measurement

The BraiNIX bootloader performs the following before jumping to the kernel entry point:

1. Load the kernel binary into memory at the expected physical address.
2. Verify the kernel's Ed25519 signature (see `RELEASE_AND_SIGNING_POLICY.md` for key types and verification process).
3. Compute SHA-256 over the kernel's `.text` and `.rodata` sections.
4. Extend the hash into PCR[2] via TPM2_PCR_Extend command.
5. Transfer control to the kernel entry point.

If signature verification fails, the bootloader halts. It does not fall through to an unsigned kernel.

### Step D: Partition Table Measurement

The kernel, immediately after initialization and before starting the scheduler:

1. Compute SHA-256 over the compiled-in scheduler partition table bytes.
2. Extend the hash into PCR[2] via TPM2_PCR_Extend command.

This ensures the PCR[2] value reflects both the kernel code and the scheduling policy.

### Step E: Server Binary Measurement

For each server binary in the spawn manifest, the kernel:

1. Load the server binary into memory.
2. Verify the server's Ed25519 signature.
3. Compute SHA-256 over the server's entire binary image.
4. Extend the hash into PCR[3] via TPM2_PCR_Extend command.
5. Spawn the server process with its initial capability set.

If any server's signature verification fails, the kernel halts. A partially-measured system does not proceed to operation.

---

## 3. TPM Quote Format

A TPM quote is a signed assertion of PCR state, used for remote attestation.

### Quote Structure

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `pcr_selection` | Bitmask | 3 bytes | Selects which PCRs are included (PCR[0] through PCR[3] for BraiNIX) |
| `pcr_digest` | SHA-256 | 32 bytes | Hash over the concatenation of selected PCR values: SHA-256(PCR[0] \|\| PCR[1] \|\| PCR[2] \|\| PCR[3]) |
| `nonce` | Bytes | 32 bytes | Freshness value provided by the verifier to prevent replay |
| `clock_info` | TPM clock | 16 bytes | TPM internal clock and reset count (tamper-evident monotonic time) |
| `firmware_version` | u64 | 8 bytes | TPM firmware version |
| `signature` | RSASSA-PKCS1-v1_5 (SHA-256) | 256 bytes | TPM 2.0 standard signing scheme over the quote structure |

### Hash Algorithm

All PCR measurements and the quote digest use **SHA-256**. No other hash algorithm is accepted.

### Signing Schemes

Two signing schemes are used in the attestation model:

1. **TPM Quote Signature:** RSASSA-PKCS1-v1_5 with SHA-256. This is the TPM 2.0 standard signing scheme for quotes, using the TPM's internal attestation key (RSA). This scheme is dictated by the TPM hardware specification.

2. **Attestation Identity:** The TPM's attestation key (AK) is an RSA key generated inside the TPM and certified by the TPM's endorsement key (EK). The AK never leaves the TPM.

The use of RSA for TPM quotes is a TPM 2.0 hardware constraint, not a design choice. All BraiNIX-authored signing (binary signing, key management) uses Ed25519 as specified in `RELEASE_AND_SIGNING_POLICY.md`.

---

## 4. Attestation Gate

The attestation gate ensures that no network traffic is accepted by a BraiNIX instance before its integrity has been verified via TPM quote.

### Gate Sequence

1. **Boot completes.** All measurements are extended into PCR[0] through PCR[3].
2. **Attestation service starts.** A minimal attestation service (running as a userspace server with a dedicated CapEndpoint) begins listening for attestation requests on a designated IPC endpoint.
3. **Network stack is loaded but gated.** The network servers (`linkd`, `ipd`, `transportd`) are spawned and initialized, but they do not process external packets. Their receive path checks an attestation-complete flag before accepting any inbound data.
4. **Remote verifier initiates attestation.** The verifier sends an attestation request containing a fresh 32-byte nonce. This request arrives over a minimal pre-attestation channel (a single designated network port that only accepts attestation protocol messages).
5. **Attestation service generates quote.** The service issues a TPM2_Quote command with the verifier's nonce and the PCR selection bitmask (PCR[0-3]).
6. **Attestation service returns quote.** The signed quote is sent back to the verifier over the pre-attestation channel.
7. **Verifier validates quote.** See Section 8 for the verification process.
8. **Verifier sends attestation-passed signal.** If the quote is valid and PCR values match known-good values, the verifier sends an attestation-passed message.
9. **Attestation gate opens.** The attestation service sets the attestation-complete flag. The network stack begins processing external packets.

### Failure Behavior

- If the remote verifier rejects the quote, the attestation gate remains closed. The system continues running but does not accept network traffic.
- If no verifier contacts the system within a configurable timeout (default: 60 seconds), the system logs a warning but the gate remains closed. The system does not fall back to unattested operation.
- The attestation gate state is not persistent across reboots. Every boot requires a fresh attestation cycle.

---

## 5. Development Flow

Development attestation uses `swtpm` (software TPM 2.0 emulator) to rehearse the full attestation flow without hardware TPM.

### swtpm Setup

```bash
# Create TPM state directory
mkdir -p /tmp/brainix-tpm

# Initialize swtpm with a new EK and SRK
swtpm_setup \
  --tpmstate /tmp/brainix-tpm \
  --tpm2 \
  --createek \
  --create-ek-cert \
  --create-platform-cert \
  --allow-signing \
  --decryption \
  --overwrite

# Start swtpm
swtpm socket \
  --tpmstate dir=/tmp/brainix-tpm \
  --ctrl type=unixio,path=/tmp/brainix-tpm/swtpm.sock \
  --tpm2 \
  --log level=0
```

### Expected Development PCR Values

In development mode, PCR values are deterministic for a given build:

- **PCR[0]:** Determined by the QEMU firmware image (SeaBIOS or OVMF). This value changes only when the QEMU firmware image changes.
- **PCR[1]:** SHA-256 hash of the BraiNIX bootloader binary (development build).
- **PCR[2]:** SHA-256(SHA-256(0^32 || kernel_text_rodata_hash) || partition_table_hash). Determined by the kernel binary and partition table.
- **PCR[3]:** Accumulated hashes of all server binaries in spawn order.

### Local Verification

To verify the attestation chain locally:

```bash
# Read PCR values from swtpm
tpm2_pcrread sha256:0,1,2,3

# Generate a local attestation quote
tpm2_quote \
  --key-context ak.ctx \
  --pcr-list sha256:0,1,2,3 \
  --qualification "development-test-nonce" \
  --message quote.msg \
  --signature quote.sig

# Verify the quote signature
tpm2_checkquote \
  --key-context ak.ctx \
  --message quote.msg \
  --signature quote.sig \
  --qualification "development-test-nonce" \
  --pcr sha256:0,1,2,3
```

### Development Mode Limitations

- swtpm provides no hardware security guarantees. The TPM state is stored as files on disk that any process with file access can modify.
- Development attestation results must never be presented as evidence of production integrity (INV-BOOT-002).
- The development attestation flow is for integration testing and flow rehearsal only.

---

## 6. Production Flow

Production attestation uses a hardware TPM 2.0 chip soldered to the motherboard or installed as a discrete module.

### Hardware Requirements

- TPM 2.0 compliant (TCG specification family 2.0)
- SHA-256 PCR bank support
- RSA 2048-bit attestation key support
- NVRAM available for monotonic counter storage
- Endorsement key (EK) with a manufacturer certificate chain

### Remote Attestation Sequence

1. **Verifier sends challenge.** The remote verifier generates a cryptographically random 32-byte nonce and sends it to the BraiNIX instance over the pre-attestation channel.

2. **BraiNIX generates quote.** The attestation service issues TPM2_Quote with the nonce and PCR selection (PCR[0-3]). The TPM signs the quote with its attestation key.

3. **BraiNIX sends quote to verifier.** The signed quote, along with the TPM's attestation key certificate chain, is sent to the verifier.

4. **Verifier validates.** See Section 8 for the full verification process.

5. **Verifier issues verdict.** The verifier sends an attestation-passed or attestation-failed message.

### Known-Good PCR Values

The verifier maintains a database of known-good PCR values for each BraiNIX release. This database is updated with each release:

- PCR[0]: Per-platform firmware hash (maintained per hardware model)
- PCR[1]: Bootloader binary hash (from release manifest)
- PCR[2]: Kernel + partition table hash (from release manifest)
- PCR[3]: Server binary cumulative hash (from release manifest)

---

## 7. Rollback Protection

Rollback protection prevents booting an older, potentially vulnerable BraiNIX release on a system that has previously booted a newer release.

### Mechanism

A monotonic counter stored in TPM NVRAM serves as the rollback boundary:

1. **Provisioning:** At initial TPM provisioning, an NVRAM index is allocated for the BraiNIX monotonic counter. The counter starts at 0.

2. **Release counter value:** Each BraiNIX release binary embeds a counter value in its image header. This value is set at build time and incremented by exactly 1 for each production release.

3. **Boot-time check:** During the boot measurement process (after PCR measurements, before the attestation gate):
   - The kernel reads the current counter value from TPM NVRAM.
   - The kernel reads its own embedded counter value from the image header.
   - If `embedded_counter < stored_counter`, the kernel prints a rollback-rejection message to serial and halts.
   - If `embedded_counter >= stored_counter`, the kernel updates the TPM counter to `embedded_counter` and continues boot.

4. **Counter update is atomic.** The TPM NVRAM write is performed via TPM2_NV_Increment or TPM2_NV_Write before proceeding past the rollback check.

### Properties

- The counter is monotonic: it can only increase, never decrease (enforced by TPM hardware for counter-type NVRAM indices).
- The counter survives reboots, power cycles, and firmware updates (stored in TPM NVRAM).
- In development mode (swtpm), the counter starts at 0 on each swtpm initialization. Development counter values do not affect production counter state.

This upholds INV-BOOT-004 (rollback policy is explicit).

---

## 8. Quote Verification

The verifier process validates a TPM quote to confirm the integrity of a remote BraiNIX instance.

### Verification Steps

1. **Receive quote.** The verifier receives the TPM quote message, signature, and attestation key certificate chain from the BraiNIX instance.

2. **Validate certificate chain.** The verifier traces the attestation key certificate back to a trusted TPM manufacturer root certificate. If the chain is invalid or the root is not trusted, verification fails.

3. **Verify quote signature.** The verifier checks the RSASSA-PKCS1-v1_5 signature over the quote message using the attestation key's public key (extracted from the validated certificate). If the signature is invalid, verification fails.

4. **Verify nonce.** The verifier checks that the nonce in the quote matches the nonce it sent in the challenge. If the nonce does not match, verification fails (replay detected).

5. **Verify PCR digest.** The verifier computes the expected PCR digest: SHA-256(expected_PCR[0] || expected_PCR[1] || expected_PCR[2] || expected_PCR[3]). The verifier compares this against the PCR digest in the quote. If they do not match, verification fails (unexpected system state).

6. **Check clock monotonicity.** The verifier checks that the TPM clock value is greater than the last recorded clock value for this instance (optional, for detecting TPM reset attacks).

### Trust Anchor

The trust anchor for production attestation is the TPM endorsement key (EK) certificate chain. This chain:

- Starts at the TPM's EK (unique per TPM chip, generated at manufacture)
- Passes through the TPM manufacturer's intermediate CA
- Terminates at the TPM manufacturer's root CA

The verifier must maintain a list of trusted TPM manufacturer root certificates. Only TPM chips from trusted manufacturers are accepted for production attestation.

### Verification Outcomes

| Outcome | Meaning | Action |
|---------|---------|--------|
| **Pass** | All checks succeed; PCR values match known-good values | Open attestation gate; system operates normally |
| **Fail: certificate** | AK certificate chain invalid or untrusted | Reject; investigate TPM identity |
| **Fail: signature** | Quote signature does not verify | Reject; possible tampering or TPM fault |
| **Fail: nonce** | Nonce mismatch | Reject; replay attack or communication error |
| **Fail: PCR mismatch** | PCR values do not match any known-good configuration | Reject; unexpected firmware, kernel, or server state |

---

*Last updated: 2026-04-11*
*This document is the authoritative specification for BraiNIX attestation.*
