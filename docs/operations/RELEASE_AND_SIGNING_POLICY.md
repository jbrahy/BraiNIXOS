# BraiNIX Release and Signing Policy

## Purpose

This document defines the release signing process, key management, binary authentication, and rollback protection mechanisms for BraiNIX. It specifies the signing algorithm, key types, key separation rules, the binary signing workflow, and emergency procedures.

This is an authoritative specification. If code or configuration diverges from this document, the document must be updated in the same PR that introduces the change.

---

## 0. Per-platform delivery and what survives

*(Added 2026-08-02 with the Apple-primary platform decision.)*

**Our signing policy is unchanged on both platforms.** Reproducible build and Ed25519 release signing are
properties of the **artifact**, not the platform, and they hold identically on Apple Silicon. What differs
is how the artifact is delivered to the machine and what the machine's own boot chain does with it.

| | x86-64 (secondary) | Apple Silicon (**primary**) |
|---|---|---|
| Artifact | GRUB2 ISO / kernel image | **Image4 (IMG4) payload** |
| Delivery | Standard boot media | `kmutil configure-boot -c <payload> -v <volume>` |
| Our signature | Ed25519, HSM-held key (§§1–4) | Ed25519, HSM-held key — **unchanged** |
| Reproducible build | ✅ (§8) | ✅ **unchanged** |
| Platform boot verification | UEFI Secure Boot | **iBoot2 vs. Secure-Enclave-held device-local policy** |
| Predicted PCRs published | ✅ before ship | ❌ **nothing to predict** |
| Monotonic-counter rollback protection (§7) | ✅ TPM NV counter | ❌ **no TPM counter available** |

### Apple Silicon delivery flow

1. The target volume is downgraded to **Permissive Security** with `bputil` from One True Recovery.
   Requires local admin credentials and **physical presence**, once per machine.
2. `kmutil configure-boot` installs the payload, wrapping it as an Image4 object under the machine's
   **device-local** policy. The Secure Enclave holds the signing key for that policy.
3. iBoot2 verifies the payload's digest against that local policy at **every** boot.

**Two things this is not.** It is not our trust root — it is Apple's, and the key is per-machine, not our
release key. And it is not attestation — it protects the payload at rest and proves nothing to any remote
party. Release notes must describe it precisely and must not let it stand in for measured boot.

### Rollback protection without a monotonic counter

§7's TPM NV monotonic counter has no Apple Silicon equivalent. Rollback to a previously valid, signed
BraiNIX payload therefore **cannot be prevented on the primary platform** by the mechanism this document
specifies. Apple's local policy will happily boot any payload we validly installed.

What remains: revoking a compromised release's signature and re-provisioning affected machines — an
operational control requiring physical or administrative access to each unit, not a structural one. Treat
this as a known limitation of the primary platform and state it in release notes rather than implying §7
coverage. Tracked with the INV-BOOT/AS consequences in [`ATTESTATION_MODEL.md`](ATTESTATION_MODEL.md) §0.

### Release-note requirement

Every Apple Silicon release note must state plainly that the build provides **no remote attestation and no
sealing**, and that deployments requiring either must use the x86-64 target (`INV-BOOT-AS-001`,
`PROJECT_RULES.md` Rule 13.0 and Rule 4.5 — no marketing claims beyond proof scope).

---

## 1. Signing Algorithm

BraiNIX uses **Ed25519** exclusively for all binary signing operations.

- No RSA signatures.
- No ECDSA signatures.
- No other signature schemes.

### Rationale

| Property | Ed25519 |
|----------|---------|
| Deterministic signatures | Yes -- same input always produces same signature (no randomness needed at sign time) |
| Key size | 32 bytes (public), 64 bytes (secret) |
| Signature size | 64 bytes |
| Verification speed | Fast -- single scalar multiplication |
| Implementation simplicity | Minimal state, no padding modes, no hash function selection |
| Resistance to implementation errors | Deterministic signing eliminates nonce-reuse vulnerabilities that affect ECDSA |

Ed25519 is chosen for its combination of small signatures, fast verification (critical for boot-time checks), and deterministic behavior that eliminates an entire class of implementation bugs.

---

## 2. Key Types

Three distinct key types exist in the BraiNIX signing ecosystem. Each key type has a defined purpose, storage location, and usage constraint.

| Key Type | Purpose | Storage | Usage Constraint |
|----------|---------|---------|-----------------|
| **Development Key** | Sign binaries for local testing and CI | Developer keyring (OS keychain or GPG-protected file) | Accepted only by kernels built with `DEV_BUILD` marker |
| **Production Key** | Sign release binaries for deployment | Hardware Security Module (HSM) | Accepted only by kernels built without `DEV_BUILD` marker |
| **Attestation Key** | TPM-bound key for attestation quotes | TPM NVRAM (non-exportable) | Used only for TPM quote signing; never used for binary signing |

### Key Format

All Ed25519 keys follow the standard format:

- Secret key: 32 bytes of random seed material (expanded to 64 bytes internally by Ed25519)
- Public key: 32 bytes (compressed Edwards point)
- Public keys are distributed as hex-encoded strings in configuration files
- Secret keys are never stored in plaintext on disk outside of HSM or TPM

---

## 3. Key Separation

Development and production keys **never share key material**. This is not a convention -- it is a structural enforcement.

### Structural Enforcement

1. The kernel binary contains a compile-time `DEV_BUILD` marker (present or absent).
2. The kernel's signature verification code checks the `DEV_BUILD` marker before selecting the verification key set.
3. A `DEV_BUILD` kernel only accepts signatures from the development public key set.
4. A non-`DEV_BUILD` kernel only accepts signatures from the production public key set.
5. There is no fallback, no override flag, and no runtime switch.

### Consequences

- A binary signed with a development key is **structurally rejected** in production. The verification fails because the production kernel does not have the development public key in its verification set.
- A binary signed with a production key is **structurally rejected** in development. The `DEV_BUILD` kernel does not have the production public key in its verification set.
- Key material compromise in one environment does not affect the other environment.

This upholds INV-BOOT-003 (dev and prod cryptographic material remain separate).

---

## 4. Key Storage

| Key Type | Storage Location | Access Control | Backup |
|----------|-----------------|---------------|--------|
| Development secret key | Developer OS keychain (macOS Keychain, Linux kernel keyring, or GPG-encrypted file) | Developer authentication | Each developer generates their own key pair; no shared development key |
| Production secret key | Hardware Security Module (HSM) with FIPS 140-2 Level 3 or higher | Multi-party authorization required for signing operations | HSM-vendor-specific backup procedure; backup stored in separate physical location |
| Attestation secret key | TPM NVRAM, marked non-migratable | TPM owner authorization | Not backed up; TPM replacement requires re-enrollment with attestation verifier |
| Development public key | Compiled into `DEV_BUILD` kernel binary | Read-only after compilation | Source-controlled in repository |
| Production public key | Compiled into production kernel binary | Read-only after compilation | Source-controlled in repository |

### HSM Requirements for Production Keys

- The HSM must support Ed25519 key generation and signing operations.
- The secret key must never leave the HSM boundary.
- Signing operations require multi-party authorization (at minimum two authorized personnel).
- The HSM audit log must record every signing operation with timestamp, operator identity, and artifact hash.

---

## 5. Binary Signing Process

The binary signing process follows these steps in order. Each step must complete successfully before the next begins.

### Step 1: Reproducible Build

Build the kernel binary using the pinned toolchain and vendored dependencies:

```
cargo build --release --offline --target x86_64-unknown-none
```

The build is reproducible: identical source, toolchain, and dependencies produce an identical binary hash. The build environment is a deterministic Docker container with pinned base image.

### Step 2: Hash Binary

Compute the SHA-256 hash of the output binary:

```
sha256sum target/x86_64-unknown-none/release/brainix-kernel > brainix-kernel.sha256
```

### Step 3: Sign Hash with Ed25519

Sign the binary hash using the appropriate key type:

- **Development:** Sign with the developer's local Ed25519 key.
- **Production:** Submit the hash to the HSM for signing. Two authorized operators must approve.

The signature covers the SHA-256 hash, not the raw binary. This allows the hash to be transmitted to the HSM without transmitting the full binary.

### Step 4: Attach Signature as Sidecar File

The signature is stored as a sidecar file alongside the binary:

```
brainix-kernel            # The binary
brainix-kernel.sha256     # SHA-256 hash
brainix-kernel.sig        # Ed25519 signature over the hash
brainix-kernel.pub        # Public key used for this signature
```

The `.sig` file contains the 64-byte Ed25519 signature in raw binary format. The `.pub` file contains the 32-byte Ed25519 public key in raw binary format.

### Step 5: Verify Signature

Before any deployment or boot, the signature is independently verified:

```
1. Read brainix-kernel.sha256
2. Read brainix-kernel.sig
3. Read brainix-kernel.pub
4. Verify: Ed25519_Verify(public_key, sha256_hash, signature) == true
5. Verify: SHA256(brainix-kernel) == sha256_hash
```

Both checks must pass. If either fails, the binary is rejected.

---

## 6. DEV_BUILD Marker

The `DEV_BUILD` marker is a compile-time constant that structurally distinguishes development binaries from production binaries.

### Definition

```rust
/// Compile-time marker distinguishing development and production builds.
/// When true, the kernel accepts only development signing keys.
/// When false, the kernel accepts only production signing keys.
///
/// This marker is set via a Cargo feature flag:
///   cargo build --features dev-build    (development)
///   cargo build                         (production, default)
#[cfg(feature = "dev-build")]
const IS_DEVELOPMENT_BUILD: bool = true;

#[cfg(not(feature = "dev-build"))]
const IS_DEVELOPMENT_BUILD: bool = false;
```

### Enforcement

1. At boot, the kernel reads `IS_DEVELOPMENT_BUILD`.
2. If `true`: the kernel loads the development public key set for signature verification. It also refuses to boot with a production TPM configuration (hardware TPM + production attestation verifier).
3. If `false`: the kernel loads the production public key set for signature verification. It also refuses to accept swtpm attestation results.

There is no runtime mechanism to override this marker. It is baked into the binary at compile time.

---

## 7. Monotonic Counter

A TPM-bound monotonic counter prevents rollback to vulnerable binary versions.

### Mechanism

1. The TPM contains a monotonic counter in NVRAM (NV index allocated at initial provisioning).
2. Each release binary embeds a counter value in its header (set at build time).
3. At boot, the kernel reads the current counter value from TPM NVRAM.
4. If `binary_counter_value < tpm_stored_counter_value`, boot is rejected. The binary is older than the last accepted release.
5. If `binary_counter_value >= tpm_stored_counter_value`, boot proceeds. The TPM counter is updated to `binary_counter_value`.

### Counter Increment Policy

- The counter is incremented by exactly 1 for each production release.
- The counter is never decremented.
- The counter is never reset to zero.
- In development mode (swtpm), the counter starts at 0 and is used for flow testing only. Development counter values have no bearing on production counter state.

### Security Properties

- **Rollback prevention:** An attacker who obtains an older, vulnerable binary cannot boot it on a system that has booted a newer release (INV-BOOT-004).
- **Tamper evidence:** The counter is stored in TPM NVRAM, which is protected by the TPM's physical security boundary.
- **Key compromise recovery:** If a signing key is compromised, incrementing the counter past all compromised releases invalidates them even if the attacker possesses the old key.

---

## 8. Release Verification

Every production release undergoes independent verification before deployment.

### Verification Process

1. **Builder** produces the binary using the reproducible build process (Step 1-4 above).
2. **Verifier** (a second party, not the builder) independently performs the reproducible build from the same source commit.
3. **Verifier** computes the SHA-256 hash of their independently built binary.
4. **Verifier** confirms their hash matches the builder's published hash. If the hashes differ, the release is rejected and the discrepancy is investigated.
5. **Verifier** verifies the Ed25519 signature over the hash using the production public key.
6. **Verifier** signs off on the release. Both builder and verifier identities are recorded in the release manifest.

### Release Manifest

Each release includes a signed manifest containing:

- Source commit hash (full SHA-1 or SHA-256 git hash)
- Binary SHA-256 hash
- Ed25519 signature
- Monotonic counter value
- Builder identity
- Verifier identity
- Toolchain version (from rust-toolchain.toml)
- Build timestamp (UTC)

---

## 9. Key Rotation

### Schedule

- **Production keys:** Rotated annually. The rotation date is the anniversary of the key's creation.
- **Development keys:** Rotated at developer discretion. Recommended annually or on team membership changes.
- **Attestation keys:** Not rotated (TPM-bound). Replaced only on TPM hardware replacement.

### Rotation Process

1. Generate a new Ed25519 key pair in the HSM.
2. Add the new public key to the kernel's production key set (the kernel accepts signatures from any key in the set).
3. Release a new kernel binary signed with the new key. This binary's monotonic counter value is incremented as usual.
4. After all deployed systems have been updated to the new binary (or a newer one), the old key is retired from the active signing set.
5. The old public key remains in the kernel's verification set for a transition period (one additional annual cycle) to allow verification of existing deployments that have not yet updated.

### Key Retirement

After the transition period, the old public key is removed from the kernel's verification set. Binaries signed with the retired key can no longer boot on systems running the updated kernel.

---

## 10. Emergency Procedures

### Key Compromise Response

If a production signing key is believed to be compromised:

1. **Revoke the compromised key.** Remove its public key from the active key set in the kernel source. This is a code change requiring the standard review and CI process.

2. **Increment the monotonic counter** past the highest counter value of any binary signed with the compromised key. This invalidates all binaries signed with the compromised key, even if the attacker possesses the key.

3. **Re-sign the latest release** with the new production key. This produces a new binary with a counter value above the compromised range.

4. **Publish a key revocation notice** documenting:
   - The compromised key's public key fingerprint
   - The date range during which the key was active
   - The counter value range of potentially compromised binaries
   - The new key's public key fingerprint
   - Steps for operators to verify they are running a non-compromised binary

5. **Deploy the re-signed binary** to all production systems. Systems running binaries signed with the compromised key must be updated.

### HSM Failure

If the HSM becomes unavailable (hardware failure, not compromise):

1. Activate the HSM backup at the secondary physical location.
2. Verify the backup HSM contains the same key material by signing a test artifact and verifying with the known public key.
3. Resume normal signing operations on the backup HSM.
4. Replace the failed primary HSM and re-provision it from the backup.

### Development Key Compromise

Development key compromise does not affect production security (keys are structurally separated). The compromised developer generates a new key pair and the old public key is removed from the development key set.

---

*Last updated: 2026-04-11*
*This document is the authoritative specification for BraiNIX release signing.*
