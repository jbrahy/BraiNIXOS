> # 📋 UNSCHEDULED — prototype design, not on the roadmap
>
> **Reviewed 2026-08-02.** A prototype reference configuration. Nothing is being built against it and it is
> not scheduled in [`../ROADMAP.md`](../ROADMAP.md).
>
> Two points of tension with the current design, noted so this file is not mistaken for a plan:
>
> - It describes an **operator login** path. The serving product authenticates *remote clients* to
>   *sessions*, not humans to a root account — see
>   [`../architecture/BSP-v1-serving-protocol.md`](../architecture/BSP-v1-serving-protocol.md).
> - On the **primary platform** the early console is an unauthenticated debug UART that grants whoever
>   holds the cable physical-access authority, and it must be **absent in production**
>   ([`../operations/PLATFORM_SUPPORT_MATRIX.md`](../operations/PLATFORM_SUPPORT_MATRIX.md) §2.5).

---

# BraiNIX Root OTP and Console USB Login Configuration *(unscheduled prototype)*
## Prototype Reference Configuration and Production Rewrite Requirements

Version: 1.0  
Status: Mandatory  
Scope: Root SSH OTP configuration, console USB-token login, enrollment flow, system file layout, and Rust rewrite requirements

---

## 1. Purpose

This document provides the concrete prototype configuration model for two BraiNIX authentication mechanisms:

1. **root remote SSH login** using:
   - SSH public key
   - Google Authenticator-style TOTP as a second factor

2. **local console login** using:
   - an enrolled USB security key created during installation
   - no password fallback

These prototype configurations are reference behavior only. BraiNIX production images must not permanently depend on OpenSSH, Linux PAM, google-authenticator-libpam, pam_u2f, or libfido2. The production system must reimplement the required behavior in Rust with fewer features and tighter security controls.

---

## 2. Design Constraints

The following constraints apply to the whole design:

- no passwords anywhere
- root remote access requires two factors
- normal remote access requires one factor: SSH public key
- console access requires possession of an enrolled USB security key
- less code is preferred to more features
- all files involved in authentication must live in root-owned system locations
- no authentication state required for login may be stored in an encrypted home directory
- no optional MFA settings such as `nullok` are allowed
- any external prototype behavior must be reproduced with simpler Rust-native BraiNIX code later

---

## 3. Reference Behavior Used

This document is based on current reference behavior from:

- OpenSSH `sshd_config` authentication method handling
- Linux/OpenSSH PAM integration
- google-authenticator-libpam TOTP handling and security options
- pam_u2f and libfido2 FIDO/U2F integration semantics

These references define the prototype only. They do not define the final production dependency model.

---

## 4. File and Directory Layout

Use fixed system-owned paths.

```text
/etc/brainix/
├── auth/
│   └── root/
│       └── .google_authenticator
├── ssh/
│   └── admin_authorized_keys
└── security/
    └── u2f_keys
```

Required ownership and modes:

```text
/etc/brainix                      root:root 0755
/etc/brainix/auth                 root:root 0700
/etc/brainix/auth/root            root:root 0700
/etc/brainix/auth/root/.google_authenticator   root:root 0600
/etc/brainix/security             root:root 0700
/etc/brainix/security/u2f_keys    root:root 0600
```

No authentication secret or security-key mapping required for login may live in an encrypted home directory.

---

## 5. Root SSH OTP Prototype Configuration

### 5.1 SSH Daemon Configuration

Prototype OpenSSH configuration:

```conf
# /etc/ssh/sshd_config

Protocol 2

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes

PermitEmptyPasswords no
PermitRootLogin yes

# Default for everyone else: SSH key only
AuthenticationMethods publickey

X11Forwarding no
UseDNS no
LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4

# Root requires SSH public key and PAM-backed OTP
Match User root
    AuthenticationMethods publickey,keyboard-interactive:pam
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitTTY yes
```

### Why these settings matter

- `PasswordAuthentication no` guarantees no password fallback.
- `AuthenticationMethods publickey` makes the default login path key-only.
- `Match User root` adds a second factor only for root.
- `PermitRootLogin yes` is necessary for this exact design because `prohibit-password` disables keyboard-interactive for root.

---

### 5.2 PAM Configuration for SSH

Prototype SSH PAM configuration:

```pam
# /etc/pam.d/sshd

# Root OTP verification
auth required pam_google_authenticator.so secret=/etc/brainix/auth/${USER}/.google_authenticator

# Keep the rest minimal and explicit in prototype environments.
account required pam_permit.so
session required pam_permit.so
```

### Required rules

- Do not use `nullok`.
- Do not use `no_strict_owner`.
- Do not use permissive `allowed_perm`.
- Do not use `allow_readonly`.
- Do not place the secret in the user home directory if that directory may be encrypted or unavailable at auth time.

### Optional hardening choices

You may decide later to use a stricter prompt:

```pam
auth required pam_google_authenticator.so secret=/etc/brainix/auth/${USER}/.google_authenticator [authtok_prompt=Root OTP: ]
```

Keep the baseline simple until the flow is proven.

---

### 5.3 Root TOTP Enrollment Procedure

Use the reference `google-authenticator` tool only during prototype development.

#### Enrollment steps

1. Create the protected directory structure:
   ```bash
   install -d -m 0700 -o root -g root /etc/brainix/auth/root
   ```

2. Run the enrollment tool as `root` and create a TOTP secret.

3. If the tool writes the secret to `/root/.google_authenticator`, move it into:
   ```text
   /etc/brainix/auth/root/.google_authenticator
   ```

4. Set strict ownership and permissions:
   ```bash
   chown root:root /etc/brainix/auth/root/.google_authenticator
   chmod 0600 /etc/brainix/auth/root/.google_authenticator
   ```

5. Add the secret to the administrator’s TOTP application.

6. Verify at least two valid codes before declaring enrollment complete.

7. Record the enrollment event in the audit log.

#### Operational recommendations

- Use TOTP, not HOTP, unless there is a compelling offline-counter requirement.
- Do not share one root seed across multiple hosts.
- Generate one seed per installation.
- Keep system time correct before testing OTP.

---

### 5.4 Root Authorized Keys Policy

Use a separate root-authorized-keys policy file only if needed by the prototype.

Recommended secure baseline:

- root authorized keys are maintained by the installer or a dedicated privileged enrollment tool
- only explicitly enrolled admin keys may authorize root login
- each enrolled root SSH key must have an owner record
- key enrollment and key removal are audited

Prototype file example:

```text
/etc/brainix/ssh/admin_authorized_keys
```

Permissions:

```bash
chown root:root /etc/brainix/ssh/admin_authorized_keys
chmod 0600 /etc/brainix/ssh/admin_authorized_keys
```

Optional `sshd_config` override:

```conf
AuthorizedKeysFile /etc/brainix/ssh/admin_authorized_keys
```

Use this only if it simplifies your prototype image.

---

## 6. Console USB Login Prototype Configuration

### 6.1 Why a USB Security Key Is the Right Baseline

Console login should not use passwords.

The console should require possession of a USB security key plus user interaction appropriate to the token:

- touch / presence
- PIN verification
- optional built-in user verification if the token supports it

This provides a clean, minimal local-auth model that fits BraiNIX better than console passwords.

---

### 6.2 Central Mapping File Requirement

Use a central root-owned mapping file, not a per-user home-directory mapping.

Recommended path:

```text
/etc/brainix/security/u2f_keys
```

Why:

- central mappings are opened as `root`
- per-user mappings in home directories can fail if the home directory is encrypted or unavailable before login
- BraiNIX should keep login-critical material in system-owned locations

---

### 6.3 Install-Time Enrollment for Console USB Keys

The installer must enroll:

- one primary console USB key
- one backup console USB key

The installation must not complete secure mode unless both are successfully enrolled and tested.

#### Recommended fixed relying-party values

Do not rely on the default hostname-based origin or appid.

Use explicit values, for example:

```text
origin = pam://brainix-console
appid  = pam://brainix-console
```

This keeps the credential stable and avoids dependence on changing hostnames.

#### Prototype enrollment command

Reference `pamu2fcfg` enrollment pattern:

```bash
pamu2fcfg -uroot -opam://brainix-console -ipam://brainix-console
```

Run it once for the primary key and once for the backup key, then append both resulting mappings to the central file.

Example mapping file content:

```text
root:<credential-data-for-primary-key>:<credential-data-for-backup-key>
```

Final permissions:

```bash
chown root:root /etc/brainix/security/u2f_keys
chmod 0600 /etc/brainix/security/u2f_keys
```

---

### 6.4 PAM Prototype Configuration for Console Login

For a PAM-based Linux console prototype, a minimal passwordless FIDO path could look like this:

```pam
# /etc/pam.d/login

auth required pam_u2f.so \
    authfile=/etc/brainix/security/u2f_keys \
    origin=pam://brainix-console \
    appid=pam://brainix-console \
    cue \
    pinverification=1

account required pam_permit.so
session required pam_permit.so
```

### Notes

- `cue` reminds the user to touch the token.
- `pinverification=1` requires PIN verification when the token supports FIDO2 PIN.
- If you use a biometric-capable token, you may later add a user-verification policy instead.

Biometric-capable example:

```pam
auth sufficient pam_u2f.so \
    authfile=/etc/brainix/security/u2f_keys \
    origin=pam://brainix-console \
    appid=pam://brainix-console \
    cue \
    pinverification=0 \
    userverification=1

auth sufficient pam_u2f.so \
    authfile=/etc/brainix/security/u2f_keys \
    origin=pam://brainix-console \
    appid=pam://brainix-console \
    cue \
    pinverification=1 \
    userverification=0
```

For BraiNIX, start with the simpler non-biometric PIN-verified flow unless you have a strong reason to support more.

---

### 6.5 Console Login User Experience

The desired console flow is:

1. Boot reaches login prompt.
2. User enters account name if the design still uses named accounts.
3. User inserts enrolled USB key if not already inserted.
4. System prompts for touch and/or PIN.
5. System verifies the registered credential.
6. Console session opens.
7. Event is audited.

No password prompt appears at any point.

---

## 7. Recommended Installer Workflow

The installer should perform authentication setup in this order:

### Phase 1 — Host identity
- generate host SSH keys
- store them in the final system image

### Phase 2 — Remote admin enrollment
- enroll at least one administrator SSH public key
- verify SSH key ownership metadata

### Phase 3 — Root OTP enrollment
- generate root TOTP seed
- import/scan into OTP application
- verify successful codes
- store seed in `/etc/brainix/auth/root/.google_authenticator`

### Phase 4 — Console USB enrollment
- prompt for primary USB security key
- register console credential
- prompt for backup USB security key
- register backup console credential
- write both mappings to `/etc/brainix/security/u2f_keys`
- verify both keys before continuing

### Phase 5 — Finalization
- validate file ownership and permissions
- write immutable or signed config manifests where supported
- write audit record of enrollment completion
- refuse completion if any required enrollment step failed

---

## 8. Recovery Policy

A secure system still needs recovery, but recovery must not silently downgrade the authentication policy.

### Allowed recovery patterns
- signed recovery media
- physically-present maintenance mode
- reinstall and restore from trusted backup
- explicit re-enrollment process for root OTP or console keys

### Forbidden recovery patterns
- fallback password
- hidden recovery password
- hardcoded vendor secret
- skipping OTP if the secret file is missing
- skipping USB verification if the mapping file is missing

### Recommended rule
Require two console keys at install time so loss of one token does not immediately become a lockout event.

---

## 9. Production Rust Rewrite Plan

The production BraiNIX implementation should replace the prototype stack with native Rust code.

### 9.1 Replace OpenSSH/PAM Root OTP Path With:
- `brainix-sshd`
- `brainix-authd`
- `brainix-otp`

#### Responsibilities
- parse only the minimum SSH features needed for BraiNIX admin access
- accept only public-key authentication for general users
- require a second factor only for root
- validate TOTP in a fixed-format, system-owned seed store
- write structured audit events directly

### 9.2 Replace PAM U2F Console Path With:
- `brainix-console-auth`
- `brainix-fido`

#### Responsibilities
- enumerate supported USB FIDO devices
- manage enrollment of one primary and one backup key
- store only the necessary public credential material
- require touch and configured token verification policy
- expose no password path
- fail closed if mapping or attestation data is invalid

---

## 10. Minimal Feature Scope

To avoid bloat, the first secure BraiNIX authentication implementation should support only:

- SSH key login for users
- SSH key + TOTP for root
- console USB key login
- install-time enrollment
- key/seed rotation
- audit logging
- recovery via explicit offline process

Not in scope initially:

- password auth
- LDAP / SSO / Kerberos
- SMS/email MFA
- desktop session MFA
- general-purpose PAM compatibility layer
- GUI enrollment tools
- automatic cloud enrollment
- biometric support unless it comes directly from the hardware token and does not expand the trusted stack meaningfully

---

## 11. Validation Checklist

A system built to this document is acceptable only if all of the following are true:

### Root SSH
- passwords fail
- SSH key alone fails for root
- OTP alone fails for root
- SSH key + valid OTP succeeds for root
- invalid OTP fails
- missing OTP secret file fails
- wrong file owner or wrong file mode fails

### Normal SSH Users
- SSH public key succeeds
- passwords fail
- OTP is not required unless explicitly added by policy

### Console USB Login
- enrolled primary key succeeds
- enrolled backup key succeeds
- unenrolled key fails
- missing mapping file fails
- wrong file owner or wrong file mode fails
- no password prompt exists

### Installer
- cannot complete secure install without primary and backup console keys
- cannot complete secure install without root OTP enrollment
- cannot complete secure install without at least one admin SSH key

---

## 12. Short Form

The entire design reduces to this:

- all remote users use SSH keys
- root uses SSH key plus Google Authenticator-style OTP
- local console login uses an enrolled USB security key
- no passwords exist anywhere
- install must enroll everything before secure mode completes
- prototype external code is reference-only
- production implementation must be rewritten in Rust
