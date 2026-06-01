# SSH_AUTH_POLICY.md

# BraiNIX SSH Authentication Policy
## Minimal, High-Assurance Remote Access Policy

Version: 1.0  
Status: Mandatory  
Scope: Remote administration, local administration policy alignment, prototype implementation guidance, and production BraiNIX requirements

---

## 1. Purpose

This document defines the BraiNIX authentication policy for remote SSH access.

The policy is intentionally minimal:

- no passwords anywhere
- no password fallback anywhere
- SSH public keys for every remote login
- root access requires SSH public key **and** a second factor
- the second factor for root is Google Authenticator-style OTP in the prototype
- console login uses an enrolled USB security key created during installation
- any third-party reference implementation is for prototype behavior only and must be rewritten for BraiNIX in Rust before production use

This project explicitly prefers **less functionality over bloated code**. Any feature not required for secure administration is out of scope.

---

## 2. Non-Negotiable Rules

1. Password authentication is forbidden for all accounts.
2. Empty-password login is forbidden.
3. OTP-only login is forbidden.
4. Remote login for non-root users must require a valid SSH public key.
5. Remote login for root must require a valid SSH public key and a valid one-time password.
6. Root OTP must not replace the SSH key. It is a second factor, not a substitute.
7. Console login must require an enrolled USB security key. No console password login is permitted.
8. Recovery must not silently downgrade authentication strength.
9. Prototype external components may be used only as behavior references and must be replaced with BraiNIX-native Rust implementations for production.
10. Any configuration option that weakens ownership checks, file-permission checks, or makes MFA optional is prohibited.

---

## 3. Security Objectives

The BraiNIX authentication system must achieve the following:

- eliminate password guessing, password reuse, and password phishing from the normal login path
- ensure root requires possession of both a trusted private key and a time-based OTP secret
- keep the remote SSH policy simple enough to audit
- keep the console login policy simple enough to recover and test
- minimize third-party code in the long-term trusted path
- separate prototype behavior from production guarantees

---

## 4. Prototype vs Production

### 4.1 Prototype Reference Stack

During prototype development and test bring-up, the following external components may be used as **behavior references only**:

- OpenSSH server/client semantics for SSH key login and multi-step authentication
- Linux PAM semantics for keyboard-interactive second-factor handling
- google-authenticator-libpam semantics for root TOTP verification
- pam_u2f / libfido2 semantics for console USB-token authentication

These components must not be treated as permanent dependencies for the final BraiNIX operating system.

### 4.2 Production BraiNIX Requirement

Before BraiNIX is considered production-ready, the authentication path must be rewritten in Rust as native BraiNIX services and libraries, with the external tools serving only as prototype models.

Target BraiNIX-native components:

- `brainix-sshd` — BraiNIX-native SSH daemon or SSH-compatible remote admin service
- `brainix-authd` — central authentication coordinator
- `brainix-otp` — TOTP validation service for root second factor
- `brainix-console-auth` — local console USB-token authentication service
- `brainix-fido` — FIDO2 / CTAP device handling and enrollment library
- `brainix-keymgr` — key enrollment, revocation, and recovery policy tooling
- `brainix-auditd` — immutable audit/event capture for all authentication attempts

These services must be implemented with the fewest features necessary to satisfy the policy.

---

## 5. Authentication Matrix

| Access Path | User Type | Required Factors | Password Allowed | Notes |
|---|---|---:|---:|---|
| SSH | normal admin/user | SSH public key | No | default remote login |
| SSH | root | SSH public key + OTP | No | root-specific Match policy |
| Local console | normal admin/user | enrolled USB security key | No | key touch and/or PIN/UV according to token policy |
| Local console | root | enrolled USB security key | No | same console path unless break-glass media is invoked |
| Recovery | break-glass only | separate documented recovery process | No | must not silently reduce normal login policy |

---

## 6. Required SSH Policy

### 6.1 Global Rules

The SSH daemon must be configured so that:

- `PubkeyAuthentication` is enabled
- `PasswordAuthentication` is disabled
- keyboard-interactive is available only because root needs OTP in the prototype
- PAM is enabled only for the root OTP path in the prototype
- root-specific restrictions are narrower than the global policy
- any forwarding feature not required for administration is disabled, especially for root

### 6.2 Global Defaults

The global SSH stance should be:

- key-based login only
- no passwords
- no challenge-response for normal users
- no X11 forwarding
- no agent forwarding for root
- no tunnel creation for root
- no port forwarding for root unless there is a separately approved need
- no unaudited root convenience paths

---

## 7. Required SSHD Prototype Configuration

The following is the reference prototype configuration for Linux/OpenSSH environments.

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

AuthenticationMethods publickey

X11Forwarding no
AllowTcpForwarding yes
PermitTunnel no
AllowAgentForwarding yes

LoginGraceTime 20
MaxAuthTries 3
MaxSessions 4
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no

# Root must use SSH key + PAM-backed OTP
Match User root
    AuthenticationMethods publickey,keyboard-interactive:pam
    AllowTcpForwarding no
    AllowAgentForwarding no
    PermitTunnel no
    X11Forwarding no
    PermitTTY yes
```

### Why this structure exists

- All users authenticate with an SSH public key.
- Root adds one more factor through keyboard-interactive PAM.
- Passwords remain disabled everywhere.
- Root remains much more constrained than non-root users.

### Important note

`PermitRootLogin prohibit-password` must **not** be used for this policy, because OpenSSH disables keyboard-interactive for root in that mode. If root is supposed to use public key plus OTP, then root must be enabled and restricted using a `Match User root` block instead.

---

## 8. PAM Policy for Root SSH OTP

The root OTP policy exists only for root.

Normal users must not be prompted for OTP during SSH login unless a future BraiNIX policy explicitly adds that requirement.

Prototype Linux PAM service reference:

```pam
# /etc/pam.d/sshd

# Root-only OTP check; the Match User root block in sshd_config
# ensures only root is forced down the keyboard-interactive path.
auth required pam_google_authenticator.so secret=/etc/brainix/auth/${USER}/.google_authenticator

# Keep normal account/session handling below according to system baseline.
account required pam_permit.so
session required pam_permit.so
```

### Mandatory restrictions for the PAM module

The following options are prohibited in the BraiNIX prototype and production design:

- `nullok`
- `no_strict_owner`
- `allowed_perm=...` with looser-than-owner-only settings
- `allow_readonly`

These options weaken mandatory-enrollment, file ownership, file-permission, or one-time semantics.

---

## 9. Root OTP Enrollment Policy

### 9.1 Storage Location

Do not store the root OTP secret in `/root/.google_authenticator`.

Store it in a dedicated system path instead, for example:

```text
/etc/brainix/auth/root/.google_authenticator
```

Required ownership and mode:

- owner: `root`
- group: `root`
- mode: `0600`

Recommended parent directories:

- `/etc/brainix`
- `/etc/brainix/auth`
- `/etc/brainix/auth/root`

All must be root-owned and non-world-writable.

### 9.2 Enrollment Rules

During installation or first secure boot:

1. generate the root TOTP secret
2. scan or import the secret into the root administrator’s OTP application
3. verify at least two successive valid codes before finalizing the install
4. print or export emergency recovery codes only if the project adopts a documented recovery-code design
5. store no plaintext copy of the seed outside the designated protected secret file
6. audit the enrollment event

### 9.3 Operational Rules

- TOTP is for root only in the initial policy.
- Root must not share OTP seeds across systems.
- Each BraiNIX installation must have its own root OTP seed.
- If root OTP enrollment is incomplete, direct root SSH must remain disabled.
- If the root OTP secret file is missing or fails ownership/permission checks, root SSH authentication must fail closed.

---

## 10. Console Login Policy

Console login must not use passwords.

The console must require an enrolled USB security key. The prototype behavior may follow pam_u2f/libfido2 semantics, but production BraiNIX must replace that with Rust-native code.

Console login rules:

- a USB security key must be enrolled during installation
- at least one backup key must also be enrolled before installation completes
- the mapping/credential store must be kept in a root-owned system path
- the login path must not depend on data stored in an encrypted home directory
- the console should require touch and, when supported, PIN verification or user verification
- the console must fail closed if the USB key mapping is missing or invalid
- there is no password fallback

---

## 11. Install-Time Enrollment Requirements

The installer must enforce the following:

1. Generate host SSH keys.
2. Enroll at least one administrator SSH key.
3. Enroll the root OTP seed.
4. Enroll at least one console USB security key.
5. Enroll at least one backup console USB security key.
6. Verify both console keys before installation finishes.
7. Write the resulting configuration into root-owned system files.
8. Record signed/audited installation events.

The installer must refuse to complete secure mode installation unless all mandatory factors are enrolled successfully.

---

## 12. Break-Glass and Recovery

Break-glass recovery must be explicit and separate from normal login.

Allowed break-glass patterns:

- offline signed recovery media
- physically present maintenance mode requiring separate signed authorization
- reinstall + restore from trusted backup if no secure recovery path exists yet

Forbidden break-glass patterns:

- hidden backdoor account
- emergency password
- undocumented override flag
- auto-bypass if OTP or USB login is misconfigured
- default vendor recovery secret

The recovery process must be documented independently and audited when used.

---

## 13. Audit Requirements

All authentication-relevant events must be logged to the BraiNIX audit system:

- ssh login success/failure
- root otp success/failure
- unauthorized auth method attempts
- disabled password auth attempts
- USB console key success/failure
- enrollment events
- recovery-mode entry
- root Match policy hits
- configuration integrity failures

Audit logs must not expose private keys, OTP seeds, or reusable challenge material.

---

## 14. Feature Cuts Required to Prevent Bloat

The following are explicitly out of scope for the first secure BraiNIX authentication system:

- password authentication
- password resets
- graphical login managers
- pluggable desktop MFA
- SMS-based MFA
- email-based recovery
- biometric login not backed by a hardware authenticator
- web-based login portals
- generalized PAM module sprawl
- remote root convenience features such as agent forwarding and unrestricted tunneling

---

## 15. Production Rust Rewrite Requirements

The production BraiNIX authentication system must be rewritten in Rust with these goals:

- fewer features than the prototype
- fewer code paths than the prototype
- no generic PAM dependency
- no generic shell-script enrollment pipeline
- no dependence on mutable user-home secret files
- fixed-format config files with strict ownership and type checks
- direct audit integration
- explicit config schema validation
- deterministic failure behavior

The Rust rewrite must preserve the same high-level policy:

- SSH key for all remote logins
- root = SSH key + OTP
- console = enrolled USB key
- no passwords anywhere

---

## 16. Acceptance Criteria

This policy is considered correctly implemented when all of the following are true:

- non-root SSH logins succeed with valid SSH public keys and fail for passwords
- root SSH logins require both SSH public key and OTP
- root cannot log in with only the SSH key
- root cannot log in with only the OTP
- console login requires a previously enrolled USB key
- console login has no password fallback
- root OTP secret is stored outside the home directory in a protected system path
- at least one backup console USB key is enrolled
- all authentication events are audited
- prototype external components are clearly marked for replacement in the production Rust implementation

---

## 17. Short Form Policy

If this document must be reduced to a simple rule set:

- no passwords
- SSH keys for everyone
- root = SSH key + OTP
- console = enrolled USB key
- backup USB key required
- no silent fallback
- prototype external auth code is reference-only
- production auth stack must be rewritten in Rust
