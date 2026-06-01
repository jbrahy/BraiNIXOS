# Security Policy

BraiNIX is a security-first project. Its threat model, trust boundary, and verification posture are
documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/security/`](docs/security/).

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions, or pull
requests.**

Instead, report them privately through GitHub's
[private vulnerability reporting](https://github.com/jbrahy/BraiNIXOS/security/advisories/new)
(the **Security** tab → *Report a vulnerability*). This opens a private advisory visible only to the
maintainers.

Please include, as far as you can:

- the affected component (kernel, bootloader, a specific server) and version/commit,
- a description of the issue and the security invariant it breaks (e.g. INV-AUTH, INV-MEM, INV-IPC),
- reproduction steps or a proof of concept, and
- the impact you believe it has.

## What to expect

- We aim to acknowledge a report within a few days.
- We will work with you to understand and validate the issue, and keep you informed of progress.
- Once a fix is ready, we will coordinate disclosure. We are happy to credit reporters who wish to be
  named.

## Scope

Because BraiNIX makes structural security claims, the most valuable reports are those that demonstrate a
violation of a documented invariant — for example, a path to ambient authority, a writable-and-executable
page, a kernel mapping reachable from ring 3, or a shared-memory IPC channel. Findings in vendored
third-party crates should be reported upstream, but please let us know so we can track and update.
