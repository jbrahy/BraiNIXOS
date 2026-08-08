# Contributing to BraiNIX

Thank you for your interest. BraiNIX is a security-first microkernel built to serve LLM inference
securely to remote clients, and it holds a deliberately high bar: every change should leave the system
as auditable and as structurally secure as it found it.

Security vulnerabilities must **not** be filed as public issues — see the
[Security Policy](SECURITY.md).

## Before you start

- Read [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md) (the timeless target), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
  and [`docs/ROADMAP.md`](docs/ROADMAP.md) (phasing and current status).
- Then [`docs/DOCUMENTATION_MAP.md`](docs/DOCUMENTATION_MAP.md), which lists every document, states the
  authority order, and marks which files are CURRENT, SUPERSEDED, or ARCHIVED. **Several documents in this
  repository are deliberately out of date** — historical records carrying a status banner. Check the map
  before trusting a file you have not seen referenced from the authority spine.
- Then the relevant docs under [`docs/architecture/`](docs/architecture/) and [`docs/security/`](docs/security/).
- For anything non-trivial, open an issue first to discuss the design. A feature that cannot be expressed
  as, or checked against, a named invariant is unlikely to land.

## The bar

These are enforced in review (and much of it in CI):

1. **Full-word names.** No abbreviations or acronyms-as-names. `capability_slot_index`, not `cap_idx`.
2. **Small functions.** Decompose into named helpers; keep function bodies short and single-purpose.
3. **No duplication.** Any logic appearing twice is extracted and named.
4. **`unsafe` is prohibited by default.** Any `unsafe` must fall under the allowlist in
   [`docs/security/UNSAFE_CODE_POLICY.md`](docs/security/UNSAFE_CODE_POLICY.md), with a `SAFETY:` block
   stating preconditions, the invariant it preserves, and the evidence (test) for it.
5. **Security-relevant code names its invariant.** State which invariant a change enforces and the test
   that verifies it. Asserted is not enforced.
6. **No new external dependencies.** The standing goal is to shrink the dependency closure toward zero,
   not grow it.
7. **No copied code from reverse-engineering projects**, regardless of their license. BraiNIX's primary
   platform is Apple Silicon, and the only public documentation of that hardware comes from
   [Asahi Linux](https://asahilinux.org/). Their work is **reference-only**: read the published
   documentation and reimplement from understanding. Where only source documents a behavior, write a
   specification and implement from that. Running m1n1 as a lab instrument is fine — that is using a tool.
8. **No page-size assumptions.** The platform uses 16 KiB base pages; the frozen x86-64 reference uses
   4 KiB. A hardcoded `4096` **or `16384`** outside `arch/` is a security defect (`INV-MEM-009`), not a
   portability nit — and with the 4 KiB aarch64 harness cancelled, a hardcoded 16 KiB is the likelier
   mistake and nothing in CI disagrees with it.
9. **No attestation claims, anywhere.** BraiNIX runs on one platform, it has no TPM, and it cannot attest
   or seal. Code, protocol fields, log lines, and docs must not imply otherwise (`INV-BOOT-AS-001`), and
   must not point at another target as the attested option — there is none.

## Checks

Before opening a pull request, please run these against the **frozen x86-64 reference** — it is not a
supported platform, but it must keep building, and today it is the only bare-metal target that exists:

```bash
cargo check   --target x86_64-unknown-none
cargo fmt     --all -- --check
cargo clippy  --workspace --all-targets
cargo build   --release --offline --target x86_64-unknown-none
bin/run-brainx.sh --once    # live boot still reaches "BraiNIX: boot complete"
```

Host-target unit tests:

```bash
cargo test -p brainix-kernel --target <your-host-target> --lib
```

## Pull requests

- Keep changes surgical and traceable — every changed line should trace to the stated goal.
- Use clear, conventional commit messages (`fix(boot): …`, `feat(process): …`, `docs: …`).
- Describe what changed, which invariant it touches, and how you verified it.
- Match the surrounding style even where you would personally do it differently.

## License

By contributing, you agree that your contributions will be licensed under the
[GNU Affero General Public License, version 3](LICENSE) — the same terms as the project itself — without
any additional terms.
