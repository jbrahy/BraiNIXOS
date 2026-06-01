# Contributing to BraiNIX

Thank you for your interest. BraiNIX is a security-first microkernel, and it holds a deliberately high
bar: every change should leave the system as auditable and as structurally secure as it found it.

Please also read the [Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities must **not** be filed
as public issues — see the [Security Policy](SECURITY.md).

## Before you start

- Read [`docs/NORTH_STAR.md`](docs/NORTH_STAR.md) (the timeless target), [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md),
  and the relevant docs under [`docs/architecture/`](docs/architecture/) and [`docs/security/`](docs/security/).
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

## Checks

Before opening a pull request, please run:

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

By contributing, you agree that your contributions will be dual licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the user's option, without any additional terms.
