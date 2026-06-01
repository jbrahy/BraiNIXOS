<!-- Thanks for contributing to BraiNIX. Please keep changes surgical and traceable. -->

## What does this change?

<!-- A short description of the change and the motivation. -->

## Invariant / security impact

<!-- Which named invariant does this touch or enforce (e.g. INV-AUTH, INV-MEM, INV-IPC)?
     If it adds `unsafe`, link the allowlist entry in docs/security/UNSAFE_CODE_POLICY.md. -->

## How was it verified?

<!-- Tests added/run, and the live-boot result if relevant. "Asserted is not enforced." -->

## Checklist

- [ ] `cargo fmt --all -- --check` is clean
- [ ] `cargo clippy --workspace --all-targets` is clean
- [ ] `cargo build --release --offline --target x86_64-unknown-none` succeeds
- [ ] Host unit tests pass
- [ ] `bin/run-brainx.sh --once` still reaches `BraiNIX: boot complete` (for kernel/boot changes)
- [ ] Any new `unsafe` is on the allowlist with a `SAFETY:` block
- [ ] No new external dependencies
