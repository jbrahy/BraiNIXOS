#!/bin/bash
#
# Lint the code CI does not: tests, benches and examples.
#
#   ./bin/clippy-all-targets-gate.sh
#
# WHY THIS EXISTS
#
# CI runs `cargo clippy --workspace -- -D warnings`, which compiles libs and
# bins. It does not pass `--all-targets`, so `#[cfg(test)]` modules, the
# `tests/` directory, `benches/` and `examples/` are never linted at all.
#
# That gap was found on 2026-08-19 the slow way. Eight test files added over two
# days were each violating the workspace's own denied lints -- expect_used,
# unwrap_used, arithmetic_side_effects -- and every report of "clippy clean"
# during that stretch was made after checking only the lib. The lints were
# denied, the code violated them, and nothing anywhere said so.
#
# WHAT IT ASSERTS, AND WHAT THAT IS WORTH
#
# That every host-testable target compiles with the workspace lint set.
# Test code legitimately needs some of those lints relaxed: a test that cannot
# use `expect` cannot assert a `Result` is `Ok`. So the bar is not "no
# suppressions in tests", it is "a suppression is written down". Each test
# module carries its own `#[allow(..)]`, which is visible in review, rather than
# the lint silently not running.
#
# The lint-suppressions gate deliberately does NOT count these: it skips test
# paths and `#[cfg(test)]` items because its subject is production code. The two
# gates cover disjoint sets on purpose, and neither one alone is the whole
# picture.
#
# WHAT IS EXCLUDED AND WHY
#
# The bare-metal crates. `--all-targets` builds a test harness for a `no_std`
# binary that supplies its own `#[panic_handler]`, which collides with the one
# libtest brings, and the failure is `duplicate lang item panic_impl` rather
# than anything about lints. Those crates are linted for their real target by
# the CI step at .github/workflows/ci.yml:46.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "${REPO}"

TARGET="$(uname -m | sed 's/arm64/aarch64/')-apple-darwin"
[[ "$(uname -s)" == "Darwin" ]] || TARGET="$(uname -m)-unknown-linux-gnu"

EXCLUDE=(
  # Bare-metal: own panic handler, linted on x86_64-unknown-none in CI.
  --exclude brainix-kernel
  --exclude brainix-bootloader
  --exclude brainix-shell
  # Proof shims: built under Kani, not as ordinary test targets.
  --exclude brainix-capability-verify
  --exclude brainix-ipc-verify
  --exclude brainix-bootloader-verify
)

if ! cargo clippy --workspace "${EXCLUDE[@]}" --target "${TARGET}" --all-targets -- -D warnings; then
  cat >&2 <<EOF

CLIPPY (ALL TARGETS) GATE FAILED

Something in a test, bench or example violates the workspace lint set. CI will
not catch this: its clippy step omits --all-targets and never compiles these.

If the lint is one test code should be allowed to break -- expect_used and
unwrap_used usually are, because asserting on a Result needs them -- put an
\`#[allow(..)]\` on that test module, the way the others in the tree do. Write it
down rather than widening the workspace lint set.
EOF
  exit 1
fi

printf 'clippy (all targets) gate: PASS -- tests, benches and examples lint clean\n'
