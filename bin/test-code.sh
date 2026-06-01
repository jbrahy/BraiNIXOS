#!/usr/bin/env bash
# Local CI equivalent — mirrors what GitHub Actions runs.
# Usage: bin/test-code.sh [--fix]
#
# --fix   Auto-format code before checking (does not change clippy or check).

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { printf "${GREEN}PASS${NC}  %s\n" "$1"; }
warn() { printf "${YELLOW}WARN${NC}  %s\n" "$1"; }
fail() { printf "${RED}FAIL${NC}  %s\n" "$1"; exit 1; }
header() { printf "\n${BOLD}--- %s ---${NC}\n" "$1"; }

FIX=false
for arg in "$@"; do
  [[ "$arg" == "--fix" ]] && FIX=true
done

printf "${BOLD}=== BraiNIX Local Test Suite ===${NC}\n"
printf "Target: x86_64-unknown-none | Toolchain: $(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1)\n"

# 1. Type check — bare-metal target
header "cargo check (x86_64-unknown-none)"
cargo check \
  --workspace \
  --exclude brainix-capability-verify \
  --target x86_64-unknown-none \
  && pass "cargo check" || fail "cargo check"

# 2. Format
header "cargo fmt"
if [[ "$FIX" == true ]]; then
  cargo fmt --all
  pass "cargo fmt (formatted in place)"
else
  cargo fmt --all -- --check \
    && pass "cargo fmt --check" \
    || fail "cargo fmt --check  (run with --fix to auto-format)"
fi

# 3. Lint — all targets, deny all warnings
header "cargo clippy"
cargo clippy \
  --workspace \
  --all-targets \
  -- -D warnings \
  && pass "cargo clippy" || fail "cargo clippy"

# 4. Unit tests — capability-verify uses std (Kani host shim)
header "cargo test (brainix-capability-verify)"
cargo test -p brainix-capability-verify \
  && pass "capability-verify tests" \
  || fail "capability-verify tests"

printf "\n${BOLD}${GREEN}All checks passed.${NC}\n"
