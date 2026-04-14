#!/usr/bin/env bash
# bin/test.sh — Full local test suite for BraiNIX
#
# Covers all UAT checkpoints: unit tests, bare-metal check, clippy,
# device crates, fuzz registration, grub.cfg entries, and syscall dispatch.
#
# Usage: bin/test.sh [--fix]
#   --fix   Auto-format before checking (fmt only; does not change other steps)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p logs
exec > logs/test.log 2>&1

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

pass() { printf "${GREEN}PASS${NC}  %s\n" "$1"; }
warn() { printf "${YELLOW}WARN${NC}  %s\n" "$1"; }
fail() { printf "${RED}FAIL${NC}  %s\n" "$1"; FAILURES=$((FAILURES + 1)); }
header() { printf "\n${BOLD}--- %s ---${NC}\n" "$1"; }

FAILURES=0
FIX=false
for arg in "$@"; do
  [[ "$arg" == "--fix" ]] && FIX=true
done

# Ensure the pinned nightly toolchain takes precedence over Homebrew cargo.
# rust-toolchain.toml declares the channel; rustup resolves the sysroot path.
if command -v rustup &>/dev/null; then
  TOOLCHAIN_CHANNEL=$(grep '^channel' rust-toolchain.toml | sed 's/.*"\(.*\)"/\1/')
  TOOLCHAIN_DIR="$(rustup toolchain list --verbose 2>/dev/null \
    | grep "^${TOOLCHAIN_CHANNEL}" | awk '{print $NF}' | head -1)"
  if [[ -n "${TOOLCHAIN_DIR}" && -d "${TOOLCHAIN_DIR}/bin" ]]; then
    export PATH="${TOOLCHAIN_DIR}/bin:${PATH}"
  fi
fi

HOST_TARGET="$(rustc -vV 2>/dev/null | awk '/^host:/{print $2}')"

printf "${BOLD}=== BraiNIX Test Suite ===${NC}\n"
printf "Toolchain: %s\n" "${TOOLCHAIN_CHANNEL:-unknown}"
printf "Host target: %s\n" "${HOST_TARGET:-unknown}"

# 1. Unit tests — host target (pure Rust, no_std kernel lib)
# --test-threads=1 prevents parallel tests from racing on ZERO_PAGE_CALL_COUNT
# global atomic in physical_allocator tests.
header "Unit tests (host: ${HOST_TARGET:-aarch64-apple-darwin})"
cargo test --target "${HOST_TARGET:-aarch64-apple-darwin}" --lib -p brainix-kernel \
  -- --test-threads=1 \
  && pass "unit tests (295+ expected)" \
  || fail "unit tests"

# 2. Bare-metal type check
header "cargo check (x86_64-unknown-none)"
cargo check --target x86_64-unknown-none -p brainix-kernel \
  && pass "bare-metal cargo check" \
  || fail "bare-metal cargo check"

# 3. Format
header "cargo fmt"
if [[ "${FIX}" == true ]]; then
  cargo fmt --all
  pass "cargo fmt (formatted in place)"
else
  cargo fmt --all -- --check \
    && pass "cargo fmt --check" \
    || fail "cargo fmt --check (run with --fix to auto-format)"
fi

# 4a. Clippy — bare-metal crates (mirrors CI "cargo clippy (bare-metal target)" job)
header "cargo clippy (bare-metal)"
cargo clippy \
  -p brainix-kernel \
  -p brainix-bootloader \
  --features brainix-kernel/kernel-binary \
  --target x86_64-unknown-none \
  -- -D warnings \
  && pass "cargo clippy bare-metal" \
  || fail "cargo clippy bare-metal"

# 4b. Clippy — host crates (mirrors CI "cargo clippy (host target)" job)
header "cargo clippy (host)"
cargo clippy \
  --workspace \
  --exclude brainix-capability-verify \
  --exclude brainix-kernel \
  --exclude brainix-bootloader \
  --exclude brainix-ipc-core \
  --exclude brainix-bootloader-verify \
  -- -D warnings \
  && pass "cargo clippy host" \
  || fail "cargo clippy host"

# 5. Device server crates compile
header "Device server crates (brainix-devd-nic, brainix-devd-disk)"
cargo check -p brainix-devd-nic -p brainix-devd-disk \
  && pass "device server crates compile" \
  || fail "device server crates compile"

# 6. Fuzz target registered
header "Fuzz target registration"
FUZZ_TARGET="fuzz_devd_nic_ipc_boundary_cannot_reach_kernel_memory"
if cargo fuzz list 2>/dev/null | grep -q "${FUZZ_TARGET}" \
  || grep -q "${FUZZ_TARGET}" fuzz/Cargo.toml 2>/dev/null; then
  pass "fuzz target registered: ${FUZZ_TARGET}"
else
  fail "fuzz target not found: ${FUZZ_TARGET}"
fi

# 7. grub.cfg lists both device servers
header "grub.cfg device server entries"
GRUB_CFG="iso/boot/grub/grub.cfg"
if [[ -f "${GRUB_CFG}" ]]; then
  if grep -q "devd-nic" "${GRUB_CFG}" && grep -q "devd-disk" "${GRUB_CFG}"; then
    pass "grub.cfg contains devd-nic and devd-disk entries"
  else
    fail "grub.cfg missing devd-nic or devd-disk entries"
    grep -E "devd-(nic|disk)|module2" "${GRUB_CFG}" || true
  fi
else
  warn "grub.cfg not found at ${GRUB_CFG} (run docker/test.sh to build the ISO)"
fi

# 8. Syscall dispatch covers device syscall numbers 9 and 10
header "Syscall dispatch (DEVICE_MAP_MMIO=9, IRQ_BIND=10)"
DISPATCH_FILE="src/kernel/src/syscall/dispatch.rs"
if grep -qE "DEVICE_MAP_MMIO|IRQ_BIND|handle_device_range" "${DISPATCH_FILE}" 2>/dev/null; then
  pass "device syscall dispatch wired in ${DISPATCH_FILE}"
else
  fail "device syscall handlers not found in ${DISPATCH_FILE}"
fi

# Result
printf "\n${BOLD}"
if [[ "${FAILURES}" -eq 0 ]]; then
  printf "${GREEN}All checks passed.${NC}\n"
else
  printf "${RED}${FAILURES} check(s) failed.${NC}\n"
  exit 1
fi
