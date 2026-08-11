#!/usr/bin/env bash
#
# Build the AS-1a first-light payload, verify its shape, and print the m1n1
# chainload invocation.
#
# This script never talks to hardware. It stops at the raw .bin and tells you
# the command to run, because the rig does not exist yet and a script that
# silently did nothing would be worse than one that says what it would do.
#
# See docs/architecture/AS-1a-first-light-boot-stub.md
#     docs/platform-specs/apple-s5l-uart.md

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE_DIR="${REPO_ROOT}/src/boot-stub-apple"
TARGET="aarch64-unknown-none-softfloat"
TOOLCHAIN="nightly-2025-12-01"

# Homebrew's cargo shadows rustup's on this workstation and does not know about
# rustup toolchains or rust-toolchain.toml, so the pinned toolchain is invoked
# by absolute path rather than by hoping PATH is right.
RUSTUP_HOME_DIR="${RUSTUP_HOME:-${HOME}/.rustup}"
TOOLCHAIN_BIN="${RUSTUP_HOME_DIR}/toolchains/${TOOLCHAIN}-aarch64-apple-darwin/bin"
LLVM_BIN="${RUSTUP_HOME_DIR}/toolchains/${TOOLCHAIN}-aarch64-apple-darwin/lib/rustlib/aarch64-apple-darwin/bin"

if [[ ! -x "${TOOLCHAIN_BIN}/cargo" ]]; then
    echo "error: pinned toolchain not found at ${TOOLCHAIN_BIN}" >&2
    echo "       run: rustup toolchain install ${TOOLCHAIN}" >&2
    exit 1
fi

ELF="${CRATE_DIR}/target/${TARGET}/release/brainix-boot-stub-apple"
BIN="${CRATE_DIR}/target/${TARGET}/release/brainix-boot-stub-apple.bin"

# Cargo discovers .cargo/config.toml from the WORKING DIRECTORY, not from
# --manifest-path. Running from the repo root would pick up the root config's
# `build.target = "x86_64-unknown-none"` and try to build this crate's host
# tests for a bare-metal x86-64 machine. So: cd, always.
cd "${CRATE_DIR}"

echo "==> host tests (the only part that proves anything today)"
RUSTC="${TOOLCHAIN_BIN}/rustc" RUSTDOC="${TOOLCHAIN_BIN}/rustdoc" "${TOOLCHAIN_BIN}/cargo" test --quiet

echo "==> building payload for ${TARGET}"
RUSTC="${TOOLCHAIN_BIN}/rustc" RUSTDOC="${TOOLCHAIN_BIN}/rustdoc" "${TOOLCHAIN_BIN}/cargo" build \
    --target "${TARGET}" --features bare-metal --release

echo "==> verifying image shape"

fail() { echo "  FAIL: $*" >&2; exit 1; }
pass() { echo "  ok:   $*"; }

load_segments="$("${LLVM_BIN}/llvm-readobj" --program-headers "${ELF}" | grep -c 'PT_LOAD' || true)"
[[ "${load_segments}" -eq 1 ]] || fail "expected exactly 1 PT_LOAD, found ${load_segments}"
pass "exactly one loadable segment"

entry="$("${LLVM_BIN}/llvm-readobj" --file-headers "${ELF}" | awk '/Entry:/ {print $2}')"
[[ "${entry}" == "0x0" ]] || fail "entry point is ${entry}, expected 0x0"
pass "entry point at 0x0"

start_addr="$("${LLVM_BIN}/llvm-nm" "${ELF}" | awk '/ T _start$/ {print $1}')"
[[ "${start_addr}" == "0000000000000000" ]] || fail "_start at ${start_addr}, expected offset 0"
pass "_start is the first byte of the image"

machine="$("${LLVM_BIN}/llvm-readobj" --file-headers "${ELF}" | grep -c 'EM_AARCH64' || true)"
[[ "${machine}" -ge 1 ]] || fail "not an aarch64 image"
pass "aarch64 image"

dynamic="$("${LLVM_BIN}/llvm-readobj" --program-headers "${ELF}" | grep -cE 'PT_DYNAMIC|PT_INTERP' || true)"
[[ "${dynamic}" -eq 0 ]] || fail "image requires a dynamic loader (${dynamic} segments)"
pass "no dynamic loader required"

echo "==> flattening to a raw binary"
"${LLVM_BIN}/llvm-objcopy" -O binary "${ELF}" "${BIN}"
size="$(wc -c < "${BIN}" | tr -d ' ')"
pass "raw image: ${BIN} (${size} bytes)"

cat <<EOF

==> next step, on a provisioned rig

  The mini must already be in Permissive Security with m1n1 installed, and
  m1n1's OWN console must already be printing over serial. That is the rig
  acceptance test and it involves none of this code. Do not chainload BraiNIX
  before it passes, or you will be debugging two unknowns at once.

  Then:

    export M1N1DEVICE=/dev/tty.usbmodemXXX
    chainload.py -r ${BIN}

  Expected output:

    [..] BraiNIX: alive          <- liveness, on the fallback UART base
    [OK] BraiNIX: first light    <- banner, on the ADT-derived base

  Reading "alive" but not "first light" means ADT discovery denied and the
  reason follows it on the same console.

  Reading neither means the fallback UART base is wrong (it is a T6030
  observation; this machine is a T6020 and the value is expected to differ),
  or the payload never ran.

EOF
