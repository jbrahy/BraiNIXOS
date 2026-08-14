#!/usr/bin/env bash
#
# INV-BOOT's first clause, checked: a third party can rebuild the published
# payload bit for bit (X-T3).
#
# Builds the bare-metal payload twice, into two target directories that share
# nothing, and compares the artifacts byte for byte. A difference means the
# build depends on something outside the source tree -- a path, a timestamp, a
# host name, an environment variable -- and every one of those makes the
# published payload and the deployed payload different objects while the
# release notes claim they are the same.
#
# What this cannot check, stated so nobody reads more into a pass than is
# there: it builds twice on **one machine with one toolchain**. A genuine
# reproducibility claim is cross-machine and cross-checkout, and the difference
# matters -- an absolute path baked into a binary shows up here only because
# the two target directories differ, while a `/home/runner` baked in on CI and
# a `/Users/...` baked in locally would need two machines to catch. This is the
# cheap half, and it catches the common causes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

WORK="${TMPDIR:-/tmp}/brainix-repro-$$"
mkdir -p "${WORK}/first" "${WORK}/second"
trap 'rm -rf "${WORK}"' EXIT

ARTIFACTS=(
  "x86_64-unknown-none/release/brainix"
  "x86_64-unknown-none/release/brainix-bootloader"
  "x86_64-unknown-none/release/brainix-shell"
)

build_into() {
  local target_dir="$1"
  CARGO_TARGET_DIR="${target_dir}" cargo build --release \
    --target x86_64-unknown-none --features kernel-binary \
    --manifest-path src/kernel/Cargo.toml >/dev/null
  CARGO_TARGET_DIR="${target_dir}" cargo build --release \
    --target x86_64-unknown-none \
    --manifest-path src/bootloader/Cargo.toml >/dev/null
  CARGO_TARGET_DIR="${target_dir}" cargo build --release \
    --target x86_64-unknown-none -p brainix-shell >/dev/null
}

echo "=== build one"
build_into "${WORK}/first"
echo "=== build two, in a directory sharing nothing with the first"
build_into "${WORK}/second"

status=0
for artifact in "${ARTIFACTS[@]}"; do
  first="${WORK}/first/${artifact}"
  second="${WORK}/second/${artifact}"
  if [ ! -f "${first}" ] || [ ! -f "${second}" ]; then
    echo "MISSING: ${artifact}"
    status=1
    continue
  fi
  if cmp -s "${first}" "${second}"; then
    echo "identical: ${artifact}  ($(wc -c < "${first}" | tr -d ' ') bytes)"
  else
    echo "DIFFERS:   ${artifact}"
    echo "  first:  $(shasum -a 256 "${first}" | cut -d' ' -f1)"
    echo "  second: $(shasum -a 256 "${second}" | cut -d' ' -f1)"
    status=1
  fi
done

if [ "${status}" -ne 0 ]; then
  echo
  echo "reproducible build: FAIL -- the payload depends on something outside the source"
  exit 1
fi

echo
echo "reproducible build: PASS -- every artifact is byte-identical across two builds"
