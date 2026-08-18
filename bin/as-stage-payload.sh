#!/bin/bash
#
# Build a boot-object payload and assemble everything the install needs.
#
#   ./bin/as-stage-payload.sh [payload-name] [output-dir]
#   ./bin/as-stage-payload.sh brainix-kernel ~/brainix-boot
#
# WHY THIS IS A SCRIPT
#
# The install happens in recoveryOS, where there is no shasum, no package
# manager, no editor worth the name, and a camera pointed at the screen instead
# of a terminal you can scroll. Everything that can be decided beforehand must
# be decided beforehand. Assembling the directory by hand is how a stale binary
# gets installed under a clean-looking log -- which happened: the first staged
# image was a leftover build with a different watchdog constant, and only the
# size-and-hash comparison caught it.
#
# So this builds from the current tree, recomputes the manifest entry, and
# verifies the staged bytes against it. If it prints STAGED, the directory is
# consistent with the source you have checked out.
#
# WHAT IT DELIBERATELY DOES NOT DO
#
# It does not copy anything to the mini. The mini boots m1n1 and has no
# reachable macOS, so there is nothing to copy to until somebody selects a
# different startup volume -- which needs the power button held. See the runbook
# section 5a.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PAYLOAD_NAME="${1:-brainix-kernel}"
OUT="${2:-${REPO}/../brainix-boot-stage}"

TOOLCHAIN="nightly-2025-12-01"
TARGET="aarch64-unknown-none-softfloat"
TOOLCHAIN_BIN="${HOME}/.rustup/toolchains/${TOOLCHAIN}-aarch64-apple-darwin/bin"

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

[[ "${PAYLOAD_NAME}" == "brainix-kernel" ]] || \
  die "only brainix-kernel is built here; the stub has bin/as-boot.sh and m1n1 is vendored"
[[ -x "${TOOLCHAIN_BIN}/cargo" ]] || die "pinned toolchain missing at ${TOOLCHAIN_BIN}"

# Build WITHOUT smp-bench. That feature puts a 64 MiB buffer in .bss, and .bss
# is zeroed past the load address by the kernel itself -- as a boot object that
# is 64 MiB of zeroes over firmware's own structures. See src/kernel/Cargo.toml.
echo "==> building ${PAYLOAD_NAME} (no smp-bench)"
cd "${REPO}/src/kernel"
RUSTC="${TOOLCHAIN_BIN}/rustc" RUSTDOC="${TOOLCHAIN_BIN}/rustdoc" \
  "${TOOLCHAIN_BIN}/cargo" build --target "${TARGET}" --features kernel-binary --release \
  >/dev/null || die "kernel build failed; run it directly for the reason"
cd "${REPO}"

OBJCOPY="$(find "${HOME}/.rustup/toolchains" -name llvm-objcopy 2>/dev/null | head -1)"
NM="$(find "${HOME}/.rustup/toolchains" -name llvm-nm 2>/dev/null | head -1)"
[[ -n "${OBJCOPY}" && -n "${NM}" ]] || die "no llvm-objcopy/llvm-nm in the rustup toolchains"

ELF="${REPO}/target/${TARGET}/release/brainix"
FILE="$(awk -F'\t' -v w="${PAYLOAD_NAME}" '$1==w{print $2}' "${REPO}/bin/payloads.tsv")"
[[ -n "${FILE}" ]] || die "payloads.tsv has no entry named ${PAYLOAD_NAME}"

mkdir -p "${OUT}"
"${OBJCOPY}" -O binary "${ELF}" "${OUT}/${FILE}"

# The entry point must be offset 0 and it must be the assembly shim, not a Rust
# function whose prologue uses a stack pointer nobody set. Checked here as well
# as in the chainload script because this is the copy that gets installed.
START_ADDR="$("${NM}" "${ELF}" | awk '/ T _start$/ {print $1}')"
[[ "${START_ADDR}" == "0000000000000000" ]] || \
  die "_start is at 0x${START_ADDR}, not 0 -- kmutil would install an image that cannot be entered"

SIZE="$(wc -c < "${OUT}/${FILE}" | tr -d ' ')"
SHA="$(shasum -a 256 "${OUT}/${FILE}" | awk '{print $1}')"

# Rewrite the manifest row from what was actually built, then copy that manifest
# alongside. The staged directory is then self-consistent by construction rather
# than by somebody remembering to update two places.
python3 - "${PAYLOAD_NAME}" "${SIZE}" "${SHA}" "${REPO}/bin/payloads.tsv" <<'PY'
import sys
name, size, sha, path = sys.argv[1:5]
lines = open(path).read().split('\n')
out = []
changed = False
for ln in lines:
    if ln.startswith(name + '\t'):
        f = ln.split('\t'); f[2] = size; f[3] = sha; ln = '\t'.join(f); changed = True
    out.append(ln)
if not changed:
    raise SystemExit(f'no row for {name} in {path}')
open(path, 'w').write('\n'.join(out))
PY

cp "${REPO}/bin/payloads.tsv" \
   "${REPO}/bin/as-install-boot-object.sh" \
   "${REPO}/bin/as-preflight.sh" \
   "${REPO}/bin/as-verify-install.sh" "${OUT}/"

# Verify the staged bytes against the staged manifest, the same way the
# installer will at the machine. A staging step that does not check is a staging
# step that ships whatever was lying around.
M_SIZE="$(awk -F'\t' -v w="${PAYLOAD_NAME}" '$1==w{print $3}' "${OUT}/payloads.tsv")"
M_SHA="$(awk -F'\t' -v w="${PAYLOAD_NAME}" '$1==w{print $4}' "${OUT}/payloads.tsv")"
[[ "${SIZE}" == "${M_SIZE}" ]] || die "staged size ${SIZE} != manifest ${M_SIZE}"
[[ "${SHA}" == "${M_SHA}" ]] || die "staged hash ${SHA} != manifest ${M_SHA}"

cat <<EOF

STAGED: ${OUT}
  payload  ${FILE}  ${SIZE} bytes
  sha256   ${SHA}
  entry    0 (assembly shim, verified at offset 0)

Still needed at the machine, and neither can be done from here:

  1. A .admin file in that directory: admin username on line 1, password on
     line 2. It is read from a file rather than passed on the command line so
     it stays out of shell history. Never commit it.
  2. The directory copied to /Users/Shared/brainix-boot on the mini, which
     needs the mini booted into macOS.

Then, from the recoveryOS Terminal:

  sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh
  sh /Volumes/Data/Users/Shared/brainix-boot/as-install-boot-object.sh ${PAYLOAD_NAME}
EOF
