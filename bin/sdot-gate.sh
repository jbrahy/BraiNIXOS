#!/bin/bash
#
# Assert that the Q8_0 matmul kernels still compile to SDOT.
#
#   ./bin/sdot-gate.sh
#
# WHY THIS EXISTS
#
# The tensor crate's largest win is not written down in its source. There are no
# intrinsics and `grep -rn neon src/tensor/src/` returns nothing, yet the
# quantized matmuls compile to AArch64's SDOT -- 16 int8 multiply-accumulates
# per instruction -- because LLVM recognises the shape of the i8-by-i8 loop.
#
# Measured 2026-08-19: 5.3 GB/s of weight bytes on one core with f32
# activations against 57.0 GB/s on the i8 path, and 7.6x to 11.4x end to end on
# a synthetic model. An order of magnitude, resting on a pattern match that
# nothing asserts. A refactor can delete it with every test still green and no
# diagnostic anywhere.
#
# WHERE THE INSTRUCTIONS ACTUALLY ARE, WHICH IS NOT WHERE I FIRST LOOKED
#
# A whole-archive count is too coarse to be a gate. Counted per symbol:
#
#   matmul_q8_0_q8a        6
#   matmul_q8_0_q8a_rows   6
#   matmul_q4_0_q8a        2
#
# The first version of this script counted the archive total, 14, and would
# have passed while any one of those went to zero. It is per symbol now, and
# the two Q8 entries are the ones a decode runs.
#
# HOW HARD I TRIED TO MAKE IT FAIL
#
# The detection works: pointed at `quantize_activations`, which contains no
# SDOT, it exits 1 with the diagnostic below. That much is tested.
#
# What is NOT demonstrated is a realistic source change that drops SDOT.
# Widening `block_dot_i8`'s accumulators from i32 to i64 -- the obvious way to
# break an int8 dot-product idiom -- changed nothing; all three counts held.
# That is evidence the idiom is more robust than feared. If you find a change
# that does drop it, add it here as the case that proves the tripwire is
# positioned where it needs to be, not merely that it can fire.
#
# WHAT IT DELIBERATELY DOES NOT CHECK
#
# That SDOT is on the hot path, or how many execute per call. Presence per
# symbol is the property that regresses to zero, so presence is what is
# asserted.
#
# It is aarch64-only by construction. On any other host it skips loudly rather
# than passing quietly, because a gate that reports success without running is
# worse than no gate.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="aarch64-apple-darwin"
CRATE="brainix-tensor"

# Symbols that must contain at least one SDOT, and what each is for. These are
# the kernels a decode actually runs: the whole-output form and the row-split
# form the multi-core dispatch uses.
REQUIRED_SYMBOLS=(
  "matmul_q8_0_q8a"
  "matmul_q8_0_q8a_rows"
)

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

case "$(uname -m)" in
  arm64|aarch64) ;;
  *)
    printf 'SKIPPED: the SDOT gate needs an aarch64 host; this is %s.\n' "$(uname -m)"
    printf '  Not a pass. The idiom cannot be checked on a machine that cannot emit it.\n'
    exit 0
    ;;
esac

OBJDUMP="$(find "${HOME}/.rustup/toolchains" -name llvm-objdump 2>/dev/null | head -1)"
[[ -n "${OBJDUMP}" ]] || die "no llvm-objdump in the rustup toolchains"

cd "${REPO}"
cargo build --release -p "${CRATE}" --target "${TARGET}" >/dev/null 2>&1 \
  || die "${CRATE} did not build for ${TARGET}; run cargo build directly for the reason"

LIB="${REPO}/target/${TARGET}/release/lib${CRATE//-/_}.rlib"
[[ -f "${LIB}" ]] || die "no rlib at ${LIB}"

# Attribute each SDOT to the symbol it falls inside. `llvm-objdump` prints
# `<address> <symbol>:` before each function, so the most recent such line owns
# every instruction until the next one.
COUNTS="$("${OBJDUMP}" -d --no-show-raw-insn "${LIB}" 2>/dev/null | awk '
  /^[0-9a-f]+ <.*>:/ { symbol = $0; sub(/^[0-9a-f]+ </, "", symbol); sub(/>:$/, "", symbol) }
  /sdot/             { hits[symbol]++ }
  END                { for (s in hits) printf "%s %d\n", s, hits[s] }
')"

FAILED=0
for wanted in "${REQUIRED_SYMBOLS[@]}"; do
  # Rust mangles as ..._<crate>_<path><len><name>, so the symbol ENDS with the
  # name's byte length followed by the name. Matching the bare name as a
  # substring would count `matmul_q8_0_q8a_rows` under `matmul_q8_0_q8a` too,
  # which is how the first version reported 12 for a function that has 6.
  suffix="${#wanted}${wanted}"
  found="$(printf '%s\n' "${COUNTS}" | awk -v want="${suffix}" '
    length($1) >= length(want) && substr($1, length($1) - length(want) + 1) == want {
      total += $2
    } END { print total + 0 }')"
  if (( found > 0 )); then
    printf '  %-24s %s sdot\n' "${wanted}" "${found}"
  else
    printf '  %-24s NONE  <-- FAILS\n' "${wanted}"
    FAILED=1
  fi
done

if (( FAILED )); then
  cat >&2 <<EOF

SDOT GATE FAILED: a Q8_0 matmul kernel no longer compiles to SDOT.

Every test will still pass and that kernel is roughly an order of magnitude
slower. Look at what changed in the i8 inner loop of src/tensor/src/matmul.rs.
LLVM drops the idiom for small reasons: a bound check it cannot elide, an
accumulator of an unexpected width, a helper that stopped being inlined.

Confirm by hand with:
  ${OBJDUMP} -d --no-show-raw-insn ${LIB} | grep -i sdot
EOF
  exit 1
fi

printf 'sdot gate: PASS -- every Q8_0 kernel still reaches SDOT\n'
