#!/usr/bin/env bash
#
# Line/branch coverage gate for the covered set.
#
# NOT the same thing as `tools/proof-coverage/`. That tracks INVARIANT coverage —
# which of the eight headline invariants have Kani proofs (62.5%, bar 80%). This
# measures whether tests actually execute the code. Both are required; neither
# substitutes for the other, and conflating them is how "our tests are good"
# becomes an unfalsifiable claim.
#
# THE RATCHET. Each crate's floor is its measured coverage, and the target is
# 100%. Floors only ever move up. A crate that reaches 100% has its floor pinned
# there and can never regress. Deliberately not set to an aspirational 100%
# everywhere on day one: a gate that is red for months is a gate everyone learns
# to ignore, which is exactly how the Prusti job sat broken and how 257 clippy
# errors hid behind a formatting failure.
#
# Usage:
#   bin/coverage-gate.sh          # enforce floors
#   bin/coverage-gate.sh --report # print the table, enforce nothing

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HOST_TARGET="${COVERAGE_TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"

# crate:floor — floor is a percentage of *regions*, the strictest of the three
# metrics llvm-cov reports. Raise a floor the moment its crate exceeds it.
CRATE_FLOORS=(
    "brainix-adt:86"
    "brainix-bsp:94"
    "brainix-transport-crypto:94"
    "brainix-bxw1:91"
    "brainix-tokenizer:91"
    "brainix-tensor:95"
    "brainix-transformer:88"
)

# Excluded from measurement. The list is the deliverable, not the escape hatch:
# every entry names why it cannot be line-covered, and an entry added without a
# reason fails review.
#
#   .*-verify/         Kani harnesses. Executed by a symbolic engine, not the
#                      test harness; their evidence is the proof, gated separately.
#   boot-stub-apple/src/main.rs
#                      Bare-metal entry, volatile MMIO, #![no_main]. Deliberately
#                      branch-free; the library behind it is in the covered set.
#   kernel/src/(arch|net|ssh)/
#                      Frozen x86-64 reference (#26) and the SSH tree P2-T6
#                      orphans. Cannot execute on the host, and has no future.
IGNORE_REGEX='(.*-verify/)|(boot-stub-apple/src/main\.rs)|(kernel/src/(arch|net|ssh)/)'

declare -a FAILED=()
declare -a AT_TARGET=()

printf "%-28s %8s %8s %9s %7s\n" "CRATE" "REGIONS" "MISSED" "COVERAGE" "FLOOR"
printf -- "----------------------------------------------------------------------\n"

for entry in "${CRATE_FLOORS[@]}"; do
    crate="${entry%%:*}"
    floor="${entry##*:}"

    summary="$(cargo llvm-cov --target "$HOST_TARGET" --summary-only \
                 --ignore-filename-regex "$IGNORE_REGEX" \
                 -p "$crate" 2>/dev/null | tail -1)"

    regions="$(awk '{print $2}' <<<"$summary")"
    missed="$(awk '{print $3}' <<<"$summary")"
    percent="$(awk '{gsub(/%/,"",$4); print $4}' <<<"$summary")"

    if [[ -z "${percent:-}" ]]; then
        printf "%-28s %8s %8s %9s %7s  MEASUREMENT FAILED\n" "$crate" "-" "-" "-" "$floor"
        FAILED+=("$crate: could not measure")
        continue
    fi

    whole="${percent%%.*}"
    status=""
    if (( whole < floor )); then
        status="BELOW FLOOR"
        FAILED+=("$crate: ${percent}% < ${floor}%")
    elif [[ "$missed" == "0" ]]; then
        status="100% — pin the floor"
        AT_TARGET+=("$crate")
    fi

    printf "%-28s %8s %8s %8s%% %6s%%  %s\n" \
        "$crate" "$regions" "$missed" "$percent" "$floor" "$status"
done

printf -- "----------------------------------------------------------------------\n"

if [[ "${1:-}" == "--report" ]]; then
    exit 0
fi

if (( ${#AT_TARGET[@]} > 0 )); then
    echo
    echo "At 100% — raise these floors to 100 in CRATE_FLOORS so they cannot regress:"
    printf '  %s\n' "${AT_TARGET[@]}"
fi

if (( ${#FAILED[@]} > 0 )); then
    echo
    echo "COVERAGE GATE FAILED:" >&2
    printf '  %s\n' "${FAILED[@]}" >&2
    exit 1
fi

echo "coverage gate: PASS"
