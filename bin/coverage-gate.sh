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
# TWO METRICS, ONE TARGET. The gate enforces LINE coverage, whose target is
# 100%, and tracks REGION coverage as a ratcheting floor with no 100% target.
#
# That split is deliberate and it is not a softening. Regions count every branch
# of every condition, so a defensive `if a && b` contributes regions for
# combinations that cannot occur -- an unreachable region is not a missing test,
# and demanding 100% of them would push toward deleting guards to satisfy a
# number. Lines are the metric that means "a test executed this code", and 100%
# of them is both achievable and worth having. Measured spread on this tree:
# tensor 99.73% lines against 96.83% regions; transformer 96.57% against 88.30%.
#
# THE RATCHET. Floors only ever move up. A crate reaching 100% lines gets pinned
# there and can never regress. Floors deliberately start at measured values
# rather than an aspirational 100%: a gate that is red for months is a gate
# everyone learns to ignore, which is exactly how the Prusti job sat broken for
# its entire existence and how 257 clippy errors hid behind a formatting
# failure.
#
# Usage:
#   bin/coverage-gate.sh          # enforce floors
#   bin/coverage-gate.sh --report # print the table, enforce nothing

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

HOST_TARGET="${COVERAGE_TARGET:-$(rustc -vV | awk '/^host:/{print $2}')}"

# crate:line_floor:region_floor
# Raise a floor the moment its crate exceeds it. line_floor's destination is 100.
CRATE_FLOORS=(
    "brainix-adt:92:86"
    "brainix-bsp:97:94"
    "brainix-transport-crypto:95:94"
    "brainix-bxw1:97:91"
    "brainix-tokenizer:98:91"
    "brainix-tensor:100:96"   # PINNED at 100% lines - cannot regress
    "brainix-transformer:96:88"
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

printf "%-28s %9s %7s %10s %7s\n" "CRATE" "LINES" "FLOOR" "REGIONS" "FLOOR"
printf -- "--------------------------------------------------------------------------\n"

for entry in "${CRATE_FLOORS[@]}"; do
    crate="$(cut -d: -f1 <<<"$entry")"
    line_floor="$(cut -d: -f2 <<<"$entry")"
    region_floor="$(cut -d: -f3 <<<"$entry")"

    summary="$(cargo llvm-cov --target "$HOST_TARGET" --summary-only \
                 --ignore-filename-regex "$IGNORE_REGEX" \
                 -p "$crate" 2>/dev/null | tail -1)"

    region_pct="$(awk '{gsub(/%/,"",$4); print $4}' <<<"$summary")"
    line_missed="$(awk '{print $9}' <<<"$summary")"
    line_pct="$(awk '{gsub(/%/,"",$10); print $10}' <<<"$summary")"

    if [[ -z "${line_pct:-}" || -z "${region_pct:-}" ]]; then
        printf "%-28s %9s %7s %10s %7s  MEASUREMENT FAILED\n" "$crate" "-" "-" "-" "-"
        FAILED+=("$crate: could not measure")
        continue
    fi

    status=""
    if (( ${line_pct%%.*} < line_floor )); then
        status="LINES BELOW FLOOR"
        FAILED+=("$crate: lines ${line_pct}% < ${line_floor}%")
    elif [[ "$line_missed" == "0" ]]; then
        status="100% lines — pin the floor"
        AT_TARGET+=("$crate")
    fi
    if (( ${region_pct%%.*} < region_floor )); then
        status="${status:+$status; }REGIONS BELOW FLOOR"
        FAILED+=("$crate: regions ${region_pct}% < ${region_floor}%")
    fi

    printf "%-28s %8s%% %6s%% %9s%% %6s%%  %s\n" \
        "$crate" "$line_pct" "$line_floor" "$region_pct" "$region_floor" "$status"
done

printf -- "--------------------------------------------------------------------------\n"

if [[ "${1:-}" == "--report" ]]; then
    exit 0
fi

if (( ${#AT_TARGET[@]} > 0 )); then
    echo
    echo "At 100% lines — pin these line floors to 100 in CRATE_FLOORS:"
    printf '  %s\n' "${AT_TARGET[@]}"
fi

if (( ${#FAILED[@]} > 0 )); then
    echo
    echo "COVERAGE GATE FAILED:" >&2
    printf '  %s\n' "${FAILED[@]}" >&2
    exit 1
fi

echo "coverage gate: PASS"
