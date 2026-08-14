#!/usr/bin/env python3
"""Line-coverage gate: 100% of reachable lines, exclusions justified in code.

NOT the same thing as ``tools/proof-coverage``. That tracks INVARIANT coverage —
which of the eight headline invariants have Kani proofs. This measures whether
tests actually execute the code. Both are required; neither substitutes for the
other, and conflating them is how "our tests are good" becomes unfalsifiable.

THE RULE
--------
Every uncovered line must carry a ``COVERAGE-EXEMPT:`` marker with a reason, on
the line itself or within the eight lines above it. An uncovered line without
one fails the gate. There is no percentage floor to drift under: the target is
100% of *reachable* lines, and the exemption list is the honest remainder.

WHY EXEMPTIONS EXIST AT ALL
---------------------------
These crates are fail-closed hostile-input parsers, and they carry defence in
depth on invariants already validated upstream — ``record_base(..)?`` after the
section layout was checked, ``checked_add`` guards that need a 2^64-byte input
to fire. Executing those lines would mean constructing invalid internal state,
which means adding test-only constructors that punch a hole in exactly the
encapsulation the safety argument rests on; or deleting the guards, which makes
a hostile-input parser strictly worse. "Unreachable today" is also precisely the
assumption that stops being true after a refactor, which is why the guards stay
and the exemption is written down instead.

So the number is not the point. The point is that every gap is named, has a
stated reason, and is reviewable in the diff that introduces it.

Usage:
    bin/coverage-gate.py            # enforce
    bin/coverage-gate.py --report   # print, enforce nothing
    bin/coverage-gate.py --list     # every unjustified line, with source
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

CRATES = [
    "brainix-adt",
    "brainix-bsp",
    "brainix-transport-crypto",
    "brainix-bxw1",
    "brainix-tokenizer",
    "brainix-tensor",
    "brainix-transformer",
    "brainix-servd",
    "brainix-modeld",
    "brainix-inferd",
    "brainix-dart",
    "brainix-bsp-client",
    "brainix-datapath",
    "brainix-sha256",
    "brainix-perf-baseline",
    "brainix-aarch64-mmu",
]

# Whole files excluded from measurement. Each entry names why it cannot be
# line-covered. An entry added without a reason fails review.
#
#   .*-verify/      Kani harnesses. A symbolic engine executes those, not the
#                   test harness; their evidence is the proof, gated separately.
#   boot-stub-apple/src/main.rs
#                   Bare-metal entry: volatile MMIO, #![no_main], diverging
#                   panic handler. Deliberately branch-free; the library behind
#                   it is measured.
#   kernel/src/(arch|net|ssh)/
#                   Frozen x86-64 reference (#26) and the SSH tree P2-T6
#                   orphans. Cannot execute on a host, and has no future.
IGNORE_REGEX = r"(.*-verify/)|(boot-stub-apple/src/main\.rs)|(kernel/src/(arch|net|ssh)/)"

EXEMPT_MARKER = "COVERAGE-EXEMPT:"
# A multi-line call expression puts the uncovered `)?;` several lines below the
# marker that explains it, so the lookback has to span one call. Kept tight
# enough that a marker cannot silently excuse an unrelated line further down.
EXEMPT_LOOKBACK = 8

UNCOVERED = re.compile(r"^\s*(\d+)\|\s*0\|")
SOURCE_HEADER = re.compile(r"^(/.*\.rs):$")


def text_report(crate: str, target: str) -> str:
    result = subprocess.run(
        ["cargo", "llvm-cov", "--target", target, "--text",
         "--ignore-filename-regex", IGNORE_REGEX, "-p", crate],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return result.stdout


def uncovered_lines(report: str) -> list[tuple[str, int]]:
    """Every (file, line) the tests never executed."""
    found: list[tuple[str, int]] = []
    current: str | None = None
    for raw in report.splitlines():
        header = SOURCE_HEADER.match(raw)
        if header:
            current = header.group(1)
            continue
        hit = UNCOVERED.match(raw)
        if hit and current:
            found.append((current, int(hit.group(1))))
    return found


def is_exempt(path: str, line_number: int) -> str | None:
    """The stated reason, if this line is marked exempt."""
    try:
        lines = Path(path).read_text(errors="ignore").splitlines()
    except OSError:
        return None
    lowest = max(0, line_number - 1 - EXEMPT_LOOKBACK)
    for candidate in lines[lowest:line_number]:
        if EXEMPT_MARKER in candidate:
            return candidate.split(EXEMPT_MARKER, 1)[1].strip()
    return None


def main() -> int:
    report_only = "--report" in sys.argv
    target = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout
    host = next(l.split()[1] for l in target.splitlines() if l.startswith("host:"))

    unjustified: list[str] = []
    total_exempt = 0

    print(f"{'CRATE':<28} {'UNCOVERED':>10} {'EXEMPT':>8} {'UNJUSTIFIED':>12}")
    print("-" * 62)

    for crate in CRATES:
        found = uncovered_lines(text_report(crate, host))
        exempt = 0
        bad: list[str] = []
        for path, line_number in found:
            reason = is_exempt(path, line_number)
            if reason:
                exempt += 1
            else:
                rel = path.replace(str(REPO_ROOT) + "/", "")
                bad.append(f"{rel}:{line_number}")
        total_exempt += exempt
        unjustified.extend(bad)
        flag = "" if not bad else "  <-- FAILS"
        print(f"{crate:<28} {len(found):>10} {exempt:>8} {len(bad):>12}{flag}")

    print("-" * 62)
    print(f"{'TOTAL':<28} {'':>10} {total_exempt:>8} {len(unjustified):>12}")

    if "--list" in sys.argv:
        print()
        for entry in unjustified:
            path, _, number = entry.rpartition(":")
            try:
                source = (REPO_ROOT / path).read_text(errors="ignore").splitlines()
                text = source[int(number) - 1].strip()
            except (OSError, IndexError, ValueError):
                text = "<unreadable>"
            print(f"{entry:<48} {text}")
        return 0

    if report_only:
        return 0

    if unjustified:
        print("\nCOVERAGE GATE FAILED — these lines are uncovered and unexplained.",
              file=sys.stderr)
        print("Either write a test that executes them, or mark them",
              f"`{EXEMPT_MARKER} <reason>`:", file=sys.stderr)
        for entry in unjustified[:40]:
            print(f"  {entry}", file=sys.stderr)
        if len(unjustified) > 40:
            print(f"  ... and {len(unjustified) - 40} more", file=sys.stderr)
        return 1

    print(f"\ncoverage gate: PASS — 100% of reachable lines, "
          f"{total_exempt} exempt with stated reasons")
    return 0


if __name__ == "__main__":
    sys.exit(main())
