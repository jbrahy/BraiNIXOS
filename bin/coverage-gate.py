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
    bin/coverage-gate.py --stale    # exemption markers that no longer excuse anything
"""

from __future__ import annotations

import json
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
    "brainix-chacha20",
    "brainix-perf-baseline",
    "brainix-aarch64-mmu",
    "brainix-platform-select",
    "brainix-pcie-config",
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

# Crates that legitimately measure ZERO executable lines, and why. Anything
# else reporting zero is a crate the gate cannot see rather than a crate with
# nothing to see, and those are not the same thing -- five crates spent an
# unknown period scoring a clean zero because llvm-cov omits the filename header
# for single-file crates and nothing here noticed.
CODELESS_CRATES = {
    "brainix-datapath": "a doc-only lib.rs; its integration tests exercise "
                        "bsp, servd, inferd and transport-crypto, and their "
                        "coverage is counted against those crates",
}

EXEMPT_MARKER = "COVERAGE-EXEMPT:"
# A multi-line call expression puts the uncovered `)?;` several lines below the
# marker that explains it, so the lookback has to span one call. Kept tight
# enough that a marker cannot silently excuse an unrelated line further down.
EXEMPT_LOOKBACK = 8

UNCOVERED = re.compile(r"^\s*(\d+)\|\s*0\|")
SOURCE_HEADER = re.compile(r"^(/.*\.rs):$")


def run_instrumented(target: str) -> None:
    """Execute every crate's tests ONCE, under instrumentation, into one profile.

    This used to be eighteen separate `cargo llvm-cov -p <crate>` runs, one per
    crate, each of which rebuilds, re-runs and re-reports. That was slow, and
    worse, it was WRONG about once in every few invocations: the first run after
    a source edit could report line numbers from the new source against counts
    from the previous build, inventing uncovered lines that do not exist. It
    misfired twice on 2026-08-19 -- once landing on comment lines, which is
    obvious, and once landing on code, which is not.

    Running the tests once and then reading that one profile eighteen times
    removes the failure mode by construction: every report is a pure read of the
    same profile, so counts and line numbers cannot come from different builds.
    """
    subprocess.run(
        ["cargo", "llvm-cov", "clean", "--profraw-only"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    command = ["cargo", "llvm-cov", "--no-report", "--target", target]
    for crate in CRATES:
        command += ["-p", crate]
    subprocess.run(command, capture_output=True, text=True, cwd=REPO_ROOT)


def text_report(crate: str, target: str) -> str:
    """The per-crate text report, read from the profile `run_instrumented` made."""
    result = subprocess.run(
        ["cargo", "llvm-cov", "report", "--target", target, "--text",
         "--ignore-filename-regex", IGNORE_REGEX, "-p", crate],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return result.stdout


def measured_line_count(crate: str, target: str) -> int:
    """Executable lines llvm-cov actually measured for `crate`.

    Zero means one of two very different things: the crate has no executable
    code, or the gate failed to measure it. Only the first is acceptable, and
    only for crates named in `CODELESS_CRATES`.
    """
    result = subprocess.run(
        ["cargo", "llvm-cov", "report", "--target", target, "--json",
         "--ignore-filename-regex", IGNORE_REGEX, "-p", crate],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return 0
    return sum(
        block.get("totals", {}).get("lines", {}).get("count", 0)
        for block in payload.get("data", [])
    )


def sole_source_file(crate: str, target: str) -> str | None:
    """The one measured file of a single-file crate, or None.

    `llvm-cov`'s TEXT report omits the `path.rs:` header when a crate has
    exactly one file, so there is nothing for `SOURCE_HEADER` to match and
    every uncovered line in that crate is dropped. The JSON export always
    names its files, so it is the way back to the filename.
    """
    result = subprocess.run(
        ["cargo", "llvm-cov", "report", "--target", target, "--json",
         "--ignore-filename-regex", IGNORE_REGEX, "-p", crate],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    names = [
        entry["filename"]
        for block in payload.get("data", [])
        for entry in block.get("files", [])
    ]
    return names[0] if len(names) == 1 else None


def uncovered_lines(report: str, fallback: str | None = None) -> list[tuple[str, int]]:
    """Every (file, line) the tests never executed.

    `fallback` names the file to attribute lines to before any header is seen.
    It exists because a single-file crate's text report has no header at all,
    which silently turned five crates into blind spots -- `brainix-sha256`,
    `brainix-chacha20`, `brainix-dart`, `brainix-perf-baseline` and
    `brainix-pcie-config` reported 0 uncovered while holding 15 uncovered lines
    between them. A gate that cannot see a crate should not score it zero.
    """
    found: list[tuple[str, int]] = []
    current: str | None = fallback
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


def source_line(path: str, line_number: int) -> str:
    """The text at `path:line_number`, or "" if it cannot be read."""
    try:
        return (REPO_ROOT / path).read_text(errors="ignore").splitlines()[line_number - 1].strip()
    except (OSError, IndexError, ValueError):
        return ""


def looks_stale(lines: list[tuple[str, int]]) -> bool:
    """Whether an uncovered set points at lines that cannot BE uncovered.

    llvm-cov emits a count only for lines that carry executable code, so a
    blank line or a comment reported as uncovered means the line numbers came
    from the current source and the counts came from an older build. Cargo
    merges every .profraw it finds, and a build that happened between the
    profile and the report is enough to shift them.

    Observed 2026-08-19: a doc-only edit to math.rs put two comment lines in the
    failure list, and the identical command passed on the next run. A gate that
    fails on comments is a gate nobody believes the next time it is right.
    """
    for path, number in lines:
        text = source_line(path, number)
        if text == "" or text.startswith("//"):
            return True
    return False


def stale_markers(uncovered: set[tuple[str, int]]) -> list[tuple[str, int, str]]:
    """Exemption markers that no longer sit above any uncovered line.

    An exemption is a licence to leave a line untested, and it is granted once
    and then never looked at again. When the line it excused becomes covered --
    a new test reaches it, or a refactor deletes the branch -- the marker stays
    behind, and from then on it silently licenses whatever code drifts into its
    eight-line window instead.

    That is the failure mode this finds: not an uncovered line without a reason,
    which the gate already refuses, but a reason without an uncovered line.
    """
    stale: list[tuple[str, int, str]] = []
    for path in sorted({p for p, _ in uncovered} | set(_marker_files())):
        try:
            lines = (REPO_ROOT / path).read_text(errors="ignore").splitlines()
        except OSError:
            continue
        for index, text in enumerate(lines, start=1):
            if EXEMPT_MARKER not in text:
                continue
            # The marker excuses its own line and the EXEMPT_LOOKBACK lines
            # below it -- the same window `is_exempt` searches, read forwards.
            window = range(index, index + EXEMPT_LOOKBACK + 1)
            if not any((path, number) in uncovered for number in window):
                stale.append((path, index, text.strip()))
    return stale


def _marker_files() -> list[str]:
    """Every tracked source file carrying an exemption marker."""
    result = subprocess.run(
        ["git", "grep", "-l", EXEMPT_MARKER, "--", "*.rs"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    return [line for line in result.stdout.splitlines() if line]


def main() -> int:
    report_only = "--report" in sys.argv
    target = subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout
    host = next(l.split()[1] for l in target.splitlines() if l.startswith("host:"))

    run_instrumented(host)

    unjustified: list[str] = []
    total_exempt = 0
    all_uncovered: set[tuple[str, int]] = set()
    unmeasured: list[str] = []

    print(f"{'CRATE':<28} {'UNCOVERED':>10} {'EXEMPT':>8} {'UNJUSTIFIED':>12}")
    print("-" * 62)

    for crate in CRATES:
        found = uncovered_lines(text_report(crate, host), sole_source_file(crate, host))
        if looks_stale(found):
            # Belt and braces. `run_instrumented` should make this unreachable,
            # so reaching it means an assumption about the profile broke.
            run_instrumented(host)
            found = uncovered_lines(text_report(crate, host), sole_source_file(crate, host))
        exempt = 0
        bad: list[str] = []
        for path, line_number in found:
            all_uncovered.add((path.replace(str(REPO_ROOT) + "/", ""), line_number))
            reason = is_exempt(path, line_number)
            if reason:
                exempt += 1
            else:
                rel = path.replace(str(REPO_ROOT) + "/", "")
                bad.append(f"{rel}:{line_number}")
        if measured_line_count(crate, host) == 0 and crate not in CODELESS_CRATES:
            unmeasured.append(crate)
        total_exempt += exempt
        unjustified.extend(bad)
        flag = "" if not bad else "  <-- FAILS"
        print(f"{crate:<28} {len(found):>10} {exempt:>8} {len(bad):>12}{flag}")

    print("-" * 62)
    print(f"{'TOTAL':<28} {'':>10} {total_exempt:>8} {len(unjustified):>12}")

    if "--stale" in sys.argv:
        stale = stale_markers(all_uncovered)
        print()
        if not stale:
            print("no stale exemptions: every marker still excuses an uncovered line")
            return 0
        print(f"{len(stale)} exemption marker(s) no longer excuse anything:")
        for path, number, text in stale:
            print(f"  {path}:{number}")
            print(f"      {text[:100]}")
        print()
        print("Each of these is a licence with nothing left to license. Delete it,")
        print("or the next uncovered line that drifts into its window inherits it.")
        return 1

    if "--list" in sys.argv:
        print()
        for entry in unjustified:
            path, _, number = entry.rpartition(":")
            print(f"{entry:<48} {source_line(path, int(number))}")
        return 0

    if report_only:
        return 0

    if unmeasured:
        print("\nCOVERAGE GATE FAILED — these crates measured NOTHING.", file=sys.stderr)
        print("Zero uncovered lines because zero lines were seen is not a pass.",
              file=sys.stderr)
        for crate in unmeasured:
            print(f"  {crate}", file=sys.stderr)
        print("\nEither the crate lost its tests, or the report did not generate.",
              file=sys.stderr)
        print("If it genuinely has no executable code, add it to CODELESS_CRATES",
              file=sys.stderr)
        print("with the reason, so the zero is a statement rather than a silence.",
              file=sys.stderr)
        return 1

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
          f"{total_exempt} exempt with stated reasons, "
          f"{len(CRATES) - len(CODELESS_CRATES)} crates measured")
    return 0


if __name__ == "__main__":
    sys.exit(main())
