#!/usr/bin/env python3
"""Clippy suppressions: an allowlist that only shrinks (X-T2 / B4).

Clippy is green across the bare-metal target and both host architectures. That
is a fact about today, and the roadmap's B4 asks for something stronger: that
it *stays* green, and that the suppression set does not quietly grow while the
job keeps passing. A lint that is green because everything noisy is suppressed
is a lint nobody is running.

THE RULE
--------
Every `allow(clippy::...)` in the tree must sit in a file this script names,
with a reason. A new suppression anywhere else fails the gate.

WHY SUPPRESSIONS EXIST AT ALL
-----------------------------
Two reasons, and neither is "the lint was annoying":

  * The **frozen x86-64 reference** (decision #26). It stays in tree and stays
    building as the implementation the aarch64 port is written against, and
    changing it earns no platform progress while risking the one build that
    currently works. The aarch64 code that replaces it is held to the
    unsuppressed bar.
  * **Test files**, where `unwrap`, `expect` and `panic` are how a test reports
    a failure. Denying them in test code would mean writing tests that cannot
    fail informatively.

Usage:
    bin/lint-suppressions.py           # enforce
    bin/lint-suppressions.py --list    # every suppression, with its file
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Trees permitted to carry clippy suppressions wholesale, with the reason.
#
# These are the frozen x86-64 reference (#26) and the userland shell that runs
# on it. They stay in tree and stay building as the implementation the aarch64
# port is written against; changing them earns no platform progress and risks
# the one build that currently works. **The aarch64 code that replaces them is
# held to the unsuppressed bar**, which is the point of freezing rather than
# fixing.
PERMITTED_TREES = {
    "src/kernel/": "frozen x86-64 reference (#26) -- raw arithmetic, hardware-fidelity casts, and the SSH server scheduled for deletion at P2-T6",
    "src/bootloader/": "frozen x86-64 reference (#26) -- the multiboot2 boot path",
    "userland/shell/": "the shell that runs on the frozen reference (#26)",
}

# Individual files outside those trees, each with the reason its suppression is
# correct rather than convenient. This is the list that must not grow silently:
# everything here is architecture-neutral code written since the pivot, and a
# suppression in it is a decision rather than an inheritance.
PERMITTED_FILES = {
    "src/bsp/src/record.rs": (
        "`absurd_extreme_comparisons` on two `>=` guards against MAX_RECORD_SEQ. "
        "BSP v2 §8 makes the *values* in its ceiling table tunable and only the "
        "presence of a hard bound fixed, so `>=` stays correct if MAX_RECORD_SEQ "
        "is ever tuned below u32::MAX and `==` would silently stop guarding at "
        "exactly that moment. The lint is right about today's constant and wrong "
        "about the contract."
    ),
}

SUPPRESSION = re.compile(r"#!?\[allow\(\s*clippy::")


def is_test_path(path: Path) -> bool:
    """Test files may suppress: unwrap and panic are how a test reports failure."""
    parts = path.parts
    return "tests" in parts or "fuzz_targets" in parts or path.name.startswith("test_")


def scan() -> list[tuple[str, int, str]]:
    found = []
    for path in sorted(REPO_ROOT.rglob("*.rs")):
        relative = path.relative_to(REPO_ROOT)
        text = str(relative)
        if text.startswith(("target/", "vendor/")) or "/target/" in text or "/vendor/" in text:
            continue
        if is_test_path(relative):
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(lines, start=1):
            if SUPPRESSION.search(line):
                found.append((text, number, line.strip()))
    return found


def main() -> int:
    found = scan()
    listing = "--list" in sys.argv

    def permitted(path: str) -> bool:
        if path in PERMITTED_FILES:
            return True
        return any(path.startswith(tree) for tree in PERMITTED_TREES)

    unpermitted = [entry for entry in found if not permitted(entry[0])]

    if listing:
        for path, number, line in found:
            mark = "permitted" if permitted(path) else "NOT PERMITTED"
            print(f"{path}:{number}  [{mark}]  {line}")
        print()

    in_frozen = sum(
        1 for entry in found if any(entry[0].startswith(tree) for tree in PERMITTED_TREES)
    )
    in_neutral = len(found) - in_frozen - len(unpermitted)
    print(
        f"clippy suppressions: {len(found)} total -- {in_frozen} in the frozen reference, "
        f"{in_neutral} in named architecture-neutral files, {len(unpermitted)} unaccounted for"
    )

    if unpermitted:
        print()
        print("A suppression outside the permitted set. Fix the lint, or add the file")
        print("to PERMITTED in this script with the reason it belongs there -- and")
        print("expect that reason to be read.")
        for path, number, line in unpermitted:
            print(f"  {path}:{number}  {line}")
        return 1

    # Report named files that no longer suppress anything: the set is meant to
    # shrink, and an entry that has become unnecessary should go rather than sit
    # there making the list look longer than the problem.
    suppressing = {entry[0] for entry in found}
    stale = [path for path in PERMITTED_FILES if path not in suppressing]
    if stale:
        print()
        print("These files are named as suppressing and no longer do. Remove them")
        print("from PERMITTED_FILES so the list keeps meaning what it says:")
        for path in stale:
            print(f"  {path}")
        return 1

    print("lint suppressions: PASS -- every one is in a file that states why")
    return 0


if __name__ == "__main__":
    sys.exit(main())
