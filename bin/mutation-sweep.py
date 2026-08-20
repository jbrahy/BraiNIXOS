#!/usr/bin/env python3
"""Break the code on purpose and check that the suite notices.

    ./bin/mutation-sweep.py            # every mutation
    ./bin/mutation-sweep.py --list     # what would run, without running it

WHY THIS EXISTS

Coverage answers "did this line execute". It does not answer "would a wrong
answer have been caught", and on 2026-08-20 that gap was not theoretical twice
in one afternoon:

  - The `Q4_0` prefill split had a fully tested kernel and an unguarded caller.
    Every test in q4_weights.rs decoded ONE token, so all of them took the
    row-split branch. Planting an off-by-worker in the token split left the file
    green. Coverage was satisfied; the branch was undefended.

  - Forcing every `worth_splitting` to `false` -- so nothing splits and the
    decode quietly runs on one core -- leaves every answer CORRECT. Three tests
    failed, all of them refusal tests failing by accident of fixture shape.
    Nothing asserted the fast path was taken.

Both are now caught by name, and both are in the catalogue below so they stay
caught.

WHAT A RESULT MEANS

CAUGHT means at least one test failed with the mutation applied. That is the
bar: not that the right test failed, only that something did. ESCAPED means the
suite accepted a deliberate defect, and that is a finding.

This is NOT exhaustive and is not trying to be. Each entry costs a full
workspace test run, so the catalogue is hand-picked for places where a silent
escape would be worst: the AEAD tag, the tree-depth bound, the quantization
nibble order, the attention grouping, the split branches.

WHY IT IS NOT A CI GATE

A full test run per mutation. At the size of the catalogue that is minutes, and
CI already runs nine gates on every push. Run this when touching a kernel, a
split, or anything in the catalogue's blast radius.

SAFETY

Every mutation is applied to a copy-on-disk and restored in a `finally`, so an
interrupted run leaves the tree as it found it. Verify with `git status` if a
run is killed.
"""
import subprocess
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# (label, file, before, after). `before` must appear EXACTLY once.
MUTATIONS = [
    (
        "AEAD: accept every tag",
        "src/transport-crypto/src/record.rs",
        "    if !constant_time_eq(&computed, &received) {\n"
        "        return Err(TransportCryptoError::AuthenticationFailed);\n    }",
        "    if false {\n        return Err(TransportCryptoError::AuthenticationFailed);\n    }",
    ),
    (
        "AEAD: compare only the first byte of the tag",
        "src/transport-crypto/src/secret.rs",
        "    left.ct_eq(right).unwrap_u8() == 1",
        "    left.first() == right.first()",
    ),
    (
        "ADT: ignore the tree depth limit",
        "src/adt/src/node.rs",
        "        if header.child_count > 0 && child_depth > crate::MAX_TREE_DEPTH {",
        "        if false {",
    ),
    (
        "GQA: every query head reads key/value group 0",
        "src/transformer/src/attention.rs",
        "            .checked_div(self.query_heads_per_group)",
        "            .checked_div(usize::MAX)",
    ),
    (
        "Q4_0: swap the nibble order",
        "src/tensor/src/q4.rs",
        "        let low = (((byte << 4) as i8) >> 4) as u8;\n"
        "        let high = ((*byte as i8) >> 4) as u8;",
        "        let high = (((byte << 4) as i8) >> 4) as u8;\n"
        "        let low = ((*byte as i8) >> 4) as u8;",
    ),
    (
        "softmax: drop the max shift that keeps exp finite",
        "src/tensor/src/softmax.rs",
        "        if *value > max {\n            max = *value;\n        }",
        "        if false {\n            max = *value;\n        }",
    ),
    (
        "swiglu: swap the gate and up branches",
        "src/tensor/src/activation.rs",
        "        let v = f64::from(*g);\n        *slot = ((v * sigmoid(v)) as f32) * u;",
        "        let v = f64::from(*u);\n        *slot = ((v * sigmoid(v)) as f32) * g;",
    ),
    (
        "block_dot_i8: drop the fourth lane",
        "src/tensor/src/matmul.rs",
        "        lanes[3] = lanes[3].saturating_add("
        "i32::from(w3 as i8).saturating_mul(i32::from(a3 as i8)));",
        "        lanes[3] = lanes[3];",
    ),
    # The two that escaped on 2026-08-20. Kept so they cannot escape again.
    (
        "REGRESSION: Q4_0 prefill workers all start at token zero",
        "src/transformer/src/weights.rs",
        "                        let start = index.saturating_mul(per_worker);\n"
        "                        let count = chunk.len().checked_div(shape.n_out).unwrap_or(0);\n"
        "                        if matmul_q4_0_q8a_tokens(",
        "                        let start = 0;\n"
        "                        let count = chunk.len().checked_div(shape.n_out).unwrap_or(0);\n"
        "                        if matmul_q4_0_q8a_tokens(",
    ),
    (
        "REGRESSION: the Q8_0 decode split is silently never taken",
        "src/transformer/src/weights.rs",
        "                        let worth_splitting = weight_bytes >= dispatch.minimum_split_bytes();",
        "                        let worth_splitting = false;",
    ),
]

TEST = [
    "cargo", "test", "--workspace",
    "--exclude", "brainix-shell",
    "--exclude", "brainix-bootloader",
    "--exclude", "brainix-kernel",
    "--target", "aarch64-apple-darwin",
]


def suite_fails() -> bool:
    return subprocess.run(TEST, cwd=REPO, capture_output=True, text=True).returncode != 0


def main() -> int:
    if "--list" in sys.argv:
        for label, path, _, _ in MUTATIONS:
            print(f"  {label}\n      {path}")
        return 0

    escaped = []
    for label, relative, before, after in MUTATIONS:
        path = REPO / relative
        source = path.read_text()
        if source.count(before) != 1:
            print(f"  STALE    {label}")
            print(f"           its pattern matches {source.count(before)} times in {relative};")
            print("           the code moved and this entry needs rewriting.")
            escaped.append(label)
            continue
        with tempfile.NamedTemporaryFile(delete=False) as backup:
            backup_path = Path(backup.name)
        shutil.copy(path, backup_path)
        try:
            path.write_text(source.replace(before, after, 1))
            caught = suite_fails()
        finally:
            shutil.copy(backup_path, path)
            backup_path.unlink()
        print(f"  {'CAUGHT ' if caught else 'ESCAPED'}  {label}")
        if not caught:
            escaped.append(label)

    print()
    if escaped:
        print(f"MUTATION SWEEP FAILED -- {len(escaped)} deliberate defect(s) went unnoticed:",
              file=sys.stderr)
        for label in escaped:
            print(f"  {label}", file=sys.stderr)
        print("\nThe suite accepts a wrong answer here. Write the test that does not,",
              file=sys.stderr)
        print("then re-run. A green suite that survives this is not a green suite.",
              file=sys.stderr)
        return 1
    print(f"mutation sweep: PASS -- all {len(MUTATIONS)} deliberate defects were caught")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
