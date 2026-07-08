# Proof Coverage Tracker

A lightweight tool to track machine-checked proof coverage (Kani + fuzz) against BraiNIX security invariants.

## Purpose

Scans the BraiNIX repository for:
- **Kani harnesses** (functions annotated `#[kani::proof]`)
- **Fuzz targets** (files under `fuzz/fuzz_targets/`)
- **Security invariants** (listed in `docs/NORTH_STAR.md`)

Emits a report mapping which invariants have associated proof/fuzz artifacts and which remain uncovered, plus counts and a percentage toward the 80% coverage bar.

## Building

From the repository root:

```bash
# Method 1: Specify the native target explicitly
cargo build --manifest-path tools/proof-coverage/Cargo.toml --release --target aarch64-apple-darwin

# Method 2: Build from within the tool directory
cd tools/proof-coverage && cargo build --release
```

## Running

After building, the binary is located at:
- `tools/proof-coverage/target/aarch64-apple-darwin/release/proof-coverage` (when built from root)
- `tools/proof-coverage/target/aarch64-apple-darwin/release/proof-coverage` (when built from tools/proof-coverage)

Quick method—from repository root:

```bash
./tools/proof-coverage/target/aarch64-apple-darwin/release/proof-coverage
```

Or build and run in one command:

```bash
cd tools/proof-coverage && cargo run --release
```

The tool automatically finds the repository root (by locating `docs/NORTH_STAR.md`), scans for artifacts, and prints a markdown report to stdout.

## Output

The report includes:

1. **Summary**: Total invariants, count of covered/uncovered, current percentage, distance to 80% bar
2. **Artifact counts**: Total Kani proofs and fuzz targets
3. **Invariant Coverage Details**: For each invariant:
   - Associated Kani proofs (if any)
   - Associated fuzz targets (if any)
   - Coverage status (✓ or ✗)
4. **Complete artifacts list**: All proofs and fuzz targets scanned
5. **Uncovered invariants**: Invariants with no artifacts found

## Dependencies

- Rust 1.56+ (uses only std library, no external crates)
- No build-time or runtime dependencies beyond Rust std

## Example Output

```
# BraiNIX Proof Coverage Report

## Summary

- **Total Invariants**: 8
- **Covered Invariants**: 5 / 8
- **Coverage Percentage**: 62.5%
- **Target (80% bar)**: Need 1 more invariants covered

- **Kani Proofs**: 6
- **Fuzz Targets**: 7

## Invariant Coverage Details

### ✓ INV-AUTH - no ambient authority; every server's capability set is frozen...
  **Kani Proofs** (2):
    - `property_rights_monotonicity_over_derivation_chain` (lib.rs)
    - `proof_revocation_loop_terminates` (lib.rs)
  **Fuzz Targets** (1):
    - `fuzz_capability_slot_index_out_of_bounds`

...
```

## Integration

This tool is standalone—it doesn't modify the kernel workspace, adds no dependencies to crates, and is safe to run anytime. Output is a markdown report; pipe to a file or CI log as needed.

```bash
cargo run --manifest-path tools/proof-coverage/Cargo.toml --release > proof_coverage_report.md
```

## Future Enhancements

- Parse proof documentation to extract explicit invariant mappings (vs. inferring from function names)
- Filter by Kani unwind bounds to assess proof depth
- Export JSON for CI integration
- Track proof/fuzz artifact history over time
