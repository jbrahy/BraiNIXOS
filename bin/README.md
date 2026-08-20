# bin — Apple Silicon bring-up instruments

Everything here exists because of one thing: for two days this project ran on
**one bit of information per ten-minute physical trip**, and several independent
faults stacked invisibly. See
[`../docs/operations/BRINGUP_PLAN.md`](../docs/operations/BRINGUP_PLAN.md) for the
postmortem. These scripts answer questions *before* they cost a trip, and they
report what they actually found rather than what was expected.

Every one of them was run against the real machine before being committed, and
three of them were wrong the first time in exactly the way the plan warns about:
an unread error turned into a confident finding. Those bugs and their fixes are
in the commit history and in comments at the point of failure.

## The gates, which are not bring-up instruments

Three scripts here have nothing to do with the mini. They are the checks that
decide whether a change is allowed to land, and they are documented here
because a gate nobody knows about is a gate nobody runs -- which is exactly how
`coverage-gate.py` spent an unknown period scoring five crates as perfect while
it could not see them at all.

| Script | Asks | Runs where |
| --- | --- | --- |
| `coverage-gate.py` | is every uncovered line explained, and every explanation still needed? | any host |
| `coverage-gate.py --stale` | the second half alone, for a focused local check | any host |
| `sdot-gate.sh` | do the `Q8_0` matmuls still compile to `SDOT`? | **aarch64 only** |
| `lint-suppressions.py` | is every lint suppression justified? | any host |
| `clippy-all-targets-gate.sh` | do tests, benches and examples lint clean? | any host |
| `reproducible-build.sh` | are the bare-metal artifacts byte-identical twice? | any host |
| `mutation-sweep.py` | would a wrong answer actually be caught? | any host, not in CI |

```sh
./bin/coverage-gate.py                # enforce: 100% of reachable lines, no stale markers
./bin/coverage-gate.py --list         # every unjustified line, with its source
./bin/coverage-gate.py --stale        # markers that no longer excuse anything
./bin/sdot-gate.sh                    # skips loudly on non-aarch64, never passes quietly
./bin/clippy-all-targets-gate.sh      # the targets CI's clippy step never compiles
```

**Why `mutation-sweep.py` exists.** Coverage answers "did this line execute".
It does not answer "would a wrong answer have been caught", and on 2026-08-20
the difference was not theoretical twice in one afternoon.

The `Q4_0` prefill split had a fully tested kernel and an unguarded caller:
every test in `q4_weights.rs` decoded one token, so all of them took the
row-split branch, and planting an off-by-worker in the token split left the file
green. Separately, forcing every `worth_splitting` to `false` -- so nothing
splits and the decode quietly runs on one core -- leaves every answer correct.
Three tests failed, all refusal tests failing by accident of fixture shape.

Both are in the catalogue now as REGRESSION entries. The sweep is not in CI: a
full test run per mutation is minutes, and CI already runs nine gates. Run it
when touching a kernel, a split, or anything else in the catalogue's blast
radius. Every mutation is restored in a `finally`, so an interrupted run leaves
the tree as it found it.

**Why `clippy-all-targets-gate.sh` exists.** CI runs `cargo clippy --workspace
-- -D warnings`, without `--all-targets`. That compiles libs and bins, so
`#[cfg(test)]` modules, `tests/`, `benches/` and `examples/` are never linted at
all. The gap was found on 2026-08-19 by noticing that eight test files added
over two days each violated the workspace's own denied lints, and that every
"clippy clean" reported during that stretch had been said after checking only
the lib.

Turning it on found more than suppressions: a dead import, a `vec!` allocated
only to be borrowed as a slice, two variables named `len`, and an `assert!`
whose operands were all `const` -- that last one guarding an exemption in
`response.rs`, so it is now a `const` item that fails the build rather than a
test that fails a run. Test code does legitimately need `expect` and `unwrap`;
those are written down as `#[allow(..)]` on the module, which `lint-suppressions.py`
deliberately does not count, because its subject is production code. The two
gates cover disjoint sets and neither alone is the whole picture.

**Why the stale audit runs by default.** It reads the same instrumentation the
coverage check does, so requiring a second invocation bought nothing but a
second full minute and the chance to forget it. A marker that no longer excuses
anything is a defect of the same kind as a line with no marker. `--stale` is
still available on its own when that is the only question.

**Why `--stale` exists.** An exemption is granted once and then never re-read.
When the line it excused becomes covered, the marker stays behind and licenses
whatever code drifts into its eight-line window instead. Auditing the tree with
it on 2026-08-19 found five justifications that were wrong rather than merely
unproven -- including one on the record layer's nonce-reuse boundary, which had
been disprovable since the day `SequenceCounter::at` was written.

**Why `sdot-gate.sh` exists.** The tensor crate's largest win is not written in
its source: there are no intrinsics, and `grep -rn neon src/tensor/src/` returns
nothing, yet the quantized matmuls compile to `SDOT` because LLVM recognises the
loop. That is worth 5.3 -> 57.0 GB/s on one core. A refactor can delete it with
every test still green.

**What it does not catch**, and this is worth knowing before trusting it: it
counts instructions, so it cannot see a scheduling change. Adding
`matmul_q4_0_q8a_rows` made `matmul_q4_0_q8a` **five times slower** with an
identical `SDOT` count, because a second caller stopped `unpack_block` being
specialised into the loop. Only `benches/matmul.rs` caught that.

## Where things run

| Script | Runs on | Changes anything? |
| --- | --- | --- |
| `as-probe.sh` | workstation | runs our code on the target, no MMIO |
| `as-channels.sh` | workstation | no (except `--serial`) |
| `as-hid-selftest.sh` | workstation | writes one file in `/tmp` on the mini |
| `as-preflight.sh` | mini (macOS or recoveryOS) | no |
| `as-verify-install.sh` | mini | only with `--record` |
| `as-install-m1n1.sh` | mini, **recoveryOS only** | yes: sets the boot object |
| `as-install-boot-object.sh` | mini, **recoveryOS only** | yes: sets the boot object |
| `screenshot-mini.sh` | workstation | no |
| `brainx-ble.py` | workstation | drives the Flipper's keyboard |
| `flipper.py` | workstation | Flipper USB CLI (only when the app is not running) |

## The order to use them in

```sh
./bin/as-probe.sh                    # THE LOOP: build, run on hardware, read the verdict
./bin/as-channels.sh                 # what can I observe right now?
                                     # also runs as-preflight.sh on the mini over ssh
./bin/as-hid-selftest.sh             # does the Flipper type what I send? (needs macOS up)
                                     # ... reboot to 1TR ...
sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-install-m1n1.sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-verify-install.sh --record m1n1
```

## `payloads.tsv`

The single source of truth for what may be installed, and **the entry point for
each payload**. m1n1 is `2048`; our stub is `0`. Installing m1n1 at `0` is the
single most expensive mistake this project has made — it never ran, was judged
useless, and was abandoned, removing the only debugging instrument available.
The two values must never be copied from one another, so they live here per
payload instead of being typed per invocation. `as-preflight.sh` cross-checks
every `as-install-*.sh` against this file and fails on disagreement.

Hashes were taken on the workstation and again on the mini under macOS.
**recoveryOS has no `shasum`, no `openssl` and no Perl `Digest::SHA`** — all
three were tried on the real machine, one round trip each — so scripts running
there fall back to the size column.

## `installed-boot-objects.tsv`

`coih` is the Image4 hash of the *wrapped* boot object, so it cannot be computed
from the payload; it can only be observed afterwards. That makes it useless as a
precondition and ideal as a fingerprint. `as-verify-install.sh --record <name>`
appends it, and a later plain run says which payload the machine is actually
holding. Three boot objects were installed across two days with no record of
which was resident, and each dark screen got blamed on the most recent change.

## Things learned the hard way, so you do not have to

- **`bputil` requires root.** As a normal user it prints `The tool requires
  running as root`, which matches none of the obvious greps. Both scripts that
  read it now refuse rather than reporting an unread failure as a finding.
- **`kmutil configure-boot` has no `-u`/`-p`.** It prompts for `Username:` and
  `Password:`. An empty answer fails as `Code=71 not a valid admin user`, which
  reads like a policy fault. The account here is `jbrahy`.
- **`diskutil info <volume-group-uuid>` names the group's *Data* volume**, whose
  mount point is `/System/Volumes/Data` — not the system volume `kmutil` wants.
  That path is a valid directory, so the mistake does not announce itself.
  Resolve `/Volumes/BraiNIX` by name, then prove it belongs to the group.
- **Never pass `-k` to `bputil`.** It enables third-party kext trust, needs a
  paired AuxKC this flow never creates, and wedged the local policy badly enough
  to cost a volume group.
- **macOS does not clear the password field on a failed login.** A field that
  still holds dots after Return means *rejected*, not *Return was not
  delivered*. Reading it the other way cost four attempts and an account lock.
- **An absent Thunderbolt link is not a fault** while the mini runs a bare-metal
  payload — nothing on that end brings the link up. The USB-PD VDM layer answers
  regardless, which makes it the only honest "is a cable attached" signal here.

## `as-probe.sh` is the loop

Build the payload, run its decisions on the real machine, print what it decided.
Seconds, and nobody in the room.

It calls `boot_stub_probe` through m1n1's proxy with **m1n1 still resident**,
rather than chainloading. A chainload replaces m1n1 with a payload that ends in
a hang, so nothing is left able to report, and on this rig the serial path
delivers nothing either. A chainload therefore yields exactly the one bit that
cost this project two days: "it went quiet."

Its first run returned `stage 1` and found a real bug: `adt_window` refused the
machine's own firmware, because `devtree - virt_base` underflows under the
kernel-VA form m1n1 passes. Both forms occur on this hardware, so the parser
worked under iBoot and denied under m1n1, presenting as "the payload is broken."

Recover the rig over the wire when the payload has taken the machine:

```sh
sudo macvdmtool reboot     # m1n1 is back in about 15 seconds
```
