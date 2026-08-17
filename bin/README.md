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
