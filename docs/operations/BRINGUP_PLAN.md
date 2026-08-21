# Bring-up plan — how to stop debugging blind

> **Phase 1 and Phase 2 both passed on 2026-08-16.** If you are here to *repeat* the
> procedure rather than to understand why it failed the first time, read
> [`FIRST_LIGHT_RUNBOOK.md`](FIRST_LIGHT_RUNBOOK.md) instead — it is the ordered,
> start-to-finish version. This file remains the postmortem, and is worth reading
> if you are tempted to skip one of that runbook's steps.

**Written 2026-08-16, after roughly twenty hours that produced no output from any BraiNIX code.**
Companion to [`APPLE_SILICON_BRINGUP_RIG.md`](APPLE_SILICON_BRINGUP_RIG.md), which is the procedure. This
file is why the procedure kept failing and what changes.

---

## 1. The actual problem, which is not any of the bugs

Across 2026-08-14/15 the bring-up effort spent **five recovery trips, three boot-object installs, and one
wedged local policy that cost a volume group** — and obtained **zero bytes of output** from either m1n1 or
BraiNIX. Not one byte, on any channel, ever.

Every attempt produced exactly **one bit** of information: the screen stayed dark. With one bit per
ten-minute physical round trip, several independent faults stacked invisibly, and each new failure was
attributed to the most recently changed thing rather than to whatever was actually wrong.

The real stack-overflow bug — `sp` pointing 73 KB past the end of the loaded image — was found by
**reading the linker script**, not by observing anything on hardware. That is the tell. When your debug
technique is "re-read the source and hope," the loop is broken, not the code.

**So the first objective is not to boot BraiNIX. It is to obtain a feedback loop.** Everything below
follows from that.

## 2. What went wrong, itemised

Recorded because the same mistakes are cheap to repeat.

| # | Error | Cost |
|---|---|---|
| 1 | **m1n1 installed with `--entry-point 0`.** m1n1's raw image carries a 2048-byte header; its documented entry is `2048`. So m1n1 never ran. | Produced nothing, was judged useless, and was abandoned — removing the only debugging instrument available. |
| 2 | **Chainloading rules ignored.** `APPLE_SILICON_BRINGUP_RIG.md` §5 says outright: *"Do not chainload BraiNIX before this passes, or you will be debugging two unknowns at once."* We went straight to installing our own payload as the boot object. | Three unknowns at once for the rest of the exercise. |
| 3 | **Flags copied without understanding them.** `-k` enables third-party kext trust and needs a paired AuxKC that this flow never creates. | `kmutil` failed with `code pairing (17)`, then `bputil` failed the same way, wedging the policy. Volume group deleted and rebuilt. **Amended 2026-08-21: `-k` is not the only route to this error** — a group that already carries a `coih` is `Not Paired`, and no new LocalPolicy can be written over that, with `-k` never passed. Diagnose with `bputil -e`, not `-d`. See `FIRST_LIGHT_RUNBOOK.md` §5. |
| 4 | **Unverified steps stacked.** Three boot objects installed without once running `bputil -d` in between. | The wedged policy was invisible until both tools refused. |
| 5 | **Diagnosis from absence of evidence.** Two silent output channels were read as *two broken channels* rather than *nothing ran*. | Chased OQ-5 and the entry point while the stack bug sat in the linker script. |
| 6 | **A stack in a `NOLOAD` section.** `objcopy -O binary` does not emit it, so the image ended at `0x2133` while `__stack_top` was `0x12140`. | The genuine fault. Died before any output path. |
| 7 | **`kmutil configure-boot` prompts for credentials and has no `-u`/`-p`.** An empty answer fails as `Code=71 not a valid admin user`, which reads as a policy fault. | Two runs lost. Fixed by answering `y`, then `jbrahy`, then the password. **Cost again on 2026-08-21**, from scratch, over several hours — by which time this row and `FIRST_LIGHT_RUNBOOK.md` §5 both already said so. Writing it down is not the same as reading it back. |
| 8 | **Diagnosis from absence of evidence, again.** A macOS login window that kept its dots after Return was read as *Return is not submitting*, rather than *the password is wrong*. macOS does not clear the field. | Four rejected attempts and a one-minute account lock, on a machine ten minutes away. |

Six of those eight are process failures. Two are real bugs. That ratio is the point, and item 8
is item 5 committed a second time on the same day.

## 3. What is known-good and must not be re-litigated

- **The volume-group boundary works.** `Macintosh HD` came through five recovery trips, three boot
  objects and a wedged policy at `coih: absent`, Full Security, untouched. Keep doing this.
- **Permissive Security is achievable and was verified** across a reboot on the first volume group.
- **The serial rig works** as far as it can be tested: `macvdmtool serial` succeeds against the target
  over an ordinary SuperSpeed USB-C cable, and `/dev/cu.debug-console` exists. Whether it *carries* our
  bytes is OQ-5 and is still unanswered.
- **The payload is well-formed**: flat binary, `mov x19, x0` at offset 0, entry 0, 42 host tests, and
  since `31ca1c2` a stack that lives inside the image.
- **The firmware pin is recorded**: macOS 15.7.5 (24G624), `mBoot-18000.161.9`.

## 4. The plan

### Principle

> **Establish a feedback loop before changing anything else. Verify every step before taking the next.
> One change per attempt.**

### Phase 1 — m1n1, done properly. This is the whole game.

m1n1 exists because bare-metal iteration on Apple Silicon is brutal; Asahi wrote it to solve precisely
the problem we have. It gives a console that works, a Python proxy that can read and write memory and run
code, and **chainloading — which replaces a ten-minute recovery trip with a one-second command.**

1. Obtain m1n1. The release asset `m1n1-stage2-v*.zip` contains `m1n1.bin`. Prefer building from source
   if its documentation says the release artifact is not the boot object.
   **Done 2026-08-16**: v1.6.1, 1,097,728 bytes, sha256
   `05137464cdacb23d8aed9be1d0ddd4fda757fb57d2b1a769ff3d88409afaafa0`, verified on the workstation and
   again on the mini, staged at `/Users/Shared/brainix-boot/m1n1.bin`.
2. Install it **with `--entry-point 2048`** — its convention, not ours, and the value we got wrong.
   Confirmed from two independent sources rather than memory: m1n1's own `README.md`, and
   `asahi-installer/src/step2/step2.sh` line 125. Our stub genuinely is entry `0`; the two values must
   never be copied from one another. Script: [`bin/as-install-m1n1.sh`](../../bin/as-install-m1n1.sh).
3. **Acceptance test: m1n1's own console prints.** Over `/dev/cu.debug-console` after `macvdmtool serial`,
   or over m1n1's USB gadget if the UART is silent — m1n1 handles the DockChannel-versus-UART question
   itself, which is exactly why it answers OQ-5 for us rather than us answering it for it.
4. **Zero BraiNIX code is involved in this test.** If it fails, the fault is the rig, and it is not
   confounded with anything of ours.

**Do not proceed to Phase 2 until m1n1 prints.** This is the rule we broke, and breaking it is what turned
one bug into twenty hours.

#### Phase 1 passed, 2026-08-16 16:13 PDT

m1n1 v1.6.1 printed 3,738 bytes on its first boot as the BraiNIX volume group's boot object, over its own
USB gadget rather than `/dev/cu.debug-console`. Log:
[`logs/m1n1-first-boot-20260816.log`](logs/m1n1-first-boot-20260816.log). It ends `Running proxy...`, so
Phase 2 is available.

It immediately answered two questions that had each been mistaken for "our code is broken":

1. **The console is DockChannel, not the s5l UART** (`Initialized dockchannel UART at 0x29e528000`). A
   correct AS-1a stub writing `UTXH` on this machine emits nothing. See
   [`../platform-specs/apple-s5l-uart.md`](../platform-specs/apple-s5l-uart.md) OQ-5, now resolved.
2. **The framebuffer given to a custom boot object is a dummy and is never scanned out**
   (`display: Dummy framebuffer found`, `display: failed to initialize DCP`, HDMI `No Signal`). The
   stage-stripe scheme was unobservable by construction.

Both output paths the stub was built around are unavailable on this hardware. That is exactly the class of
fact Phase 1 exists to establish before any of our code is on trial, and it was obtained in one boot.

### Phase 2 — iterate BraiNIX over the proxy

With m1n1 resident, the loop becomes:

```
build → chainload.py -r payload.bin → read the console → fix → repeat
```

Seconds per cycle, no recovery, no reboots, and m1n1 reports exceptions with register dumps — so a fault
like the stack bug shows up as a data abort with an address, instead of a dark screen.

### Phase 3 — boot object, once, at the end

Only once the payload demonstrably runs under m1n1 does it become the Image4 boot object. By then the
only new variable is the delivery mechanism, and everything else is known-good.

Order within the single recovery trip, with a verification after each:

1. `diskutil apfs listVolumeGroups` → read the **current** UUID (it changes when a volume group is rebuilt)
2. `bputil -n -c -v <uuid>` — **no `-k`**
3. `bputil -d -v <uuid>` → **must** report `Security Mode: Permissive`. Stop if not.
4. `find ... -exec shasum -a 256 {} \;` → confirm the payload hash before installing it
5. `kmutil configure-boot -c <path> --raw --entry-point 0 --lowest-virtual-address 0 -v /Volumes/BraiNIX`
6. Capture that command's output. **Every previous failure was invisible because this was not done.**

## 5. Standing rules

1. **One change per attempt.** Two changes and a dark screen tells you nothing.
2. **Verify after every step**, in the same session, before the next step.
3. **Never copy a flag without knowing what it buys.** `-k` and `--entry-point 2048` both came from
   copying.
4. **Absence of output is not evidence about output paths.** Two silent channels most likely means
   nothing ran.
5. **Capture the output of anything that modifies boot state**, at the moment it runs.
6. **The payload must not depend on unverified firmware behaviour** to report. It currently assumes
   iBoot populates `boot_args.video`; if Phase 1 shows otherwise, the fallback is a timed reboot — a
   machine that power-cycles on a rhythm proves execution with no output device at all.

## 6. What this does not change

The model-serving work is **not** implicated in any of this and largely succeeded: gemma-4-12B-it served
at 18.7 tok/s, and the failures there (launchd cannot read the other volume group; `sd-server` scans its
working directory into TCC; `curl --retry-all-errors` truncating a resumed download; the machine
sleeping) are understood and written down. That work resumes independently of bring-up.
