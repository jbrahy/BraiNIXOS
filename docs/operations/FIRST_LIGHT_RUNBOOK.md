# First light on Apple Silicon: the repeatable procedure

**What this gets you:** a Mac running your own bare-metal code, printing to a
terminal on your workstation, with a build-and-reload loop measured in seconds.

**What it cost the first time:** two days, five recovery trips, three boot
objects, one wedged security policy, one deleted volume group, and zero bytes of
output. Following the order below instead should cost one session.

Companions, all cross-linked and none a substitute for this file:

- [`BRINGUP_PLAN.md`](BRINGUP_PLAN.md) is the postmortem: why the first attempt
  failed, itemised. Read it if you are tempted to skip a step here.
- [`APPLE_SILICON_BRINGUP_RIG.md`](APPLE_SILICON_BRINGUP_RIG.md) is the
  chronological log of findings, including everything about volume groups,
  bandwidth and model serving that is not on the critical path for first light.
- [`../../bin/README.md`](../../bin/README.md) documents the instrument scripts
  this runbook invokes.

> Style note: this file avoids em dashes per the project writing rule for new
> documents, while its siblings in this directory use them. That is deliberate
> and not drift.

---

## 0. The one rule

> **Get a console before you debug anything of your own.**

The first attempt installed our own payload as the boot object on day one. It
produced a dark screen. That single bit of information could not distinguish
between a stack bug, a wrong entry point, a wrong UART, a wrong framebuffer, and
a machine that never executed a byte, and *all five* were true at various points.

m1n1 costs one recovery trip and turns every subsequent iteration into a
one-second command. Install it first. Every time.

## 1. What you need

| Thing | Notes |
| --- | --- |
| Target Mac | Apple Silicon. This procedure was run on `Mac14,12` (M2 Pro mini). |
| Workstation Mac | Apple Silicon, for `macvdmtool`. |
| USB-C cable | Any SuperSpeed cable. USB4 is not required. |
| Display on the target | You will need to read the screen during recovery. |
| Keyboard on the target | Or a Flipper Zero, see section 8. |
| An admin account on the target's volume group | Section 5 is unforgiving about this. |

## 2. Carve a volume group for the experiment

Never do this on the volume you care about. A separate APFS volume group is the
blast wall, and it has held: across everything above, `Macintosh HD` stayed at
`coih: absent` with Full Security, untouched.

```sh
diskutil apfs addVolume disk0s2 APFS BraiNIX
```

Then install macOS onto it. The installer must be run from the GUI; see
[`APPLE_SILICON_BRINGUP_RIG.md`](APPLE_SILICON_BRINGUP_RIG.md) section 1a.3 for
why the CLI path does not work.

**Record the volume group UUID, and re-read it every session.** It changes
whenever the group is rebuilt, and a stale `-v` fails in a way that reads as a
policy fault rather than as a wrong argument.

```sh
diskutil apfs listVolumeGroups
```

## 3. Stage the payload and the scripts

On the target, under macOS, in a directory that will be reachable from
recoveryOS as `/Volumes/Data/Users/Shared/brainix-boot`:

```sh
mkdir -p /Users/Shared/brainix-boot && cd /Users/Shared/brainix-boot
curl -sL -o m1n1.zip \
  https://github.com/AsahiLinux/m1n1/releases/download/v1.6.1/m1n1-stage2-v1.6.1.zip
unzip -o m1n1.zip && rm m1n1.zip
shasum -a 256 m1n1.bin
# 05137464cdacb23d8aed9be1d0ddd4fda757fb57d2b1a769ff3d88409afaafa0
```

Copy in `bin/as-install-m1n1.sh`, `bin/as-preflight.sh`,
`bin/as-verify-install.sh` and `bin/payloads.tsv` from this repository, and write
`.admin` with the username on line 1 and the password on line 2.

**Verify the hash here, under macOS.** recoveryOS has no `shasum`, no `openssl`
and no Perl `Digest::SHA`. All three were tried, one round trip each. Scripts
running there fall back to a size check.

## 4. Enter One True Recovery

> **No hands on the machine?** [`REMOTE_HANDS.md`](REMOTE_HANDS.md) covers
> driving the picker and Recovery from the laptop with the Flipper as a keyboard
> and the camera as eyes, including the keyboard rules for Recovery, which are
> not the ones you would guess. Holding the power button and the admin password
> still need a person; everything between them does not.

Hold the power button until `Loading startup options` appears. Pick **Options**,
then the volume whose *data* you need mounted. Pick **Macintosh HD** if your
scripts live there, because that group's data volume only unlocks if you
authenticate against it.

Then **Utilities > Terminal**.

Confirm the environment before doing anything:

```sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh
```

It should end `READY (recoveryOS) -- 0 checks failed`. It checks tool
availability, hashing capability, volume groups and their mount points, the
policy on both groups, payload integrity, and that every install script's entry
point agrees with `payloads.tsv`.

## 5. Install m1n1

```sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-install-m1n1.sh
```

### The entry point is 2048, and it is not the same as yours

```sh
kmutil configure-boot -c m1n1.bin --raw \
    --entry-point 2048 --lowest-virtual-address 0 -v /Volumes/BraiNIX
```

Confirmed from two independent sources: m1n1's own `README.md`, and
`asahi-installer/src/step2/step2.sh` line 125. **Our boot stub is entry `0`.**
The first m1n1 attempt used `0`, so m1n1 never ran, was judged useless, and was
abandoned, removing the only debugging instrument available. Keep the value per
payload in `payloads.tsv` and never copy one payload's value to another.

### Never pass `-k` to `bputil`

`-k` enables third-party kext trust, needs a paired AuxKC that this flow never
creates, and wedged the local policy badly enough to cost a volume group.
`bputil -n -c -v <uuid> -u <user> -p <pass>` is the whole command.

### `pairing (17)` means the group already carries a boot object

`-k` is one way to reach this error. It is not the only one, and on 2026-08-21
the *other* way cost a whole evening with `-k` never once passed:

```
Error Domain=KMErrorDomain Code=71 "Boot policy error: Error updating custom os
local policy: code pairing (17)"
```

and `bputil` refuses identically, which is the part that identifies it:

```
Boot objects update failed for <VG>: Error Domain=BYErrorDomain Code=401
"Failed to create local policy" NSUnderlyingError=
  {Domain=com.apple.bootpolicy Code=17 "pairing (17)"}
```

**Two tools, one error, at LocalPolicy creation.** That rules out kmutil, and it
rules out the credential -- which is worth stating because the credential error
looks similar and appears one step earlier.

**Diagnose with `bputil -e`, not `bputil -d`.** In 1TR, `-d` prints the policy
of the *booted* environment and tells you almost nothing about your target. `-e`
prints every policy on the machine, and the answer is the two rows side by side:

| | the experiment group | the untouched macOS |
| --- | --- | --- |
| OS Pairing Status | **Not Paired** | Paired |
| Security Mode | Permissive (smb0 && smb1): 1 | Full |
| coih | `8BABB8ED...D87375F` | absent |

A group that already has a `coih` is **Not Paired**, and a new LocalPolicy
cannot be written over that state. The same symptom is reported against the
Asahi installer by someone who also had a custom boot policy already set:
<https://github.com/AsahiLinux/asahi-installer/issues/50>.

To clear it, set **that group only** back to Full Security -- the operation
Startup Security Utility performs through the GUI, and reversible:

```sh
bputil -f -v <uuid> -u <user> -p <pass>
```

**Never `bputil -r` / `--remove`.** It deletes the LocalPolicy outright. That is
the shape of the mistake that already cost this project a volume group, and it
is not what is needed here.

### The real cause: the group has no recoveryOS of its own

**Clearing `coih` is not enough.** On 2026-08-21 `bputil -f` succeeded and left
the group at `coih: absent`, Full Security -- and the very next downgrade still
failed with `pairing (17)`, with and without `-c`. What that isolates:

| operation | signed by | result |
| --- | --- | --- |
| `bputil -f` (raise to Full) | Apple, over the network | **works** |
| `bputil -n` (lower to Permissive) | locally, needs a paired OS | `pairing (17)` |

An Apple-personalized change does not care about pairing. A local downgrade
does. And the group is `Not Paired` because it has no recoveryOS:

```sh
diskutil apfs list | grep -E "Name:|Roles:"
```

```
Macintosh HD, Preboot, Recovery, Data, VM, BraiNIX - Data, BraiNIX, macOS Base System
```

**One `Recovery` volume, and it belongs to Macintosh HD.** A volume group
becomes pairable only when it has its own recoveryOS, and a group carved by
adding a volume and copying a system into it never gets one.

**So the experiment volume must be created by a real macOS install**, not by
cloning -- §2 of this file says carve a volume group, and this is the part that
makes it a *bootable, policy-editable* one. Reinstall macOS onto it from
Recovery and let the installer create the paired recoveryOS. Until then no
custom boot object can be installed on it, no matter what the security mode says.

recoveryOS has no `startosinstall` and no installer CLI, so this is the GUI
wizard. Photograph the disk picker and confirm the target by name before every
confirming keypress; picking wrong installs over the working macOS.

### `exit` in the Recovery Terminal is a one-way door

The Recovery main window does **not** wait behind Terminal. It is gone. Type
`exit` and you are left with a dead Terminal window, no shell, and no way back:
Cmd-Q, Cmd-W, Cmd-N and Ctrl-F2 are the only routes to the menu bar, and none of
them were in the Flipper's key table. That ended a session and cost a
power-button trip on 2026-08-21. `cmd-q`, `cmd-w` and `cmd-n` were added to
`named_keys[]` the same night; **check the firmware actually carries them before
relying on it**, because the table lives in the app and the app has to be
reflashed.

Do not close the shell until the work is done.

### recoveryOS has pmset

`/usr/bin/pmset` and `/usr/bin/caffeinate` both exist. Before anything long:

```sh
pmset -a sleep 0 displaysleep 0 disksleep 0
```

Losing the display to idle sleep looks exactly like a wedged machine, and
waking it costs keystrokes you may not want to send blind.

### Full Security needs the Internet, so this step needs a cable

`bputil -f` is personalized against Apple's servers and fails without
connectivity -- harmlessly, before changing anything:

```
Boot objects update failed for <VG>: Error Domain=BYErrorDomain Code=102
"Can't continue because you are not connected to the Internet"
  {AuthInstallErrorDomain Code=11}, BYErrorHint=NetworkRequired,
  BYPersonalizationType=os
```

Permissive and `coih` are signed locally by the SEP and need no network. Only
the Full Security round trip does.

**recoveryOS has no `networksetup`** -- only `/sbin/ifconfig` and
`/usr/sbin/ipconfig`. So Wi-Fi cannot be joined from the Terminal, and Recovery
does not inherit the association from macOS. The menu-bar Wi-Fi picker is the
only route and it needs a mouse.

**Plug in Ethernet.** `en0` reads `status: inactive` with no cable; then
`ipconfig set en0 DHCP` and confirm an address before retrying. Add this to the
short list of things that need a person, next to holding the power button.

### Answer kmutil's prompts one at a time

`kmutil configure-boot` has **no** `-u`/`-p`. It asks three things in order:

```
Are you sure you want to do this? (enter y or n)    ->  y
Username:                                            ->  your admin user
Password:                                            ->  no echo
```

Three failure modes, all of which happened:

1. **An empty answer** fails as `Code=71 "not a valid admin user"`, which reads
   like a policy fault rather than a missed prompt.
2. **A wrong password** fails as `Code=71 "Unable to set credentials, possibly
   wrong name or password"`. These are different messages; read which one you got.
3. **The password prompt reads `/dev/tty` directly**, so a plain pipe feeds `y`
   and the username and then waits forever at `Password:`. Confirmed: a pipe on
   `/dev/tty` gives `Device not configured`.

   This file used to end that paragraph "There is no way around this. Someone
   has to type it." **That was wrong**, and it is the sentence that kept the
   install manual. `script(1)` allocates a pty, which satisfies the `/dev/tty`
   read, and the answers can be fed in:

   ```sh
   { printf '%s\n' y "$ADMIN_USER" "$ADMIN_PASS"; sleep 120; } \
     | script -q /dev/null sh as-install-boot-object.sh brainix-kernel 2>&1 | tr -d '\r'
   ```

   Two details, both established by experiment on 2026-08-22 and both easy to
   get wrong:

   * **The `sleep` is load-bearing, not padding.** Without it the pipe hits EOF
     before kmutil issues its reads and every answer comes back empty. Measured:
     bare pipe gives `got:[]`; held pipe gives the value.
   * **A fifo does not work.** macOS `script` calls `tcgetattr` on its stdin and
     refuses anything that is not a tty or a pipe.

   The pipeline finishes only when the holder does, so the sleep sets a floor on
   runtime -- 120s is well under kmutil's own duration and is absorbed entirely.

   `bin/as-autoinstall.sh` does this, and falls back to the manual procedure if
   `script(1)` turns out to be missing from recoveryOS rather than hanging.

### Output buffering will make it look hung

The install script tees through a FIFO, so kmutil's stdout is a pipe and libc
**fully buffers** it. `Username:` does not appear when kmutil asks; it appears
later, in a burst, together with everything else. Three minutes of apparent hang
was kmutil sitting at an invisible prompt.

If you see nothing after answering `y`, type the username anyway. If it echoes,
the prompt was there all along.

## 5a. Install the kernel, and take m1n1 out of the loop

Everything above installs m1n1, which is the debugging instrument. This installs
BraiNIX itself, which is the point.

```sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-install-boot-object.sh brainix-kernel
```

The payload name is the only argument, and the script reads
[`payloads.tsv`](../../bin/payloads.tsv) for the file, size, hash and **entry
point**. The kernel's entry is 0 and m1n1's is 2048; the two must never be
copied from one another, and neither is typed at the prompt.

### Rehearse it over the wire first, because you can

`bin/as-chainload-kernel.sh` runs the same image on the same machine without
touching the boot object at all. m1n1 shuts its own MMU down and jumps to the
payload at EL2, MMU off, `x0` holding boot_args -- the entry state iBoot gives a
custom boot object. If the kernel is going to fail on install, it fails here
first, and here costs a reboot instead of a trip to the machine.

### There is no screen and there is no serial. Watch the USB bus.

The framebuffer handed to a custom boot object is a dummy that is never scanned
out (section 9), and the SBU serial path on this rig delivers zero bytes
(section 9a). Once m1n1 is gone, the machine has no way to tell you anything
except by rebooting.

So `_start` climbs a ladder, re-arming the watchdog four seconds longer at each
rung, and parks. **The interval between reboots is the report.** A fully working
install cycles about every 26 seconds plus boot time, forever:

```sh
while :; do ls /dev/cu.usbmodem* >/dev/null 2>&1 && echo up || echo down; sleep 1; done
```

Time from power-on to the device leaving the bus, and read it off:

| interval | how far it got |
| --- | --- |
| ~5s | device tree parsed, `/arm-io/wdt` found and armed |
| ~9s | cpu topology read out of the tree |
| ~13s | `/arm-io/pmgr` translated, cpu-start base derived |
| ~17s | a second cpu released, which reported its own MPIDR |
| ~21s | its own page tables built, from firmware's geometry |
| ~26s | **MMU and caches on**, fetching through those tables |
| never | it did not reach the first rung |

Arming before each attempt is what makes the ladder safe: the watchdog is the
hang recovery as well as the signal, so a rung that wedges does not take the
report with it. What arrives is "it got this far and then stopped".

Rungs are four seconds apart because two was not enough. Overhead between arming
and the device leaving the bus runs one to three seconds, so 13s and 15s arms
both landed on +16 and three identical runs decoded as two different rungs. That
read as a flaky kernel and was a flaky ruler.

Measured by chainload on 2026-08-17, three consecutive runs at +26, +27, +26s.
The reason the reading is believable at all is that the interval tracks the
constant: an earlier 5-second arm reset at +7s and a 15-second arm at +16s. A
payload that crashed into `VBAR_EL2 = 0` and reset the machine on its own would
not move when a Rust constant changes, and neither would a firmware watchdog.

### Getting back

The heartbeat is a permanent reboot loop, which is the intended signal and also
means the machine will not sit still for anything else. Hold the power button
for One True Recovery and install a different boot object. `macvdmtool reboot`
will not help: it reboots into whatever the boot object is, which is the loop.

## 6. Record what you installed

```sh
sh /Volumes/Data/Users/Shared/brainix-boot/as-verify-install.sh --record m1n1
```

`coih` is the Image4 hash of the *wrapped* boot object, so it cannot be
predicted from the payload, only observed afterwards. That makes it useless as a
precondition and ideal as a fingerprint. Three boot objects were installed
across two days with no record of which was resident, and every dark screen got
blamed on the most recent change.

## 7. Reboot and read the console

```sh
reboot
```

It boots straight into the experimental volume; no picker step, because m1n1 is
that volume group's boot object.

**Expect `No Signal` on HDMI. That is normal and is not a fault.** See section 9.

On the workstation, m1n1's USB gadget appears over the ordinary USB-C cable:

```sh
ls /dev/cu.usbmodem*
# /dev/cu.usbmodemNNPN625M0M1   console and proxy
# /dev/cu.usbmodemNNPN625M0M3   second interface
timeout 6 cat /dev/cu.usbmodemNNPN625M0M1
```

You should see `Initialized dockchannel UART at ...`, the device info block, the
MMU log, and finally `Running proxy...`. A full known-good capture is committed
at [`logs/m1n1-first-boot-20260816.log`](logs/m1n1-first-boot-20260816.log).

**You do not need `macvdmtool serial` for this.** The USB gadget is a separate
path and it is the one that works. `/dev/cu.debug-console` read zero bytes
throughout.

## 8. The proxy: the actual iteration loop

```sh
curl -sL -o m1n1-src.tgz \
  https://github.com/AsahiLinux/m1n1/archive/refs/tags/v1.6.1.tar.gz
tar xzf m1n1-src.tgz
python3 -m venv m1n1-venv
./m1n1-venv/bin/pip install construct==2.10.70 pyserial==3.5

cd m1n1-1.6.1/proxyclient
M1N1DEVICE=/dev/cu.usbmodemNNPN625M0M1 PYTHONPATH=. ../../m1n1-venv/bin/python - <<'PY'
from m1n1.setup import *
print("base 0x%x  EL%d" % (u.base, u.mrs(CurrentEL) >> 2))
PY
```

**The proxy is on the same port as the console**, not the second one. The second
interface times out with `UartTimeout: Expected 1 bytes, got 0 bytes`, which
looks like a dead proxy and is not.

From here you can read and write memory, run code, dump the ADT, and chainload:

```sh
M1N1DEVICE=/dev/cu.usbmodemNNPN625M0M1 PYTHONPATH=. \
  ../../m1n1-venv/bin/python tools/chainload.py -r /path/to/payload.bin
```

That is the loop. Build, chainload, read the console, fix, repeat.

## 9. Two facts that will otherwise cost you days

Both were discovered by m1n1 in a single boot, and both had been repeatedly
misread as "our code is broken".

### The console is DockChannel, not the s5l UART

```
Initialized dockchannel UART at 0x29e528000
```

`/arm-io/uart0` exists on this machine, is correctly described, carries
`compatible = uart-1,samsung`, translates correctly, and is even marked
`boot-console`. It is **not** the console: the debug serial mux presents
DockChannel on the Type-C SBU pins. A flawless s5l driver emits zero bytes at
the host, which is indistinguishable from never running.

DockChannel is four registers and needs no configuration at all:

| Offset | Meaning |
| --- | --- |
| `0x4004` | write one byte |
| `0x4014` | free TX slots; poll until nonzero |
| `0x401C` | RX byte, in bits `[15:8]` |
| `0x402C` | RX count |

See `src/boot-stub-apple/src/dockchannel.rs`.

### The framebuffer given to a custom boot object is a dummy

```
display: Dummy framebuffer found, initializing display
dcp: dtpx-port is only supported with V13_5 OS firmware.
display: failed to initialize DCP
fb init: 640x1136 (32) [s=640] @0x10799a48000
```

`boot_args.video` *is* populated, so reading it is not the problem. The surface
simply is never scanned out, and HDMI stays at `No Signal`. **Painting it cannot
produce anything visible.** Any plan that depends on drawing to the screen as a
progress indicator is unobservable by construction, however correct the drawing
code is.

## 9a. Open: the SBU serial path delivers nothing on this rig

**Measured 2026-08-16, and it is not a fault in any of our code.**

The DockChannel register block is live and accepts bytes. Read through m1n1's
proxy, with m1n1 resident:

```
TX_FREE  (0x4014): 0x00000800     2048 free FIFO slots
RX_COUNT (0x402c): 0x00000000
```

Writing the exact sequence our driver uses, from the proxy, succeeds: the poll
loop terminates and the FIFO takes the bytes.

```python
BASE = 0x2_9E52_8000
for ch in b"PROXY-DOCKCHANNEL-TEST\r\n":
    while p.read32(BASE + 0x4014) == 0:
        pass
    p.write32(BASE + 0x4004, ch)
```

**Nothing arrives at `/dev/cu.debug-console`.** Three independent writers were
tried and all three produce zero bytes there:

| Writer | Bytes at the host |
| --- | --- |
| our chainloaded stub | 0 |
| a proxy write to the same registers | 0 |
| **m1n1 itself, across a full boot** | 0 |

The third row is the one that matters. m1n1 is known-good and demonstrably
prints 3,738 bytes over its USB gadget, and it prints
`Initialized dockchannel UART` as its *first* line, before USB exists. If its
output does not reach that device either, the device is not carrying this
machine's DockChannel on this setup.

So a silent `/dev/cu.debug-console` is **not evidence about the payload**, and
must not be read as one. This is the same trap as OQ-5, one layer further out.

Things not yet eliminated, in the order worth trying, all physical:

1. **The cable.** SBU is not present on every USB-C cable. Charge-only and some
   USB 2.0 cables omit those pins entirely.
2. **The port.** See [`APPLE_SILICON_BRINGUP_RIG.md`](APPLE_SILICON_BRINGUP_RIG.md)
   section 3.2, which already records that port choice matters and that getting
   it wrong presents as a different failure.
3. **Ordering.** `macvdmtool serial` was issued, then the target rebooted; serial
   mode may not survive the reboot. Setting the mode with m1n1 already up and
   then writing was also tried, and also produced nothing.

**Until this is resolved, verify payload behaviour through the proxy instead**:
m1n1 stays resident, and memory can be read back after the fact. That path is
already proven to work, needs nobody in the room, and does not depend on SBU.

## 9b. Verify the payload through the proxy, not the console

**This is the technique that worked, and it needs no serial path at all.**

Chainloading destroys m1n1, so a payload that ends in a hang leaves nothing on
the machine able to say what happened. Instead, give the payload a second entry
point that reports into memory and **returns**, and call it with m1n1 resident:

```python
image = open(BIN, "rb").read()
code = u.malloc(len(image) + 0x1000)
out  = u.malloc(64)
iface.writemem(code, image)
p.dc_cvau(code, len(image))     # the I-cache has not seen this yet
p.ic_ivau(code, len(image))
ret = p.call(code + PROBE_OFF, p.get_bootargs(), out)
vals = [p.read64(out + 8 * i) for i in range(6)]
```

`PROBE_OFF` comes from the ELF, not from guesswork:

```sh
llvm-nm target/.../brainix-boot-stub-apple | awk '/ T boot_stub_probe$/ {print $1}'
```

Two things that will bite:

1. **The cache maintenance is not optional.** Bytes written as data are not
   visible to the instruction fetcher until `dc_cvau` + `ic_ivau`.
2. **`#[no_mangle]` does not survive LTO** in a binary crate when nothing calls
   the function. It is dead-stripped and vanishes from the symbol table. Anchor
   it with a `#[used]` static holding its address.

The probe must **touch no MMIO**. It is running on the machine that is hosting
the measurement, and driving a UART there disturbs the host. Verify decisions
here; verify registers separately by writing them from the proxy.

Result on 2026-08-16, which is what closed AS-1a's substance:

```
returned 0x427261694e495801 -> OUR CODE RAN
  stage         0x3             all three stages reached
  adt_phys      0x1000361c000   the real ADT
  adt_len       0x78000
  console_kind  0x1             DockChannel
  console_base  0x29e528000     the address m1n1 independently printed
```

The first run of this loop returned `stage 0x1` and found a real bug in
`adt_window` within minutes. See `src/adt/tests/fixtures/README.md`.

## 9c. Probing the kernel, and what bit us doing it

The kernel is probed the same way as the stub, through `kernel_probe`, but four
things differ and each cost a cycle or a machine hang.

**Build release, not debug.** `p.call` runs on m1n1's stack. A debug-profile
kernel (116,305 bytes) crashed the target; the release build (77,761) does not.
Debug aarch64 code at opt-level 0 uses far more stack than that call frame has.

**Size the allocation from `__bss_end`, not from the image.** `objcopy -O binary`
does not emit `.bss`, so it lives past the end of the flat image, and the
16 KiB-aligned root table pushed it to `0x18000..0x20000` while the image was
`0x14261` bytes. Allocating image-plus-slack puts that table outside the
allocation, on top of m1n1.

```sh
llvm-nm <elf> | awk '/ B __bss_end$/ {print $1}'
```

**Zero `.bss` at every entry point.** Nothing else will. Statics start as
whatever was in that memory, which produced exception readings that were
unreproducible and unexplainable and cost an evening. `kernel_probe` never
passes through `_start`, so zeroing hidden inside `_start` leaves every
proxy-verified measurement running on uninitialised statics.

**Do not use `fetch_add` in a payload.** Measured on the target: every `store`
in the exception handler landed correctly while `fetch_add` on a counter read
back as zero. A read-modify-write needs the exclusive monitor or LSE atomics to
work on the memory it targets; a plain store does not, and the payload runs from
memory whose attributes are not ours to choose.

**Not all m1n1 USB interfaces answer the proxy.** With two cables attached there
are four ports; two carry it and two time out with `Expected 1 bytes, got 0`,
which looks exactly like a dead proxy. Try each.

Recover a wedged target without touching it:

```sh
sudo macvdmtool reboot     # m1n1 is back in about 15 seconds
```

## 9d. Bringing up the MMU without losing the machine

Enabling translation is the one operation here that fails with **no way to
report why**: get the tables or `TCR` wrong and the next instruction fetch goes
through a mapping that no longer describes the code doing the faulting. No
console, and the vector table is itself at an address that may no longer
resolve.

The order that worked, on 2026-08-16:

1. **Exception vectors first.** Bringing up translation *is* faulting. A fault
   with nowhere to land is indistinguishable from a hang.
2. **Walk before you write.** The hardware is already running with translation
   on, which makes its tables a free, fully populated test case and its `AT`
   instruction a free oracle. `AT s1e2r` cannot fault -- an untranslatable
   address is reported in `PAR_EL1.F`. A walker checked against tables you also
   built confirms only that you are self-consistent.
3. **Change one thing.** Program `TTBR` with a **copy of the live root table**.
   The register changes; the mapping does not. Every address that resolved
   before resolves after, so a fault is attributable to the switch alone.
   Debugging a new table builder and a `TTBR` switch at once gives you a hang
   with two candidate causes and no console to tell them apart.
4. **Only then build your own tables**, and check them with the walker the
   hardware already validated.

Every barrier in the switch is load-bearing:

```
dsb ishst      descriptor writes visible to the table walker before it uses them
msr TTBR0_EL2  ...
isb            new TTBR in effect before any later instruction fetch
tlbi alle2is   stale entries describe the OLD table
dsb ish
isb            invalidation complete before execution continues
```

`tlbi` is the one people skip. It **appears to work**, because the TLB still
holds correct translations, and then fails later at an unrelated address.

### Installing tables you built yourself

Step 4 above, and three rules make the difference between a measurement and a
coin flip.

**Map all of DRAM, not what you think you need.** It is the *cheap* option, not
the expensive one: at a 16 KiB granule the block level covers 32 MiB, one
level-2 table spans 64 GiB of it, and all 32 GiB of this machine's memory is
1024 entries inside a single table. Root plus intermediate plus leaf is **three
tables, 48 KiB**. Sizing the map to the payload instead is a guess — `p.call`
runs on **m1n1's** stack, and `boot_args`, m1n1's code and your image are
scattered across its heap — and the failure mode of guessing wrong is a hang.

**Lift the attributes from a live descriptor.** Do not write a plausible
constant. Memory type is an `AttrIndx` into `MAIR`, so the same descriptor bits
mean different things under different `MAIR` values, and a wrong index produces
a mapping that resolves perfectly and cannot be executed. On this target a live
block reads `0x1000c000601`, giving attribute bits `0x600`: `AF=1`, `SH=2`,
`AP=0`, `AttrIndx=0`.

**Check before you switch, and refuse on any disagreement.** Walk every address
the window will touch twice — once with your own walker over the table you just
built, once with `AT s1e2r`, which cannot fault. A refused switch costs nothing;
a wrong one costs the machine and tells you nothing about why. Include the
stack pointer in the checked set.

```
built root       0x000001000cc94000  3 tables for all 32 GiB of DRAM
cross-checked    5 addresses against AT s1e2r, 0 mismatches
read through it  0xa90957fed102c3ff  (before: 0xa90957fed102c3ff)  SAME
TTBR0_EL2 after  0x0000010002e3c000  RESTORED
```

Values measured on the target, for reference:

| | |
| --- | --- |
| `TCR_EL2` | `0x37510b510`, `T0SZ` 16, `TG0` 2 |
| granule | 16 KiB, 4 levels |
| `TTBR0_EL2` | `0x1000369c000` |
| mapping | identity — VA equals PA |
| a live descriptor | `0x1000c000601`, a **block** at level 2 of 4 |

`TG0` is **not in size order**: `0b00` is 4 KiB, `0b01` is 64 KiB, `0b10` is
16 KiB. Reading it as ordered gives a walker that is wrong on exactly the
granule Apple Silicon uses.

## 9e. Align the load address, or lose a day to it

**`u.malloc` does not align.** It returns wherever the heap happens to be —
`0x1000da10240` on the run that exposed this. The payload contains structures
that are aligned *relative to the start of the image*: two 2 KiB-aligned vector
tables and a 16 KiB-aligned root page table. They are only aligned in memory if
the image starts aligned.

Nothing tells you when this is wrong. `VBAR` ignores bits [10:0], so a
misaligned table is **not rejected** — every exception branches that many bytes
short of the real table, into the middle of whatever precedes it. The machine
hangs, with no console and no fault.

It is intermittent in the worst possible way. The alignment depends on the size
of the allocations before it, which depends on the size of the image, so a
change that has nothing to do with exceptions can turn a working probe into a
hang. Adding 2 KiB of vector table did exactly that: a probe that reported forty
values started reporting none, and nothing in the diff looked like it could.

`bin/as-kernel-probe.sh` rounds the load address up to 16 KiB and refuses to run
if it cannot. Any new loader needs the same, including `as-probe.sh` the moment
the boot stub grows anything alignment-sensitive.

## 9f. Dropping to EL1 under m1n1

It works, and the two things that made it look impossible were both ours.

**Install `SPSR_EL2` as well as `ELR_EL2`.** A handler that writes only the
return address leaves `SPSR_EL2` holding what exception entry put there. That is
correct exactly when the return resumes at the level the exception came from,
and silently wrong otherwise — which is every return that changes level. `HVC`
from EL1 enters with `SPSR_EL2` = EL1h; a redirect asking for EL2h that does not
write `SPSR_EL2` resumes **at EL1**, and the next EL2-only instruction wedges the
machine. A `brk` at EL2 will never show this, because there the stale value
happens to be right.

**EL1 needs more than `TTBR` and `TCR`.** Copying the tables without `MAIR`
leaves every `AttrIndx` naming Device-nGnRnE, including the one the instruction
stream is fetched through. And `VBAR_EL1` had never been written on this machine,
so an EL1 fault branched into whatever was in it — a hang carrying nothing. EL1
gets a vector table of its own, reading only EL1 registers; pointing it at the
EL2 table instead is worse than useless, because that table reads `ESR_EL2` and
faults inside itself forever.

**Ask before you jump.** `AT S1E1R` translates through EL1's regime and
**cannot fault** — an unreachable address lands in `PAR_EL1.F`. With `TGE` clear
it answers, for free, the question the drop otherwise answers by hanging. `TGE`
must be clear first: with it set, `AT S1E1R` uses the EL2&0 regime and tells you
nothing about EL1.

**One returning call per experiment.** A hang takes m1n1's proxy with it, so
anything sharing a call with a step that hangs is lost with it — including
measurements that already succeeded. `el1_probe` takes a stage argument for this
reason, and the safe measurements run in `kernel_probe` where nothing can hang.

Measured on 2026-08-16:

```
observed EL      EL1  DROPPED TO EL1
HCR before       0x0000032488000038
HCR after        0x0000032488000038  RESTORED
return vector    8  (lower EL, AArch64, synchronous)
EL1 fault        none -- EL1 reached its hvc without faulting
```

### SVC entry

Once the drop works, a system call is a small step, with two traps in it.

**Split on `ESR_EL1.EC`, not the vector index.** Vector 4 is "current EL,
`SP_ELx`, synchronous" — that is `SVC` *and* every data abort, alignment fault
and undefined instruction EL1 can raise. A handler that returns because the
index was 4 will re-execute a faulting instruction forever. `EC 0x15` is `SVC`
from AArch64; everything else on that vector should abandon the level.

**Do not advance `ELR_EL1`.** The EL2 handler adds 4 to step past a `brk`.
`ELR_EL1` after an `SVC` already points at the next instruction, so adding 4
skips a real instruction of the caller — silently, and only in the syscall path.

**Preserve registers on the return path.** The abandon path owes nothing,
because nothing resumes. The `SVC` path resumes, so it owes the caller every
register it touched — the same debt the EL2 handler learned when a timer FIQ
corrupted the values its neighbours were holding.

Measured:

```
SVC dispatches   1
ESR_EL1          0x0000000056000042  EC 0x15  ISS 0x42
ELR_EL1          0x000001000dfab120  (the instruction after the svc)
EL1 fault        none -- EL1 resumed after the svc and reached its hvc
```

Check all four. A dispatch count alone does not say *which* trap arrived, the
syndrome alone does not say EL1 resumed, and the absence of a fault record is
what proves the return path rather than the entry path.

### Getting to EL0

**Give the user page its own page, at both ends.** The EL0 code lives in a
section with `.balign 16384` before *and* after it. At this granule a page holds
four thousand instructions, so anything sharing it is handed to userspace along
with the code — verify with `llvm-nm -n` that no other symbol falls in the range.

**One page, not one block.** The smallest thing a block descriptor can say
anything about at a 16 KiB granule is 32 MiB. Marking the block EL0-accessible
is shorter and hands userspace the kernel's own code, so the 32 MiB containing
the user page is laid out as individual pages instead. Map the fine-grained
region **first**: the builder refuses to overwrite a table descriptor with a
block, and refuses to split a live block into pages, so the order is forced.

**Set `PXN` on user pages and `UXN` on kernel pages.** EL1 must not execute
memory EL0 can write, and EL0 must not execute the kernel even if a permission
bug ever made it readable.

**The gate is three `AT` instructions, and the one that matters must fail.**

```
kernel@EL1  0xff0001000c6f0b00  -> PA 0x1000c6f0000     must succeed
user@EL0    0xff0001000c6d0b00  -> PA 0x1000c6d0000     must succeed
kernel@EL0  0x000000000000081f  UNREACHABLE (FST 0xf)   MUST FAIL
```

`AT S1E0R` applies the unprivileged permission rules, so it answers "can
userspace reach this" rather than "is this mapped". Without the third question a
regime that accidentally made all of DRAM EL0-accessible passes every other
check. `AT` cannot fault, so the whole gate is free — and the `eret` to EL0 does
not happen unless all three answer correctly. Note `TGE` must be clear first, or
these describe the EL2&0 regime and say nothing about EL0 under EL1.

**Record the caller's exception level.** `SPSR_EL1.M[3:0]` is 0 for EL0t and 5
for EL1h. Without it an `SVC` from EL0 and one from EL1 produce identical
records, and "userspace made a system call" is the entire claim.

**Two calls, not one.** A syscall that *returns to userspace* is what a kernel
does constantly, and no trap test shows it. EL0 cannot reach EL2 itself, so the
second call carries a different immediate and EL1's handler makes the `HVC` on
its behalf. Split on the immediate rather than a counter: a handler whose
behaviour depends on how many times it has run is the same shape as the bug that
made the exception statics unreadable across probe runs.

**Counters in `.data` do not get zeroed.** `bss::zero` resets `.bss`. A static
with a non-zero initialiser lives in `.data` and accumulates for as long as the
image stays loaded — across every `p.call` in a session. The syscall count read
3 instead of 2 for exactly this reason. Excursions snapshot before they start
and report the difference.

## 9g. Pointer authentication: enabled is not the same as working

`SCTLR` bits for features a part does not implement are **RES0** — the write is
accepted and discarded. So read the register back; a bit that did not stick
means everything after it measures a feature that was never on.

Measured: `0x30901185` → `0x10f8903185`, with `EnIA`, `EnIB`, `EnDA`, `EnDB` and
`BT1` all set and all stuck.

That still proves nothing about authentication. With PAC disabled, signing
returns the pointer unchanged and authenticating it matches — every round-trip
test passes while the mitigation is absent. **Tamper with the signature.** Only
rejection distinguishes a working PAC from a disabled one:

```
plain            0x000001000d328138
signed as found  0x000001000d328138  unchanged -- a NOP beforehand, as expected
signed           0x024e01000d328138  signature present
recovered        0x000001000d328138  matches plain
tampered auth    0x02ce01000d328138  REJECTED
exception        vector 4 -- FEAT_FPAC faulted on the forged signature
```

Write `PACIA1716`/`AUTIA1716` as `hint #8`/`hint #12`. They are in the HINT
space precisely so a part without the feature NOPs them, and the raw form
assembles without the target enabling `pauth` — which it must not, because
whether the feature exists is a run-time question.

Two Apple specifics. `ID_AA64ISAR1_EL1.APA` (QARMA) is **0** and `API`
(implementation defined) is **4**: check only `APA` and you conclude PAC is
absent on hardware that has it, with `FEAT_FPAC` on top. And
`ID_AA64ISAR0_EL1 = 0x0221100110212120` — the `RNDR` field is **zero**, so
**this part has no hardware RNG**. The key comes from the boot seed instead;
see below.

### BTI: the register is the half that does nothing

`SCTLR.BT` is what everyone sets, and on its own it has **no effect**. BTI
constrains indirect branches only into pages whose descriptors carry `GP`
(bit 50), so on firmware's tables the feature cannot fire and every test of it
passes. Enforcement needs your own page tables; it is a page-table job wearing a
register's clothes.

**Guard only the page under test.** BTI is decided by the page the branch
*target* is in. Guard all of DRAM and the exception handler is guarded too — and
a Branch Target Exception raised inside the handler for a Branch Target
Exception is an unrecoverable loop, with no console, that looks exactly like BTI
not working.

**`BTI c` and `BTI j` are not interchangeable.** `BLR` needs `BTI c` (or `jc`);
`BR` needs `BTI j` (or `jc`). Landing a `BLR` on a `BTI j` faults, and the fault
is indistinguishable from the feature being broken. As HINTs: `bti` is
`hint #32`, `bti c` is `hint #34`, `bti j` is `hint #36`, `bti jc` is
`hint #38` — the HINT space again, so a part without `FEAT_BTI` NOPs them.

**Make the failing branch recoverable.** Point it at `nop; ret`. The exception
is taken *on* the `nop`, so the handler's usual four-byte advance lands on the
`ret` and returns to the caller. A test whose failure case wedges the machine
measures nothing.

**Check both directions, and read `GP` back.**

```
descriptor       0x000401000cebc603  GP=1
SCTLR enabled    0x0000001030901185  BT=1
blr -> plain instruction in a guarded page
  faulted        1  ESR 0x0000000036000002  EC 0xd
blr -> BTI c landing pad in the same page
  faulted        0  (must be 0)
```

The second branch is the one that proves discrimination rather than blanket
rejection. And without reading `GP` back out of the built descriptor, a builder
that dropped the bit gives a run where nothing faults — identical to a part
without the feature.

## 9h. Entropy on a part with no RNG

**`/chosen/random-seed`.** iBoot leaves 64 bytes there. `/chosen/cl4-entropy`
is the other candidate and is **192 bytes of zeros** on this machine — named
here so nobody spends the hour again.

**That it exists proves nothing.** A constant baked into the firmware image
would look identical to a fresh seed in any single read. Read it across boots
before trusting it:

```
fixture  7558166c851e9572
boot 1   3a182c6dcf382651
boot 2   fdee395561310b24
boot 3   4825d9b55323425a
```

All different, 63-64 of 64 bytes non-zero. That is a real per-boot seed.

**Hash it, do not slice it.** Two reasons. Firmware bytes should not reach a key
register as themselves — a partial disclosure of a derived key then says nothing
about the seed. And one seed has many consumers: PAC alone wants five key pairs,
and handing each a different slice of the same 64 bytes correlates them. A
domain separator gives each an independent-looking value.

**Erase it after use, and check that the erase happened.** Deriving from the
seed and leaving it in DRAM keeps a key-equivalent readable by anything that can
map that page, for the rest of the boot. Use `write_volatile`: an ordinary write
to memory that is never read again is precisely what an optimiser may delete,
and a deleted erase is indistinguishable from a successful one until someone
dumps the page. Read it back to confirm — `0 non-zero` is the only evidence that
counts.

**Refuse a bad seed rather than deriving from it.** An all-zero key
authenticates perfectly, passes every self-test, and protects nobody, because it
is the same key on every machine. `SeedQuality::usable` rejects absent, short,
all-zero and single-byte-pattern buffers. Refusing to install a key is the
honest outcome; installing a known one looks like a mitigation.

Note what this does and does not establish. That the seed is fresh per boot is
measured on hardware; that different seeds give different keys is proved by host
test. The composition gives per-boot keys. Comparing two signatures across boots
would *not* show it, because the signed pointer is the load address and that
moves on its own.

## 9i. Starting a second CPU

**There is no PSCI and there are no spin-tables.** The other cores are powered
down, not parked in a loop. Starting one is a reset vector plus two MMIO writes:

```
write64(cpu_impl_reg, entry)                       // RVBAR, 4 KiB aligned
write32(pmgr + 0x28000 + 0x4, 1 << (4*cluster+core))   // enable
write32(pmgr + 0x28000 + 0x8 + 4*cluster, 1 << core)   // release
```

`0x28000` is the T6020 offset and every Apple part has a different one. m1n1's
only comment on the first write is *"some kind of system level startup/status
bit. Without this, IRQs don't work"* -- that is the state of public knowledge.

**The RVBAR address field is bits 43:12, not `GENMASK(47,12)`.** Bits 47:44
carry die/cluster/core identity and read back unchanged whatever you write. A
mask that includes them makes a successful write look rejected -- which is
exactly the wrong conclusion the first measurement here produced. Writing the
register also **clears the lock bit**, which is what m1n1's cryptic "this also
clears RVBAR_LOCK" refers to. Measured on this part: writable.

Read it back and **refuse to start the core if the vector did not take**. A core
released to an address you did not choose runs arbitrary code beside you and
cannot be stopped: there is no IPI here, and m1n1 does not know it exists.

**The hard part is cache coherency, not architecture.** The secondary arrives
with `SCTLR.M = 0`, so its accesses bypass the data cache entirely, while the
boot core's writes may still be dirty in it. Both directions need handling and
neither fails loudly:

- Clean the stub *and* its report buffer with **`dc civac`** before release --
  point of coherency. `dc cvau` reaches only the point of unification, which is
  enough for instruction fetch on a coherent core and not for this one.
- Invalidate before every poll, or the boot core reads a line it cached earlier
  and never sees the report.

**Write the magic last, after a `dsb sy`, and poison the buffer first.**
Otherwise a reader can see the magic while the rest is still stale, and report a
core that started with an MPIDR it never wrote.

**Compare MPIDR, not just the magic.** A magic word proves *something* wrote the
buffer. A different affinity proves it was a different core.

```
RVBAR before     0x00111100039fc001  LOCK=1
RVBAR after      0x001111000dfac000  LOCK=0  ACCEPTED
started          1   after 176 ticks (7.3 us at 24 MHz)
MPIDR_EL1        0x0000000080000001  aff0=1 aff1=0 aff2=0
CurrentEL        EL2
SCTLR_EL1        0x0000100030d50980  M=0
```

It is one shot per boot. The stub parks in `wfe` and there is no way to recall
it, so a second attempt in the same session times out -- which is honest: the
core is running, just not listening.

## 10. Driving the machine when you are not next to it

Recovery work needs a keyboard on the target and eyes on its screen. Both can be
remote.

- **Keyboard:** `tools/flipper/brainx-flipper-one` turns a Flipper Zero into a
  USB keyboard for the target, driven over BLE from the workstation with
  `bin/brainx-ble.py`. It was verified to type all 46 characters of
  `Test.ABC xyz 123 !@#$%^&*()_+-={}[]|:;"<>,.?/~` byte-identically, so shifted
  characters are not a concern. Lines are capped at 191 characters.
- **Screen:** `bin/screenshot-mini.sh` grabs a still through a camera pointed at
  the display. Aim it so the **bottom** of the terminal window is in frame; the
  prompts are there, and a view that cuts them off produces exactly the
  guess-and-hope debugging this runbook exists to prevent.
- **Note:** `clear` does not exist in recoveryOS, so you cannot scroll output
  back to the top of the window that way.

## 11. Checklist

```
[ ] separate volume group, and its UUID re-read this session
[ ] payload staged, hash verified under macOS (not recoveryOS)
[ ] as-preflight.sh reports READY
[ ] the experiment group has its OWN Recovery volume (diskutil apfs list)
[ ] bputil -e read FIRST: target group Paired, and coih absent
[ ] pmset -a sleep 0 displaysleep 0 disksleep 0
[ ] do NOT type `exit` in the Recovery Terminal until finished
[ ] if coih is already set: bputil -f to clear it (needs Ethernet), never -r
[ ] bputil -n -c, no -k
[ ] bputil -d confirms Permissive before touching the boot object
[ ] entry point taken from payloads.tsv, per payload
[ ] kmutil's three prompts answered one at a time
[ ] as-verify-install.sh --record <name>
[ ] console read over the USB gadget, not the debug-console device
[ ] proxy connected on the same port as the console
```
