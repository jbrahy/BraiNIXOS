# Remote hands: driving the mini with no hands on it

The mini has no console until m1n1 is installed, and no ssh until macOS is
booted. Everything before those two points — the startup picker, macOS Recovery,
`bputil` and `kmutil` output — exists only as pixels on a monitor and only
accepts input from a keyboard plugged into the machine.

This is how to work it anyway. Written 2026-08-20 after learning all of it the
slow way in one session.

## The two instruments

| | |
| --- | --- |
| **Eyes** | `bin/screenshot-mini.sh <device>` — the laptop's camera pointed at the mini's monitor. |
| **Hands** | `bin/brainx-ble.py send '<command>'` — a Flipper Zero plugged into the mini as a USB HID keyboard, driven from the laptop over BLE. |

Neither is optional. The Flipper is one-directional and cannot read the screen;
the camera cannot type. Together they are a full remote console for a machine
that offers none.

### Camera: use device 0

```sh
./bin/screenshot-mini.sh 0
```

**The script's default is device 1, and that default is usually wrong.** Device 1
is the Continuity Camera — an iPhone — which is only present while the phone is.
When the phone leaves the room the index becomes a `/dev/null Camera` placeholder
and `ffmpeg` hangs indefinitely rather than failing. Device 0 is the built-in
FaceTime camera, which is bolted to the laptop and always there.

List them with:

```sh
ffmpeg -f avfoundation -list_devices true -i ""
```

Screens photograph badly at this angle. Crop and upscale before reading anything
small — a focus ring is a few pixels wide on the full frame and obvious at 3x:

```sh
ffmpeg -y -i shot.jpg -vf "crop=900:560:520:330,scale=1400:-1" crop.jpg
```

### Flipper: expect to retry

```sh
./bin/brainx-ble.py send 'status'      # ble=linked usb=linked armed
./bin/brainx-ble.py send 'key enter'
./bin/brainx-ble.py send 'type ls /Volumes'
```

**BLE advertising is intermittent. One attempt in two or three finds nothing and
that is normal, not a fault.** Wrap every send in a retry:

```sh
for a in 1 2 3; do
  r=$(timeout 120 ./bin/brainx-ble.py send 'key enter' 2>&1 | tail -1)
  case "$r" in *ok*) break;; esac
done
```

`status` reporting `usb=linked` means the mini has enumerated the Flipper as a
keyboard, which also means **the mini is powered**. A machine that is truly off
does not enumerate USB. If the TV says "No Signal" but `usb=linked`, the mini is
asleep or the TV is on the wrong input — not dead.

The app accepts exactly these keys, and nothing else:

```
enter  tab  esc  space  up  down  left  right  ctrl-c  ctrl-d  cmd-tab
shift-cmd-t
```

`raw <text>` is `type` without the trailing Return, not an escape hatch for
arbitrary HID codes. There is no way to send a modifier combination the table
does not already list.

**Terminal in Recovery is Shift-Cmd-T, not a menu-bar trip.** An earlier
version of this file said the menu bar was the only route and that Ctrl-F2 was
needed to reach it. That was wrong. Recovery's Utilities menu prints the
shortcut beside the item, and it reads Shift-Cmd-T; the key was added to
`named_keys[]` on 2026-08-20. There is still no F-key in the table, and nothing
so far has needed one.

### Check the frame covers the whole screen, first, every time

**The very first shot of a session must show the menu bar and all four edges of
the display.** On 2026-08-20 it did not: the lens covered one corner of the
monitor, the leftmost terminal columns and the entire menu bar were outside the
frame, and roughly an hour went into diagnosing a keyboard that was working
perfectly. Output was arriving where the camera could not see it.

Nothing on the laptop can pan or zoom the camera, so a bad frame is a bad
session. If the menu bar is not in shot, stop and get the camera re-aimed
before doing anything else.

Once framing is confirmed, two habits still pay:

Screens photograph badly at an angle, so crop and upscale before reading
anything small, and lift the gamma -- terminal text at this distance is a few
pixels per glyph:

```sh
ffmpeg -y -i shot.jpg -vf "crop=680:400:355:240,scale=2720:-1,eq=brightness=0.06:contrast=1.5" crop.jpg
```

And prefer verdicts that survive a blurry photograph. `GOOD GOOD GOOD` against
`BAD BAD BAD` reads at a glance where a single digit or an exit code does not.

Before trusting "the screen did not change", check the camera is live:
consecutive JPEGs of an unchanging screen still differ in sensor noise, so
identical content with differing `md5` means the display really is static.

### "The keyboard is dead" was the framing, twice

On 2026-08-20 I concluded from a static screen that the mini had stopped acting
on keystrokes, that `furi_hal_hid_is_connected()` was reporting a link the
Flipper no longer had, and that the session needed a person to replug it. All
of that was wrong. Every keystroke had landed. The camera was pointed at one
corner of the monitor and the terminal's output was arriving outside the frame,
so a working system produced a photograph indistinguishable from a wedged one.

The tell I should have used, and did not: **the frame was not the whole
screen.** If the menu bar is not in shot, nothing about what is in shot can be
trusted to be all of it. Check the frame covers the display before drawing any
conclusion from what is missing.

The general failure is worth naming because it has now happened twice in one
session, both times as an *absence*: no output, no reaction. An absence is the
weakest evidence there is, because every layer between the key and the pixel
can produce it. Before concluding a component is broken, make it produce a
positive signal -- something that must appear if the component works -- and
only then read silence as failure.

## Navigating macOS Recovery by keyboard

This cost the most time, so it is written out in full. The rules are not the
ones you would guess, and one wrong key restarts the machine and costs a
physical trip.

**1. Focus does not exist until you create it.** On a fresh screen nothing is
highlighted and arrow keys appear dead. `down` establishes focus on the first
control. Only then do `left`/`right` move it. Two `right` presses on a screen
with no focus do nothing at all, which reads exactly like "the keyboard is not
connected".

**2. `enter` selects an icon but does not advance.** On the volume picker it
puts the grey selection box on a volume and stops. The screen does not move.

**3. `tab` cycles to the buttons, and Restart comes first.** From the volume
grid, one `tab` lands on **Restart** — the button that ends the session and
costs another power-button hold. A second `tab` reaches **Next**. Photograph
between them. Do not press anything on faith here.

**4. `space` activates a focus-ringed button; `enter` does not.** This is the
macOS convention and it is the opposite of the picker's behaviour one screen
earlier. A blue ring around Next plus `enter` does nothing at all; `space`
advances.

The working sequence for "Options → Macintosh HD → authenticate":

```
key down          establish focus            -> BraiNIX highlighted
key right         move to the right volume   -> Macintosh HD highlighted
key enter         select it                  -> box stays, screen does not move
key tab           focus the buttons          -> Restart ringed  (DO NOT press)
key tab           next button                -> Next ringed
key space         activate                   -> admin user picker
```

Pick **Macintosh HD**, not BraiNIX: the scripts live on Macintosh HD's data
volume, and that group's data only unlocks if you authenticate against it.

## kmutil asks a question, and a stray keystroke answers it

`kmutil configure-boot` prompts on stdin before it installs anything:

```
By setting a custom boot object, you will be putting your system into
Permissive Security.
Are you sure you want to do this? (enter y or n)
```

It is not in Apple's documentation for the subcommand, and on 2026-08-21 it ate
a run: the prompt was below the visible fold, the shell looked hung, and the
next command sent became the answer. `grep` is not `y`, so it aborted and the
script reported `kmutil configure-boot failed` with nothing about a question.

**Once the install is launched, send nothing until the prompt is on screen.**
Then send exactly `y`. `as-install-boot-object.sh` now prints a warning to this
effect immediately before the call. The window title is a good progress signal
here -- it reads `Terminal - kmutil - sh as-install-boot-object.sh` for as long
as the tool is working, which is a couple of minutes and looks like a hang.

## pairing (17): the group already has a custom boot object

Diagnosed 2026-08-21. The install is blocked behind a network requirement, not
behind anything about the picker or the credentials.

Answering kmutil's prompts with `jbrahy` and the admin password clears the
first error -- `not a valid admin user for the volume at /Volumes/Preboot/<VG>/`
disappears, so the credential is correct. What is left is:

```
Error Domain=KMErrorDomain Code=71 "Boot policy error: Error updating custom os
local policy: code pairing (17)"
```

and `bputil -n -c -v <VG> -u <user> -p <pass>` fails with the same underlying
error, which is the useful part:

```
Boot objects update failed for <VG>: Error Domain=BYErrorDomain Code=401
"Failed to create local policy" NSUnderlyingError=
  {Domain=com.apple.bootpolicy Code=17 "pairing (17)"}
```

Two tools, one error, at LocalPolicy creation. So it is not kmutil, and it is
not the skipped `bputil` step in `as-install-boot-object.sh`.

Ruled out by inspection, so do not spend time re-checking:

| Suspicion | Evidence against |
| --- | --- |
| Target is a bare volume, not an OS | `/Volumes/BraiNIX` has Applications, Library, System, Users, bin, usr, var; `System/Library/CoreServices` is populated |
| Wrong or non-owner credential | `diskutil apfs listUsers /Volumes/BraiNIX` shows 2 cryptographic users on disk3s8, both `Volume Owner: Yes`; `/Volumes/BraiNIX/Users` has a `jbrahy` home |
| Policy not Permissive | `Security Mode: Permissive (smb0 && smb1): 1`, `Kernel CTRR Status: Disabled (sip2): 1` |
| Payload wrong | 193857 bytes, matches `payloads.tsv`; kmutil got as far as `found raw boot object, deriving Mach-O boot properties... wrapping boot object payload...` |

**Use `bputil -e`, not `bputil -d`.** This is the command that ended the
guessing, and it should be the first one run next time. `-d` prints the policy
of the *booted* environment, which in 1TR tells you almost nothing; `-e`
prints every policy on the machine:

| | BraiNIX `5B900D83-...` | Macintosh HD `C40FFC20-...` |
| --- | --- | --- |
| OS Pairing Status | **Not Paired** | Paired |
| Security Mode | Permissive (smb0 && smb1): 1 | Full |
| coih | `8BABB8ED...D87375F` | absent |

That is the error in plain form: the BraiNIX group is Not Paired and already
carries a custom boot object from an earlier install, and a new LocalPolicy
cannot be written over that. The same symptom is reported against the Asahi
installer by a user who also had a custom boot policy already set:
<https://github.com/AsahiLinux/asahi-installer/issues/50>.

So the fix is to clear the stale `coih` first, by setting **that group only**
back to Full Security -- the operation Startup Security Utility performs, and
reversible. Do NOT reach for `bputil -r/--remove`; it deletes the policy
outright and is the shape of mistake that already cost this machine a volume
group.

### and Full Security needs the Internet

`bputil -f` then fails, harmlessly and before changing anything:

```
Boot objects update failed for <VG>: Error Domain=BYErrorDomain Code=102
"Can't continue because you are not connected to the Internet"
  {AuthInstallErrorDomain Code=11}, BYErrorHint=NetworkRequired,
  BYPersonalizationType=os
```

Full Security is personalized against Apple's servers, so it needs real
connectivity. Permissive and `coih` are signed locally by the SEP and do not.

**recoveryOS has no `networksetup`** -- only `/sbin/ifconfig` and
`/usr/sbin/ipconfig`. There is therefore no way to join Wi-Fi from the Terminal,
and Recovery does not inherit the Wi-Fi association from macOS. The Wi-Fi picker
in the menu bar is the only route, and the menu bar needs a mouse.

**So this step needs an Ethernet cable, and that is a physical act.** The mini's
built-in port is `en0` (`5c:e9:1e:e8:a9:45`) and reads `status: inactive` with
nothing plugged in. With a cable: `ipconfig set en0 DHCP`, confirm an address,
then Full Security, then back to Permissive, then install.

Add this to the list of things that need a person, alongside holding the power
button.

## What still needs a person

**Entering Recovery.** Holding the power button is the only way in. This is not
an oversight to route around — One True Recovery requires physical presence by
design, and that is the property it exists to have. Checked and confirmed on
macOS 15.3.1: there is no `recovery-boot-mode` nvram key and `bless` has no
`--nextonly`/`--recovery` on Apple Silicon.

**The admin password.** Recovery asks which admin user you know the password for
and then asks for it. There is no way around this and there should not be.
Either a person types it, or it is handed to the Flipper to type — in which case
it is a secret in a shell command, so treat it accordingly and never commit it.

Everything between those two points can be done from the laptop.

## Reaching the mini over the network

Use the mDNS name, not a remembered address:

```sh
ssh jbrahy@baby-jesus.local
```

**The IPv4 address moves.** `~/.ssh/config` has a `mini-ip` entry pointing at
`192.168.0.136`; the machine was on `192.168.0.151` on 2026-08-20 and every
attempt against the stale address timed out in a way that looks exactly like a
powered-off machine. `dscacheutil -q host -a name baby-jesus.local` prints what
it actually has.

ssh only answers when the mini is booted into **macOS**. Its default boot object
is a custom one, so a plain reboot does not land there.
