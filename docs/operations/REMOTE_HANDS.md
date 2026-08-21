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

### The camera does not see the whole screen

**Roughly the leftmost 24 terminal columns and the entire menu bar sit outside
the camera frame.** The monitor extends up and to the left of what the lens
covers, and nothing on the laptop can pan it. This is not a focus or exposure
problem and no amount of cropping recovers those pixels.

The consequence is specific and it wasted most of an hour: **short output lines
are completely invisible.** A shell prompt is ten characters, so it never
appears; `ok` appears as nothing at all. A screen that has genuinely changed
looks identical to a screen that has frozen.

So indent everything past the cut, and make every signal long:

```sh
some-command 2>&1 | sed "s/^/                                   /"
```

Thirty-five spaces clears the margin with room to spare. Prefer verdicts that
survive a blurry photograph -- `GOOD GOOD GOOD` against `BAD BAD BAD` reads at
a glance where a single digit or an exit code does not.

Before trusting "the screen did not change", check the camera is live:
consecutive JPEGs of an unchanging screen still differ in sensor noise, so
identical content with differing `md5` means the display really is static.

### The Flipper can report a link it no longer has

On 2026-08-20 the mini stopped acting on keystrokes partway through a Recovery
session. `status` kept saying `ble=linked usb=linked armed`, the `typed=`
counter kept climbing, and every `type` returned `ok`. Seventy-two characters
sent in one burst produced no change anywhere on screen.

`furi_hal_hid_is_connected()` reports the USB configured state, which is not
the same claim as "the host is acting on my reports". **An `ok` from the app
means the report was queued, and nothing more.** Do not read it as delivery.

There is no command that re-enumerates USB, so there is no way out of this from
the laptop: it needs the Flipper unplugged and replugged, or the mini
power-cycled. Both are hands-on. Adding a `reconnect` verb to the app that
cycles `furi_hal_usb_set_config` would remove the trip, and is the highest-value
change left in the app.

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
