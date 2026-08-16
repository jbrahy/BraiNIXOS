# brainx-flipper-one

A Flipper Zero app that bridges **BLE in** to **USB HID out**: lines sent from a
workstation over Bluetooth are typed into whatever the Flipper is plugged into.

## Why

Apple Silicon recovery-mode bring-up means typing long `bputil` and `kmutil`
invocations into a shell with no history, no paste, and nothing readable back.
Two of this project's failures were transcription errors. See
[`../../docs/operations/BRINGUP_PLAN.md`](../../docs/operations/BRINGUP_PLAN.md).

BadUSB scripts solve half of that, but the Flipper has **one USB port**: plugged
into the target it is not connected to the workstation, so the command set must
be decided in advance and cannot be corrected once the target's state is known.
BLE and USB are independent peripherals, so this app is a keyboard to the target
and a BLE endpoint to the workstation **at the same time**.

## Safety

Whatever arrives over BLE is typed into a root shell, so **typing is disarmed
until armed physically on the device** with the OK button. A BLE peer cannot arm
itself; a stray connection can type nothing. The armed state is on screen, and
leaving the app disarms.

Two more deliberate refusals:

- **Whole lines only.** Input is buffered until a newline before anything is
  typed. A command typed in fragments as BLE packets arrive would execute a
  *prefix of itself* if the tail were dropped.
- **Over-long lines are discarded whole**, and a full buffer is reported on
  screen as `OVF`, rather than typing a truncation.

`KEY_DELAY_MS` exists because recoveryOS Terminal drops characters typed faster
than about 12 ms apart, and a dropped character in a path fails as "no such
file" — which reads like a staging problem rather than a typing one.

## Build

```
ufbt update --channel=release     # SDK; must match the device's API
ufbt                              # build
python3 ~/.ufbt/current/scripts/storage.py send \
    dist/brainx_flipper_one.fap /ext/apps/Tools/brainx_flipper_one.fap
```

`ufbt launch` also works but *starts* the app, which switches the Flipper's USB
to HID and drops the CLI — unhelpful when it is plugged into the workstation.

**The FAP's API version must match the firmware's.** Built against 87.1; the
device was on 0.105.0 / API 72.1 and was updated to 1.4.3 to match. A mismatch
does not warn, it simply fails to load.

## Not a substitute for m1n1

One-directional with respect to the target: it cannot read the screen and cannot
hold the power button for One True Recovery. It removes transcription error and
makes the command set correctable at the moment of use. The feedback loop is
still Phase 1 of the bring-up plan.
