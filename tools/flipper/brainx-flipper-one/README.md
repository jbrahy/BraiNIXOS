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

## Why not BLE HID, which would need no app at all

Because the firmware will not let an external app do it. In
`api_symbols.csv` every `ble_profile_hid_*` function, the `ble_profile_hid`
descriptor, and every `ble_svc_hid_*` function are marked `-` — not exported to
FAPs. That is a policy in the API table, not a defect to route around, and an
app that calls them fails to load with `err_04 Missing imports`. `usb_hid`,
every `furi_hal_hid_*` function, and the whole BLE serial profile are `+`.

## The bug that made this design look broken the first time

The serial service is flow-controlled by the **return value** of its event
callback: it is the number of further bytes the app will accept. Return zero and
the credit is zero, so a peer's writes are accepted by CoreBluetooth,
acknowledged as successful, and then never delivered. That is exactly what
"the write returned success and `rx` stayed at 0" looked like, and it is
invisible from the workstation end. `serial_service.h` types the callback as
returning `uint16_t` and says nothing about what the number means. Every return
path in `ble_rx_callback` yields a non-zero credit.

## Safety

Whatever arrives over BLE is typed into a root shell. The OK button toggles
arming and the state is on screen. It **defaults to armed**, because the machine
this drives is usually unattended — the button is a kill switch for someone
standing at the Flipper, not a gate. Leaving the app disarms by ending it.

Two more deliberate refusals:

- **Whole lines only.** Input is buffered until a newline before anything is
  typed. A command typed in fragments as BLE packets arrive would execute a
  *prefix of itself* if the tail were dropped.
- **Over-long lines are discarded whole**, and so are lines that arrive while
  the queue is full, rather than typing a truncation. Both are logged.

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

## Commands, one per line over BLE

```
type <text>     type <text> and press Return
raw <text>      type <text> with no Return
key <name>      enter tab esc space up down left right ctrl-c ctrl-d cmd-tab
status          report both links, armed state, lines typed, bytes received
```

Every command answers on the same characteristic, including refusals, so the
workstation can tell "sent" from "delivered" — a distinction whose absence
produced three wrong conclusions during this bring-up.

**The FAP's API version must match the firmware's.** Built against 87.1; the
device was on 0.105.0 / API 72.1 and was updated to 1.4.3 to match. A mismatch
does not warn, it simply fails to load.

## Not a substitute for m1n1

One-directional with respect to the target: it cannot read the screen and cannot
hold the power button for One True Recovery. It removes transcription error and
makes the command set correctable at the moment of use. The feedback loop is
still Phase 1 of the bring-up plan.
