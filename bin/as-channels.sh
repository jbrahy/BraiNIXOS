#!/bin/bash
#
# Enumerate every channel the workstation has for observing or driving the
# mini, and report which are alive right now. Run on the workstation.
#
#   ./bin/as-channels.sh
#
# WHY
#
# BRINGUP_PLAN.md item 5: two silent output channels were read as two broken
# channels rather than as "nothing ran", and that cost a day. The only defence
# is knowing, at the moment of the observation, which channels were actually
# capable of carrying a byte. A silent serial console means something entirely
# different depending on whether the serial rig was up.
#
# Nothing here modifies the mini. `macvdmtool serial` is the one exception --
# it puts both ends into serial mode, which is what the rig is for and is
# harmless -- and it is only run when --serial is passed.

set -u

MINI_HOST="${MINI_HOST:-jbrahy@baby-jesus.local}"
MACVDM="${MACVDM:-/Users/jbrahy/OtherProjects/_tools/macvdmtool/macvdmtool}"
HERE="$(cd "$(dirname "$0")" && pwd)"
DO_SERIAL=0
[ "${1:-}" = "--serial" ] && DO_SERIAL=1

row() { printf '  %-22s %-8s %s\n' "$1" "$2" "$3"; }

printf '\nchannel                state    detail\n'
printf -- '-------------------------------------------------------------------------\n'

# --- ssh ------------------------------------------------------------------
# The best channel by far when it exists, and the one that tells you the mini
# is running macOS rather than anything of ours.
if OUT="$(ssh -o ConnectTimeout=6 -o BatchMode=yes "$MINI_HOST" 'sw_vers -productVersion; diskutil info / | awk -F": *" "/Volume Name/{print \$2}"' 2>/dev/null)"; then
  VER="$(printf '%s' "$OUT" | sed -n 1p)"
  VOL="$(printf '%s' "$OUT" | sed -n 2p)"
  row "ssh" "UP" "macOS $VER on $VOL"
  SSH_UP=1
else
  row "ssh" "DOWN" "no shell: mini is off, in recoveryOS, or running our payload"
  SSH_UP=0
fi

# --- thunderbolt ----------------------------------------------------------
# A link here needs firmware on BOTH ends. Its absence is expected while the
# mini runs a bare-metal payload, and is NOT evidence of a fault.
TB="$(system_profiler SPThunderboltDataType 2>/dev/null | grep -c 'Device Name: Mac')"
if [ "${TB:-0}" -gt 1 ]; then
  row "thunderbolt/usb4" "UP" "a Mac is linked on the bus"
else
  row "thunderbolt/usb4" "DOWN" "no device; expected unless the mini runs macOS"
fi

# --- usb-pd / vdm ---------------------------------------------------------
# Works at the power-delivery layer, so it answers even when the mini is
# running nothing at all. That makes it the one honest "is a cable attached"
# signal on this rig.
if [ -x "$MACVDM" ]; then
  VDM="$(sudo -n "$MACVDM" status 2>&1)"
  # Read the output rather than mapping a non-zero exit onto the first guess.
  # The first version of this line reported "needs passwordless sudo" for a
  # tool that had run perfectly and was telling us the cable was unplugged.
  case "$VDM" in
    *"a password is required"*|*"sudo:"*)
      row "usb-pd vdm" "BLOCKED" "sudo needs a password in this session" ;;
    *"No connection detected"*|*"Connection: None"*)
      row "usb-pd vdm" "DOWN" "no USB-C connection: the cable to the mini is unplugged" ;;
    *"Connection:"*)
      row "usb-pd vdm" "UP" "connection: $(printf '%s' "$VDM" | sed -n 's/^Connection: *//p' | head -1)" ;;
    *)
      row "usb-pd vdm" "UNKNOWN" "unrecognised macvdmtool output" ;;
  esac
else
  row "usb-pd vdm" "ABSENT" "macvdmtool not at $MACVDM"
fi

# --- serial console -------------------------------------------------------
# OQ-5 is still open: whether this device carries the mini's bytes at all is
# unproven. Report what it is, and only claim silence after actually reading.
if [ -e /dev/cu.debug-console ]; then
  if [ "$DO_SERIAL" = 1 ] && [ -x "$MACVDM" ]; then
    sudo -n "$MACVDM" serial >/dev/null 2>&1
    TMP="$(mktemp)"
    ( timeout 8 cat /dev/cu.debug-console > "$TMP" ) 2>/dev/null
    N="$(wc -c < "$TMP" | tr -d ' ')"
    rm -f "$TMP"
    if [ "${N:-0}" -gt 0 ]; then
      row "serial console" "UP" "$N bytes in 8s"
    else
      row "serial console" "SILENT" "device exists, 0 bytes in 8s (OQ-5 unresolved)"
    fi
  else
    row "serial console" "PRESENT" "/dev/cu.debug-console exists; pass --serial to read it"
  fi
else
  row "serial console" "ABSENT" "run macvdmtool serial first"
fi

# --- flipper over ble -----------------------------------------------------
# The only channel that can drive the mini when it has no OS to log into.
if [ -x "${HERE}/brainx-ble.py" ]; then
  if BLE="$(timeout 60 "${HERE}/brainx-ble.py" send status 2>&1 | grep -E '^\s+ble=')"; then
    row "flipper ble" "UP" "$(printf '%s' "$BLE" | tr -s ' ' | sed 's/^ //')"
  else
    row "flipper ble" "DOWN" "no reply: app not running, or out of range"
  fi
else
  row "flipper ble" "ABSENT" "brainx-ble.py not found"
fi

# --- flipper over usb cli -------------------------------------------------
# Mutually exclusive with the Flipper acting as a keyboard: the app takes USB
# for HID, so this port disappearing is a sign the app is running, not a fault.
if ls /dev/cu.usbmodemflip_* >/dev/null 2>&1; then
  row "flipper usb cli" "UP" "$(ls /dev/cu.usbmodemflip_* | head -1) -- app is NOT running"
else
  row "flipper usb cli" "DOWN" "no port; expected while the app holds USB as HID"
fi

# --- camera ---------------------------------------------------------------
# The mini's screen is the only place iBoot, the startup picker and our stripes
# ever appear. Without this there is no way to read any of them.
if command -v ffmpeg >/dev/null 2>&1; then
  CAMS="$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 | awk '/AVFoundation video devices/,/AVFoundation audio devices/' | grep -c '\[[0-9]\]')"
  if [ "${CAMS:-0}" -gt 0 ]; then
    row "camera" "UP" "$CAMS video device(s); ./bin/screenshot-mini.sh"
  else
    row "camera" "DOWN" "ffmpeg present but no video devices"
  fi
else
  row "camera" "ABSENT" "ffmpeg not installed"
fi

printf -- '-------------------------------------------------------------------------\n'

# --- remote preflight -----------------------------------------------------
if [ "$SSH_UP" = 1 ]; then
  printf '\nRunning as-preflight.sh on the mini over ssh:\n'
  ssh -o ConnectTimeout=8 "$MINI_HOST" 'sh /Users/Shared/brainix-boot/as-preflight.sh' 2>&1 | sed 's/^/  /'
else
  printf '\nNo ssh, so the mini-side preflight was not run. Boot Macintosh HD, or run\n'
  printf 'it by hand from the recoveryOS Terminal:\n'
  printf '  sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh\n'
fi
