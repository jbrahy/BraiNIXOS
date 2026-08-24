#!/bin/bash
#
# Print the avfoundation index of the best device for seeing the mini's screen.
#
# The camera pointed at the monitor was always a workaround. It gave a
# photograph of a screen at an angle, in a dark room, which OCR reads at maybe
# 85% and a human reads slowly -- and which silently becomes a photograph of
# the room the moment somebody moves the laptop. Two wrong diagnoses in one
# night came out of that loop.
#
# An HDMI capture dongle removes it entirely: the mini's own framebuffer, in
# pixels, over USB. It has to be a CAPTURE device (HDMI in -> USB, UVC class),
# not a USB-C-to-HDMI adapter, which carries video the other way and cannot
# work no matter how it is plugged in.
#
# Preference order, best first:
#   1. anything that looks like a capture dongle (USB/UVC/HDMI/chipset names)
#   2. the built-in FaceTime camera, i.e. the old analog loop
#
# Deliberately never chosen:
#   * "/dev/null Camera" -- the Continuity Camera when the phone has left.
#     ffmpeg HANGS on it rather than failing, which reads as a dead machine.
#   * "Capture screen N" -- that is THIS laptop's screen, not the mini's.
#
#   ./bin/as-capture-device.sh          # prints an index, e.g. 4
#   ./bin/as-capture-device.sh --list   # show what was found and why
set -uo pipefail

LIST="$(ffmpeg -f avfoundation -list_devices true -i "" 2>&1 \
        | sed -n '/AVFoundation video devices/,/AVFoundation audio devices/p' \
        | grep -oE '\[[0-9]+\] .*$' || true)"

[ -n "$LIST" ] || { echo "no avfoundation video devices found" >&2; exit 1; }

if [ "${1:-}" = "--list" ]; then
  printf '%s\n' "$LIST"
  exit 0
fi

pick=""
# A capture dongle reports whatever string its firmware carries, and the cheap
# ones vary wildly, so match on the families rather than one model.
while IFS= read -r line; do
  idx="$(printf '%s' "$line" | sed -E 's/^\[([0-9]+)\].*/\1/')"
  name="$(printf '%s' "$line" | sed -E 's/^\[[0-9]+\] //')"
  case "$name" in
    *"/dev/null"*|*"Capture screen"*) continue ;;
  esac
  case "$name" in
    *USB*|*UVC*|*HDMI*|*MACROSILICON*|*MS2109*|*Cam\ Link*|*Elgato*|*Video*)
      pick="$idx"; break ;;
  esac
done <<< "$LIST"

if [ -z "$pick" ]; then
  # Fall back to the first real camera, which is the analog loop.
  while IFS= read -r line; do
    idx="$(printf '%s' "$line" | sed -E 's/^\[([0-9]+)\].*/\1/')"
    name="$(printf '%s' "$line" | sed -E 's/^\[[0-9]+\] //')"
    case "$name" in
      *"/dev/null"*|*"Capture screen"*) continue ;;
    esac
    pick="$idx"; break
  done <<< "$LIST"
fi

[ -n "$pick" ] || { echo "no usable video device" >&2; exit 1; }
printf '%s\n' "$pick"
