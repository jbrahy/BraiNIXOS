#!/bin/bash
#
# Grab a still of the mini's display through a camera.
#
# This is the feedback loop docs/operations/BRINGUP_PLAN.md says the bring-up
# has been missing. Everything about that machine in recovery -- the startup
# picker, kmutil's output, and AS-1a's stage stripes -- exists only as pixels
# on a monitor. A camera pointed at it is the difference between one bit per
# physical trip and something readable on demand.
#
#   ./bin/screenshot-mini.sh            # default device, writes to the scratchpad
#   ./bin/screenshot-mini.sh 1 out.jpg  # explicit avfoundation device index
#
# List devices with:
#   ffmpeg -f avfoundation -list_devices true -i ""
set -eu

DEVICE="${1:-1}"          # 1 is usually the Continuity Camera; 0 is the built-in
OUT="${2:-/private/tmp/claude-501/-Users-jbrahy-OtherProjects-brainix/3aab4a38-fd47-451e-9a65-11f8a595da95/scratchpad/mini-$(date +%H%M%S).jpg}"

# -update 1 because a single still is not an image sequence, which ffmpeg
# otherwise warns about at length while doing the right thing anyway.
ffmpeg -y -loglevel error \
    -f avfoundation -framerate 30 -video_size 1920x1080 \
    -i "$DEVICE" -frames:v 1 -update 1 "$OUT" 2>/dev/null \
  || ffmpeg -y -loglevel error \
    -f avfoundation -framerate 30 \
    -i "$DEVICE" -frames:v 1 -update 1 "$OUT"

printf '%s\n' "$OUT"
