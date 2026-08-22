#!/bin/bash
#
# Read the only success signal a custom boot object gives, and say which rung
# it reached.
#
# There is no console and no screen. The framebuffer handed to a custom boot
# object is a dummy that is never scanned out, and the SBU serial path on this
# rig delivers zero bytes -- measured, with m1n1's own output too. So the
# report is the INTERVAL BETWEEN REBOOTS: _start climbs a ladder and re-arms
# the watchdog four seconds longer at each rung, so how long the machine stays
# on the USB bus is how far it got.
#
# FIRST_LIGHT_RUNBOOK.md prints a while-loop and asks you to eyeball the gaps.
# This does the arithmetic instead, because a human timing reboots by eye is
# the same one-bit-per-trip feedback loop the whole bring-up effort exists to
# escape -- and misreading 17s as 21s means blaming the wrong rung.
#
#   ./bin/as-watch-boot.sh              # watch until interrupted
#   ./bin/as-watch-boot.sh --cycles 3   # stop after three reboots
#
set -uo pipefail

CYCLES=0
case "${1:-}" in --cycles) CYCLES="${2:-0}" ;; esac

DEV_GLOB='/dev/cu.usbmodem*'

present() { compgen -G "$DEV_GLOB" >/dev/null 2>&1; }

# The ladder, from as-install-boot-object.sh. Each rung adds four seconds, so
# the boundaries sit midway between the published marks: a run that leaves at
# 15s is the 13s rung, not the 17s one.
verdict() {
  local s=$1
  if   (( s < 3  )); then echo "did not reach the first rung (dead before the watchdog was armed)"
  elif (( s < 7  )); then echo "~5s   device tree parsed, /arm-io/wdt found and armed"
  elif (( s < 11 )); then echo "~9s   cpu topology read"
  elif (( s < 15 )); then echo "~13s  /arm-io/pmgr translated"
  elif (( s < 19 )); then echo "~17s  a second cpu released, reported its own MPIDR"
  elif (( s < 24 )); then echo "~21s  its own page tables built"
  else                    echo "~26s  MMU AND CACHES ON -- the whole ladder, the good outcome"
  fi
}

printf 'watching %s\n' "$DEV_GLOB"
printf 'Pick BraiNIX at the startup picker now. Ctrl-C to stop.\n\n'

n=0
while :; do
  # Wait for the device to appear (the machine booting).
  until present; do sleep 0.5; done
  up=$(date +%s)
  printf '%s  up\n' "$(date +%H:%M:%S)"

  # ...and for it to leave, which is the reboot.
  while present; do sleep 0.5; done
  down=$(date +%s)
  secs=$(( down - up ))
  n=$(( n + 1 ))

  printf '%s  down after %ss\n' "$(date +%H:%M:%S)" "$secs"
  printf '            %s\n\n' "$(verdict "$secs")"

  if (( CYCLES > 0 && n >= CYCLES )); then
    printf 'stopped after %s cycle(s)\n' "$n"
    exit 0
  fi
done
