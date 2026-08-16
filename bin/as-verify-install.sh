#!/bin/bash
#
# Say which payload the mini will actually boot, and prove it did not change by
# accident. Read-only unless --record is passed.
#
#   sh as-verify-install.sh                 # report, and compare to the record
#   sh as-verify-install.sh --record m1n1   # note that <name> is now installed
#
# WHY A LEDGER RATHER THAN A CHECK
#
# `coih` is the Image4 hash of the *wrapped* boot object, not of the file we
# handed kmutil, so it cannot be predicted from the payload. It can only be
# observed after the fact. That makes it useless as a precondition and perfect
# as a fingerprint: record it at install time, and every later run can say
# whether the machine still holds the object you think it holds.
#
# This matters because three boot objects were installed across two days with
# no record of which was resident, and a dark screen was attributed to the most
# recently changed thing each time (BRINGUP_PLAN.md items 4 and 5).

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LEDGER="${HERE}/installed-boot-objects.tsv"

RECORD=""
if [ "${1:-}" = "--record" ]; then
  RECORD="${2:-}"
  [ -n "$RECORD" ] || { printf 'usage: %s --record <payload-name>\n' "$0"; exit 2; }
fi

VG="$(diskutil apfs listVolumeGroups 2>/dev/null | awk '
  /Volume Group [0-9A-F-]{36}/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{36}$/) uuid=$i }
  /BraiNIX/ && uuid { print uuid; exit }
')"
[ -n "$VG" ] || { printf 'FAILED: no BraiNIX volume group found\n'; exit 1; }

# bputil answers `The tool requires running as root` to a normal user, and that
# string matches none of the greps below -- so without this check the script
# would report "coih: unknown" as though it had looked. Refuse instead.
if [ "$(id -u)" -eq 0 ]; then
  BP="bputil"
elif sudo -n true 2>/dev/null; then
  BP="sudo -n bputil"
else
  printf 'FAILED: bputil requires root; re-run as: sudo sh %s\n' "$0"
  exit 2
fi

POLICY="$($BP -d -v "$VG" 2>&1)"
case "$POLICY" in
  *"requires running as root"*|"")
    printf 'FAILED: bputil produced no readable output; nothing here is a finding\n'
    exit 2 ;;
esac
# sed, not `awk -F'(coih): '`. An awk field separator is an ERE, so those
# parentheses group rather than match, and the separator silently became
# `coih: ` -- which never occurs in bputil's output. The result was an empty
# field read as "absent", i.e. this script confidently reporting no boot object
# on a machine that had one. Same class of error as everything else in
# BRINGUP_PLAN: an unchecked parse presented as a finding.
COIH="$(printf '%s' "$POLICY" | sed -n 's/.*(coih):[[:space:]]*//p' | tr -d ' \r' | head -1)"
MODE="$(printf '%s' "$POLICY" | sed -n 's/.*Security Mode:[[:space:]]*//p' | awk '{print $1}' | head -1)"

[ -n "$COIH" ] || { printf 'FAILED: could not parse coih out of bputil output\n'; exit 2; }

printf 'volume group : %s\n' "$VG"
printf 'security mode: %s\n' "${MODE:-unknown}"
printf 'coih         : %s\n' "${COIH:-unknown}"

if [ "$COIH" = "absent" ] || [ -z "$COIH" ]; then
  printf '\nNo custom boot object is installed. This machine boots macOS only.\n'
  [ -n "$RECORD" ] && { printf 'refusing to record "%s" against an absent boot object\n' "$RECORD"; exit 1; }
  exit 0
fi

if [ -n "$RECORD" ]; then
  printf '%s\t%s\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RECORD" "$COIH" >> "$LEDGER"
  printf '\nrecorded: %s is now the resident boot object\n' "$RECORD"
  printf 'ledger: %s\n' "$LEDGER"
  exit 0
fi

if [ ! -r "$LEDGER" ]; then
  printf '\nA boot object is installed but nothing has ever been recorded, so its\n'
  printf 'identity is unknown. Run with --record <name> right after an install.\n'
  exit 1
fi

KNOWN="$(awk -F'\t' -v c="$COIH" '$3==c {print $2; exit}' "$LEDGER")"
if [ -n "$KNOWN" ]; then
  printf '\nResident boot object: %s\n' "$KNOWN"
  LAST="$(tail -1 "$LEDGER" | cut -f2)"
  if [ "$KNOWN" != "$LAST" ]; then
    printf 'NOTE: the most recent install recorded was "%s". The machine is\n' "$LAST"
    printf 'holding an earlier one, so that install did not take effect.\n'
    exit 1
  fi
  exit 0
fi

printf '\nUNKNOWN boot object: this coih is not in the ledger.\n'
printf 'Something installed a payload without recording it. Do not assume which.\n'
exit 1
