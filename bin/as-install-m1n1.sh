#!/bin/bash
#
# Install m1n1 as the mini's custom boot object, from recoveryOS.
#
# This is Phase 1 of docs/operations/BRINGUP_PLAN.md, the step that was skipped:
# get a console before debugging our own code. m1n1 gives a working serial
# console, a Python proxy that can read and write memory, and chainloading --
# which replaces a ten-minute recovery trip with a one-second command. Nothing
# of ours runs during this test, so a failure here is unambiguously the rig.
#
# It REPLACES the BraiNIX boot object on the BraiNIX volume group. Macintosh HD
# is a different volume group and is not touched.
#
# Usage, from the recoveryOS Terminal:
#
#   sh /Volumes/Data/Users/Shared/brainix-boot/as-install-m1n1.sh
#
# WHAT IT WILL ASK YOU
#
#   1. "Are you sure you want to do this? (enter y or n)"  ->  y
#   2. "Username:"                                          ->  jbrahy
#   3. "Password:"                                          ->  (no echo)
#
# kmutil configure-boot has no -u/-p flags; it prompts, and an empty answer
# fails as `Code=71 not a valid admin user`, which reads like a policy fault
# rather than a missed prompt. That cost two runs. Answer all three.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${HERE}/m1n1-install-$(date +%Y%m%d-%H%M%S).log"
PAYLOAD="${HERE}/m1n1.bin"
CRED="${HERE}/.admin"

# m1n1 v1.6.1, m1n1-stage2-v1.6.1.zip. Verified on the workstation and again on
# the mini under macOS, where real hash tools exist:
#   05137464cdacb23d8aed9be1d0ddd4fda757fb57d2b1a769ff3d88409afaafa0
# recoveryOS has no shasum, no openssl, and no Perl Digest::SHA -- all three
# were tried. So the check here is the size, and the hash above is the record
# of what that size is supposed to be.
EXPECT_SIZE=1097728

# m1n1's documented entry point for the raw image, from its own README:
#   kmutil configure-boot -c m1n1.bin --raw --entry-point 2048 \
#       --lowest-virtual-address 0 -v <OS volume>
# and identically in asahi-installer's step2.sh. This is the value the first
# m1n1 attempt got wrong -- it was installed at 0, so m1n1 never ran, was
# judged useless, and was abandoned. Our own stub genuinely is entry 0; the two
# are different and must not be copied from each other.
ENTRY_POINT=2048

FIFO="${LOG}.fifo"
rm -f "$FIFO"; mkfifo "$FIFO" 2>/dev/null && {
  tee -a "$LOG" < "$FIFO" &
  TEE_PID=$!
  exec > "$FIFO" 2>&1
} || {
  echo "WARNING: could not create $FIFO -- output is on screen only"
}

say()  { printf '\n=== %s ===\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*"; printf 'log: %s\n' "$LOG"; exit 1; }

say "m1n1 install — $(date)"
printf 'log: %s\n' "$LOG"

# ---------------------------------------------------------------------------
say "1. environment"
# ---------------------------------------------------------------------------
sw_vers 2>/dev/null || true
printf 'booted volume: %s\n' "$(diskutil info / 2>/dev/null | awk -F': *' '/Volume Name/{print $2}')"
[ -r "$CRED" ] || die "missing credential file $CRED (username on line 1, password on line 2)"
ADMIN_USER="$(sed -n 1p "$CRED")"
ADMIN_PASS="$(sed -n 2p "$CRED")"
[ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ] || die "credential file must hold username on line 1 and password on line 2"
printf 'admin user: %s\n' "$ADMIN_USER"

# ---------------------------------------------------------------------------
say "2. payload"
# ---------------------------------------------------------------------------
[ -f "$PAYLOAD" ] || die "payload not found at $PAYLOAD"
SIZE="$(stat -f%z "$PAYLOAD")"
printf 'path:  %s\nbytes: %s (expected %s)\n' "$PAYLOAD" "$SIZE" "$EXPECT_SIZE"
[ "$SIZE" = "$EXPECT_SIZE" ] || die "payload is $SIZE bytes, expected $EXPECT_SIZE -- wrong file"

# ---------------------------------------------------------------------------
say "3. volume group UUID"
# ---------------------------------------------------------------------------
# Derived, never remembered: the UUID changes whenever a volume group is
# rebuilt, and a stale -v fails in a way that reads as a policy fault.
VG="$(diskutil apfs listVolumeGroups 2>/dev/null | awk '
  /Volume Group [0-9A-F-]{36}/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{36}$/) uuid=$i }
  /BraiNIX/ && uuid { print uuid; exit }
')"
if [ -z "$VG" ]; then
  printf 'automatic derivation failed; full listing follows\n'
  diskutil apfs listVolumeGroups 2>/dev/null
  die "could not identify the BraiNIX volume group UUID -- pass it as \$1 and re-run"
fi
[ $# -ge 1 ] && VG="$1" && printf 'UUID overridden on the command line\n'
printf 'BraiNIX volume group: %s\n' "$VG"

# ---------------------------------------------------------------------------
say "4. security policy -> Permissive (NO -k)"
# ---------------------------------------------------------------------------
# -k enables third-party kext trust, needs a paired AuxKC this flow never
# creates, and wedged the policy badly enough to cost a volume group.
bputil -n -c -v "$VG" -u "$ADMIN_USER" -p "$ADMIN_PASS" || die "bputil could not set Permissive Security"

# ---------------------------------------------------------------------------
say "5. verify the policy actually changed"
# ---------------------------------------------------------------------------
POLICY="$(bputil -d -v "$VG" 2>&1)"
printf '%s\n' "$POLICY" | grep -E "Security Mode:|smb0|sip2|Volume Group UUID" || true
printf '%s\n' "$POLICY" | grep -q "Permissive" || die "policy is not Permissive after bputil -- stopping before the boot object"
printf 'confirmed Permissive\n'

# ---------------------------------------------------------------------------
say "6. install m1n1 as the boot object"
# ---------------------------------------------------------------------------
# `diskutil info <volume-group-uuid>` describes the group's Data volume, whose
# mount point is /System/Volumes/Data -- not the system volume kmutil wants.
# Resolve by name, then prove the name belongs to the group we downgraded.
TARGET=/Volumes/BraiNIX
[ -d "$TARGET" ] || die "target volume $TARGET is not mounted"
printf 'target volume: %s\n' "$TARGET"

TARGET_VG="$(diskutil info "$TARGET" 2>/dev/null | awk -F': *' '/Volume Group/{print $2}' | tr -d ' ')"
printf 'target volume group: %s\n' "${TARGET_VG:-<none>}"
if [ -n "$TARGET_VG" ] && [ "$TARGET_VG" != "$VG" ]; then
  die "target $TARGET belongs to volume group $TARGET_VG, not $VG -- refusing to install onto the wrong install"
fi

printf '\nkmutil will now ask for y, then Username (%s), then Password.\n' "$ADMIN_USER"
printf 'An empty answer fails as "Code=71 not a valid admin user".\n\n'

kmutil configure-boot \
  -c "$PAYLOAD" \
  --raw --entry-point "$ENTRY_POINT" --lowest-virtual-address 0 \
  -v "$TARGET" || die "kmutil configure-boot failed -- see the log, and do NOT retry blindly"

# ---------------------------------------------------------------------------
say "7. result"
# ---------------------------------------------------------------------------
bputil -d -v "$VG" 2>&1 | grep -E "coih|Security Mode:" || true
cat <<'DONE'

INSTALL COMPLETE.

Reboot and choose BraiNIX at the startup picker. It now boots m1n1, not our
stub. Expect m1n1's console banner over the USB-C debug console after
`macvdmtool serial`, or over m1n1's own USB gadget. m1n1 decides between the
DockChannel and the legacy UART itself, which is why it answers OQ-5 for us
rather than us answering it for m1n1.

If nothing prints on either channel, the fault is the rig, and no code of ours
is involved in that conclusion.
DONE
printf 'log saved: %s\n' "$LOG"
exec >/dev/tty 2>&1 || true
[ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null
rm -f "${LOG}.fifo"
