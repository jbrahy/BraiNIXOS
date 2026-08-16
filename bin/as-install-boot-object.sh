#!/bin/bash
#
# Install the BraiNIX payload as the mini's custom boot object, from recoveryOS.
#
# Run this INSTEAD of typing bputil and kmutil by hand. Every failure in
# docs/operations/BRINGUP_PLAN.md §2 was either a transcription error, a step
# taken without verifying the previous one, or a command whose output nobody
# captured. This script exists to make all three impossible:
#
#   * it derives the volume group UUID rather than trusting a remembered one,
#     which matters because the UUID changes whenever the volume group is
#     rebuilt and a stale -v fails in a way that reads as a policy fault;
#   * it stops at the first failure instead of stacking another change on top;
#   * it verifies the security mode actually changed before touching the boot
#     object, which was never once done across three installs;
#   * it tees everything to a log on the OTHER volume, so the output survives
#     the reboot and can be read from macOS afterwards. No previous attempt
#     produced a record of what the tools actually said.
#
# Usage, from the recoveryOS Terminal:
#
#   sh /Volumes/Data/Users/Shared/brainix-boot/as-install-boot-object.sh
#
# The admin password is read from a sibling file rather than passed on the
# command line, so it stays off the Flipper's SD card and out of shell history.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG="${HERE}/install-$(date +%Y%m%d-%H%M%S).log"
PAYLOAD="${HERE}/brainix-boot-stub-apple.bin"
CRED="${HERE}/.admin"
EXPECT_SHA="8829d562069985bbe41a714a84a9f02e"   # first 32 of the sha256

exec > >(tee -a "$LOG") 2>&1

say()  { printf '\n=== %s ===\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*"; printf 'log: %s\n' "$LOG"; exit 1; }

say "BraiNIX boot object install — $(date)"
printf 'log: %s\n' "$LOG"

# ---------------------------------------------------------------------------
say "1. environment"
# ---------------------------------------------------------------------------
sw_vers 2>/dev/null || true
printf 'booted volume: %s\n' "$(diskutil info / 2>/dev/null | awk -F': *' '/Volume Name/{print $2}')"
[ -r "$CRED" ] || die "missing credential file $CRED (write it from the other volume: user on line 1, password on line 2)"
ADMIN_USER="$(sed -n 1p "$CRED")"
ADMIN_PASS="$(sed -n 2p "$CRED")"
[ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ] || die "credential file must hold username on line 1 and password on line 2"
printf 'admin user: %s\n' "$ADMIN_USER"

# ---------------------------------------------------------------------------
say "2. payload"
# ---------------------------------------------------------------------------
[ -f "$PAYLOAD" ] || die "payload not found at $PAYLOAD"
SIZE="$(stat -f%z "$PAYLOAD")"
SHA="$(shasum -a 256 "$PAYLOAD" | cut -c1-32)"
printf 'path:  %s\npbytes: %s\nsha256: %s\n' "$PAYLOAD" "$SIZE" "$SHA"
[ "$SHA" = "$EXPECT_SHA" ] || die "payload hash is $SHA, expected $EXPECT_SHA -- this is the wrong build"

# ---------------------------------------------------------------------------
say "3. volume group UUID"
# ---------------------------------------------------------------------------
# Derived, never remembered. `listVolumeGroups` prints the UUID on its own line
# followed by the member volumes, so take the UUID whose block names BraiNIX.
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
# creates, and wedged the policy badly enough to cost a volume group. It buys
# nothing for booting our own kernel. See BRINGUP_PLAN.md §2 item 3.
bputil -n -c -v "$VG" -u "$ADMIN_USER" -p "$ADMIN_PASS" || die "bputil could not set Permissive Security"

# ---------------------------------------------------------------------------
say "5. verify the policy actually changed"
# ---------------------------------------------------------------------------
POLICY="$(bputil -d -v "$VG" 2>&1)"
printf '%s\n' "$POLICY" | grep -E "Security Mode:|smb0|sip2|Volume Group UUID" || true
printf '%s\n' "$POLICY" | grep -q "Permissive" || die "policy is not Permissive after bputil -- stopping before the boot object"
printf 'confirmed Permissive\n'

# ---------------------------------------------------------------------------
say "6. install the boot object (once, last)"
# ---------------------------------------------------------------------------
# `diskutil info <volume-group-uuid>` describes the group's **Data** volume,
# whose mount point is /System/Volumes/Data when booted -- not the system
# volume kmutil wants. Caught by dry-running this on the real machine; the
# old fallback never fired because that path is a valid directory, so kmutil
# would have been handed the wrong target and failed obscurely.
#
# Resolve by name, then prove the name belongs to the volume group we just
# downgraded. A mismatch here would point kmutil at the production install.
TARGET=/Volumes/BraiNIX
[ -d "$TARGET" ] || TARGET=/
printf 'target volume: %s\n' "$TARGET"
[ -d "$TARGET" ] || die "target volume $TARGET is not mounted"

TARGET_VG="$(diskutil info "$TARGET" 2>/dev/null | awk -F': *' '/Volume Group/{print $2}' | tr -d ' ')"
printf 'target volume group: %s\n' "${TARGET_VG:-<none>}"
if [ -n "$TARGET_VG" ] && [ "$TARGET_VG" != "$VG" ]; then
  die "target $TARGET belongs to volume group $TARGET_VG, not $VG -- refusing to install onto the wrong install"
fi

kmutil configure-boot \
  -c "$PAYLOAD" \
  --raw --entry-point 0 --lowest-virtual-address 0 \
  -v "$TARGET" || die "kmutil configure-boot failed -- see the log, and do NOT retry blindly"

# ---------------------------------------------------------------------------
say "7. result"
# ---------------------------------------------------------------------------
bputil -d -v "$VG" 2>&1 | grep -E "coih|Security Mode:" || true
cat <<'DONE'

INSTALL COMPLETE.

Reboot and choose BraiNIX at the startup picker. Expect horizontal stripes at
the top of the screen: white, then cyan, then green. The last stripe turns red
if that stage denied. A dark screen means it did not run, which is a result
too -- the log above says how far this script got.
DONE
printf 'log saved: %s\n' "$LOG"
