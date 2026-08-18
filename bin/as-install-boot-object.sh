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
CRED="${HERE}/.admin"
MANIFEST="${HERE}/payloads.tsv"

# WHICH payload, by name, from the manifest -- not by a filename and a hash
# pasted into this script.
#
#   sh as-install-boot-object.sh                  # the kernel
#   sh as-install-boot-object.sh brainix-stub     # the first-light stub
#   sh as-install-boot-object.sh brainix-kernel <volume-group-uuid>
#
# It used to carry `brainix-boot-stub-apple.bin` and the first 32 hex of its
# hash as constants. That was correct for exactly one payload, and the moment
# there was a second one the choice would have been made by editing this file
# under recoveryOS with a camera pointed at the screen. payloads.tsv already
# exists to be the single source of truth for what gets installed and at what
# entry point; this reads it.
#
# --dry-run does everything EXCEPT the two irreversible steps, and prints the
# exact commands it would have run. The install is a one-shot with a camera
# pointed at the screen and a trip to the machine to retry, so being able to
# check the payload, the volume group, the target volume and the entry point
# without committing to any of it is worth the twenty lines it costs. Every
# failure in BRINGUP_PLAN.md section 2 would have been caught by this.
DRY_RUN=0
case "${1:-}" in
  --dry-run) DRY_RUN=1; shift ;;
esac
PAYLOAD_NAME="${1:-brainix-kernel}"
[ $# -ge 1 ] && shift
case "${1:-}" in
  --dry-run) DRY_RUN=1; shift ;;
esac

# Log to a file AND to the screen, without process substitution.
#
# This was `exec > >(tee -a "$LOG") 2>&1`, which is a bashism: run under `sh`
# it fails with "syntax error near unexpected token '>'" -- so the one feature
# added to give us a record is what stopped the script from running at all.
# A FIFO works in any POSIX shell, and the screen still shows everything,
# which matters because a camera is how this is being read.
FIFO="${LOG}.fifo"
rm -f "$FIFO"; mkfifo "$FIFO" 2>/dev/null && {
  tee -a "$LOG" < "$FIFO" &
  TEE_PID=$!
  exec > "$FIFO" 2>&1
} || {
  # No FIFO available: keep the screen output, lose the log, say so.
  echo "WARNING: could not create $FIFO -- output is on screen only"
}

say()  { printf '\n=== %s ===\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*"; printf 'log: %s\n' "$LOG"; exit 1; }

say "BraiNIX boot object install — $(date)"
printf 'log: %s\n' "$LOG"

# ---------------------------------------------------------------------------
say "1. environment"
# ---------------------------------------------------------------------------
sw_vers 2>/dev/null || true
printf 'booted volume: %s\n' "$(diskutil info / 2>/dev/null | awk -F': *' '/Volume Name/{print $2}')"
# Optional, not required. It is needed only to DOWNGRADE the policy, and a
# group that is already Permissive needs no downgrade -- see step 4. Demanding
# it up front meant putting an admin password on the machine to perform a no-op.
if [ -r "$CRED" ]; then
  ADMIN_USER="$(sed -n 1p "$CRED")"
  ADMIN_PASS="$(sed -n 2p "$CRED")"
  [ -n "$ADMIN_USER" ] && [ -n "$ADMIN_PASS" ] \
    || die "credential file must hold username on line 1 and password on line 2"
  printf 'admin user: %s\n' "$ADMIN_USER"
else
  ADMIN_USER=""
  ADMIN_PASS=""
  printf 'no credential file; fine unless the policy needs downgrading\n'
fi

# ---------------------------------------------------------------------------
say "2. payload"
# ---------------------------------------------------------------------------
[ -r "$MANIFEST" ] || die "no payloads.tsv beside this script at $MANIFEST"

# Tab-separated: name file bytes sha256 entry_point lowest_virtual_address ...
ROW="$(awk -F'\t' -v want="$PAYLOAD_NAME" '$1 == want { print; exit }' "$MANIFEST")"
[ -n "$ROW" ] || die "payloads.tsv has no payload named '$PAYLOAD_NAME'
  known: $(awk -F'\t' 'NR>1 && $1 !~ /^#/ && $1 != "name" && $1 != "" { printf "%s ", $1 }' "$MANIFEST")"

PAYLOAD_FILE="$(printf '%s' "$ROW" | cut -f2)"
EXPECT_SIZE="$(printf '%s' "$ROW" | cut -f3)"
EXPECT_SHA="$(printf '%s' "$ROW" | cut -f4)"
ENTRY_POINT="$(printf '%s' "$ROW" | cut -f5)"
LOWEST_VA="$(printf '%s' "$ROW" | cut -f6)"
PAYLOAD="${HERE}/${PAYLOAD_FILE}"

printf 'name:   %s\npath:   %s\nentry:  %s\nlow VA: %s\n' \
  "$PAYLOAD_NAME" "$PAYLOAD" "$ENTRY_POINT" "$LOWEST_VA"
[ -f "$PAYLOAD" ] || die "payload not found at $PAYLOAD"

SIZE="$(stat -f%z "$PAYLOAD")"
printf 'bytes:  %s (manifest says %s)\n' "$SIZE" "$EXPECT_SIZE"
[ "$SIZE" = "$EXPECT_SIZE" ] || die "payload is $SIZE bytes, manifest says $EXPECT_SIZE -- this is the wrong build"

# recoveryOS has no shasum, no openssl and no Perl Digest::SHA -- all three were
# tried on the real machine. So the hash is checked when it can be, and the size
# above is what stands in when it cannot. Saying which one actually ran matters:
# "verified" meaning two different things depending on the environment is how a
# wrong build gets installed with a clean-looking log.
if command -v shasum >/dev/null 2>&1; then
  SHA="$(shasum -a 256 "$PAYLOAD" | cut -d" " -f1)"
  printf 'sha256: %s\n' "$SHA"
  [ "$SHA" = "$EXPECT_SHA" ] || die "payload hash is $SHA, manifest says $EXPECT_SHA -- this is the wrong build"
  printf 'hash VERIFIED against the manifest\n'
else
  printf 'sha256: NOT CHECKED -- no shasum here. Size above is the only check.\n'
fi

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
# ---------------------------------------------------------------------------
# bputil and kmutil both refuse to run as a normal user, and the refusal is a
# line of text rather than a distinctive exit code. as-preflight.sh already
# carries the scar: an unread "The tool requires running as root" made its grep
# match nothing, and it announced "not Permissive" -- a finding manufactured
# from an error. This script did exactly the same thing on its first dry run
# over ssh. So escalate the same way preflight does, once, here.
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
elif sudo -n true 2>/dev/null; then
  SUDO="sudo -n"
else
  SUDO=""
  printf 'WARNING: not root and no passwordless sudo. bputil and kmutil will refuse.\n'
fi

say "4. security policy -> Permissive (NO -k)"
# ---------------------------------------------------------------------------
# -k enables third-party kext trust, needs a paired AuxKC this flow never
# creates, and wedged the policy badly enough to cost a volume group. It buys
# nothing for booting our own kernel. See BRINGUP_PLAN.md §2 item 3.
# Skip it entirely if the policy is ALREADY Permissive.
#
# `bputil -n -c` is the only step that needs an admin password, and on a volume
# group that has already been downgraded it is a no-op that asks for one anyway.
# Not asking is better than asking: it means no credential file has to exist on
# the machine, and a password that is never written down cannot leak from it.
#
# The verification below is unchanged and still authoritative -- this decides
# whether to *act*, and that decides whether we were right to.
CURRENT="$($SUDO bputil -d -v "$VG" 2>&1 || true)"
if printf '%s\n' "$CURRENT" | grep -q "Permissive"; then
  printf 'already Permissive; skipping bputil and the credential it would need\n'
elif [ "$DRY_RUN" = "1" ]; then
  printf 'DRY RUN -- would run:\n  bputil -n -c -v %s -u %s -p <password>\n' "$VG" "${ADMIN_USER:-<from .admin>}"
else
  [ -n "${ADMIN_USER:-}" ] && [ -n "${ADMIN_PASS:-}" ] \
    || die "policy is not Permissive and there is no credential file at $CRED
  Write it on THIS machine: admin username on line 1, password on line 2."
  $SUDO bputil -n -c -v "$VG" -u "$ADMIN_USER" -p "$ADMIN_PASS" || die "bputil could not set Permissive Security"
fi

# ---------------------------------------------------------------------------
say "5. verify the policy actually changed"
# ---------------------------------------------------------------------------
POLICY="$($SUDO bputil -d -v "$VG" 2>&1)"
printf '%s\n' "$POLICY" | grep -E "Security Mode:|smb0|sip2|Volume Group UUID" || true
if printf '%s\n' "$POLICY" | grep -q "Permissive"; then
  printf 'confirmed Permissive\n'
elif [ "$DRY_RUN" = "1" ]; then
  # Expected on a dry run against a group that has not been downgraded yet:
  # nothing was changed, so nothing should have changed. Said out loud rather
  # than passed over, because "the dry run was clean" must not come to mean
  # "the policy is already right".
  printf 'NOT Permissive, and this is a dry run so nothing set it. The real\n'
  printf 'run would set it at step 4 and stop here if it did not take.\n'
else
  die "policy is not Permissive after bputil -- stopping before the boot object"
fi

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

# Entry point and lowest virtual address come from the manifest, per payload.
# Getting this wrong is the most expensive mistake this project has made: m1n1
# was installed at 0 when its entry is 2048, so it never ran, was judged
# useless, and was abandoned -- which removed the only debugging instrument
# available. Ours is 0. The two must never be copied from one another, and
# neither is typed here.
if [ "$DRY_RUN" = "1" ]; then
  printf 'DRY RUN -- would run:\n  kmutil configure-boot -c %s --raw --entry-point %s --lowest-virtual-address %s -v %s\n' \
    "$PAYLOAD" "$ENTRY_POINT" "$LOWEST_VA" "$TARGET"
  printf '\nDRY RUN COMPLETE. Nothing was changed. Re-run without --dry-run to install.\n'
  printf 'log saved: %s\n' "$LOG"
  exec >/dev/tty 2>&1 || true
  [ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null
  rm -f "${LOG}.fifo"
  exit 0
fi
$SUDO kmutil configure-boot \
  -c "$PAYLOAD" \
  --raw --entry-point "$ENTRY_POINT" --lowest-virtual-address "$LOWEST_VA" \
  -v "$TARGET" || die "kmutil configure-boot failed -- see the log, and do NOT retry blindly"

# ---------------------------------------------------------------------------
say "7. result"
# ---------------------------------------------------------------------------
$SUDO bputil -d -v "$VG" 2>&1 | grep -E "coih|Security Mode:" || true
printf '\nINSTALL COMPLETE: %s is now the boot object.\n\n' "$PAYLOAD_NAME"
case "$PAYLOAD_NAME" in
  brainix-kernel)
    cat <<'DONE'
Reboot and choose BraiNIX at the startup picker.

WHAT SUCCESS LOOKS LIKE, AND IT IS NOT ON THE SCREEN. The framebuffer handed
to a custom boot object is a dummy that is never scanned out, and the SBU
serial path on this rig delivers zero bytes -- measured, with m1n1's own
output too. So do not watch the display.

Watch the USB device instead. _start climbs a ladder and re-arms the watchdog
four seconds longer at each rung, so THE INTERVAL BETWEEN REBOOTS IS THE
REPORT. From the workstation:

    while :; do ls /dev/cu.usbmodem* >/dev/null 2>&1 && echo up || echo down; sleep 1; done

Time from power-on to the device leaving the bus:

    ~5s    device tree parsed, /arm-io/wdt found and armed
    ~9s    cpu topology read
    ~13s   /arm-io/pmgr translated
    ~17s   a second cpu released, reported its own MPIDR
    ~21s   its own page tables built
    ~26s   MMU AND CACHES ON -- the whole ladder, which is the good outcome
    never  it did not reach the first rung

A machine that sits there doing nothing did not get that far, and it cannot say
which part failed -- that is exactly why the reboot is the signal.

To stop the loop, hold the power button for One True Recovery and install a
different boot object.
DONE
    ;;
  *)
    cat <<'DONE'
Reboot and choose BraiNIX at the startup picker. Expect horizontal stripes at
the top of the screen: white, then cyan, then green. The last stripe turns red
if that stage denied. A dark screen means it did not run, which is a result
too -- the log above says how far this script got.
DONE
    ;;
esac
printf 'log saved: %s\n' "$LOG"
# Let the tee drain before the shell exits, or the tail of the log is lost.
exec >/dev/tty 2>&1 || true
[ -n "${TEE_PID:-}" ] && wait "$TEE_PID" 2>/dev/null
rm -f "${LOG}.fifo"
