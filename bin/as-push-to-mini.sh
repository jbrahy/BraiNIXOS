#!/bin/bash
#
# Put the staged boot-object directory on the mini, and prove it arrived.
#
#   ./bin/as-push-to-mini.sh <ssh-target> [stage-dir]
#   ./bin/as-push-to-mini.sh 192.168.0.136
#   ./bin/as-push-to-mini.sh jbrahy@baby-jesus.local ~/OtherProjects/brainix-boot-stage
#
# WHEN THIS WORKS
#
# Only when the mini is booted into macOS. Its default boot object is m1n1, so
# a plain `macvdmtool reboot` lands there and nothing answers on port 22 --
# measured, 150 seconds of polling, m1n1's own CDC gadget on usbmodem5/6 the
# whole time. Getting macOS means holding the power button and picking
# Macintosh HD at the startup picker. There is no remote substitute: m1n1's
# proxy exposes no NVRAM and no boot-mode control, and neither does its PMU or
# SMC support.
#
# WHY A WHOLE-TREE SYNC AND NOT A FILE LIST
#
# Copying named files is the failure mode: whatever you forget stays at its old
# version, and the next copy's list will not include it either, so the drift is
# permanent and silent. A payload directory where the manifest and the binary
# disagree is precisely the thing the installer's hash check exists to catch,
# and it should never get that far. So: rsync --delete over the whole
# directory, which reconciles rather than accumulates.
#
# And then VERIFY, from the far side. A copy that reports success without being
# checked is not a copy. This re-hashes every file on the mini and compares
# against the local hashes, because "rsync exited 0" and "the right bytes are
# there" are different claims.
set -euo pipefail

TARGET="${1:-}"
STAGE="${2:-${HOME}/OtherProjects/brainix-boot-stage}"
REMOTE_DIR="/Users/Shared/brainix-boot"

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

[[ -n "${TARGET}" ]] || die "usage: $0 <ssh-target> [stage-dir]
  The mini must be booted into macOS. See the header of this script."
[[ -d "${STAGE}" ]] || die "no staging directory at ${STAGE} -- run bin/as-stage-payload.sh first"
[[ -f "${STAGE}/payloads.tsv" ]] || die "${STAGE} has no payloads.tsv; it is not a staged directory"

# The credential file is the operator's to create and must never be copied from
# here or committed. Say so rather than silently shipping a directory that will
# fail at step 1 of the install, ten minutes and one trip later.
if [[ -f "${STAGE}/.admin" ]]; then
  die "${STAGE}/.admin exists. Remove it: credentials belong on the mini, written
  there directly, never synced from a workstation and never in a repo."
fi

echo "==> checking the mini is reachable and running macOS"
ssh -o ConnectTimeout=8 -o BatchMode=yes "${TARGET}" 'sw_vers -productVersion' \
  || die "no answer from ${TARGET}.
  If it is sitting in m1n1 this is expected -- hold the power button and pick
  Macintosh HD at the startup picker."

echo "==> syncing ${STAGE} -> ${TARGET}:${REMOTE_DIR}"
ssh -o BatchMode=yes "${TARGET}" "mkdir -p '${REMOTE_DIR}'" || die "could not create ${REMOTE_DIR}"
# --delete so the remote directory reconciles to this one rather than
# accumulating whatever a previous attempt left behind.
rsync -av --delete "${STAGE}/" "${TARGET}:${REMOTE_DIR}/" || die "rsync failed"

echo "==> verifying by hash, from the far side"
LOCAL_SUMS="$(cd "${STAGE}" && find . -type f | sort | xargs shasum -a 256)"
REMOTE_SUMS="$(ssh -o BatchMode=yes "${TARGET}" "cd '${REMOTE_DIR}' && find . -type f | sort | xargs shasum -a 256")"

if [[ "${LOCAL_SUMS}" == "${REMOTE_SUMS}" ]]; then
  printf '\nEVERY FILE MATCHES.\n\n'
  printf '%s\n' "${REMOTE_SUMS}"
else
  printf '\nMISMATCH. local then remote:\n\n'
  printf '%s\n\n--- remote ---\n%s\n' "${LOCAL_SUMS}" "${REMOTE_SUMS}"
  die "the copy is not what was staged -- do not install from it"
fi

cat <<EOF

STAGED ON THE MINI: ${REMOTE_DIR}

Two things left, both of which need you at the machine:

  1. Write the credential file there, on the mini, not from here:

       printf '<admin-user>\\n<admin-password>\\n' > ${REMOTE_DIR}/.admin
       chmod 600 ${REMOTE_DIR}/.admin

  2. Shut down. Hold the power button until "Loading startup options".
     Options -> Macintosh HD -> Utilities -> Terminal. Then:

       sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh
       sh /Volumes/Data/Users/Shared/brainix-boot/as-install-boot-object.sh --dry-run brainix-kernel
       sh /Volumes/Data/Users/Shared/brainix-boot/as-install-boot-object.sh brainix-kernel

     Run the dry run first and read it. It checks the payload hash, the volume
     group, the target volume and the entry point without committing to
     anything, and the real run is a one-shot with a camera pointed at the
     screen.

Success is not on the display -- the framebuffer a custom boot object gets is a
dummy that is never scanned out. It is a reboot every ~13 seconds, which decodes
to "a second CPU was released". Runbook section 5a has the ladder.
EOF
