#!/bin/sh
#
# The mini half of the recoveryOS console. See as-recovery-console.py for why
# this exists; the short version is that recoveryOS runs no sshd, so without
# this every result has to be read off a photograph of the monitor, and a
# blank photograph means both "it worked and printed nothing" and "nothing
# ran". That ambiguity is what has made this process un-automatable.
#
# Poll for a command, run it, post back stdout+stderr and the exit status.
#
# Started with ONE typed line, which is the only thing a human or the Flipper
# has to get right:
#
#   sh /Volumes/Data/Users/Shared/brainix-boot/as-recovery-agent.sh http://192.168.2.1:8765/t/<token> &
#
# `as-recovery-console.py bootstrap` prints that line with the live token in it.
#
# POSIX sh only, and curl is the one non-builtin it needs. recoveryOS has no
# shasum, no openssl, no networksetup and no Perl Digest::SHA -- each of those
# was discovered by a script dying mid-run -- so this depends on as little as
# it can and says so when the little it needs is missing.

set -u

BASE="${1:-}"
if [ -z "$BASE" ]; then
  echo "usage: $0 http://<host>:<port>/t/<token>" >&2
  exit 2
fi

command -v curl >/dev/null 2>&1 || { echo "no curl in this environment" >&2; exit 3; }

LOG="${TMPDIR:-/tmp}/brainx-agent.log"
: > "$LOG"

log() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$*" >> "$LOG"; }

log "agent starting against $BASE"

# Announce ourselves so the console shows a live agent rather than silence.
# A failure here is not fatal: the poll loop reports the real story.
curl -s -m 10 -o /dev/null "$BASE/cmd" 2>/dev/null || log "first poll failed"

IDLE=0
while :; do
  # -w appends the HTTP status on its own line, so one request yields both the
  # body and the code without a second round trip.
  RESP="$(curl -s -m 35 -w '\n%{http_code}' "$BASE/cmd" 2>/dev/null)"
  CODE="$(printf '%s' "$RESP" | tail -1)"
  BODY="$(printf '%s' "$RESP" | sed '$d')"

  case "$CODE" in
    200) : ;;
    204)
      # Nothing queued. Back off gently so an idle console is not a busy loop,
      # but stay responsive while someone is actually driving.
      IDLE=$((IDLE + 1))
      [ "$IDLE" -gt 20 ] && sleep 3 || sleep 1
      continue
      ;;
    *)
      log "poll got status '${CODE:-none}'; retrying"
      sleep 3
      continue
      ;;
  esac

  IDLE=0
  ID="$(printf '%s' "$BODY" | head -1)"
  CMD="$(printf '%s' "$BODY" | sed '1d')"
  case "$ID" in
    ''|*[!0-9]*) log "bad job id '$ID'"; sleep 2; continue ;;
  esac

  log "job $ID: $CMD"

  # stdout and stderr together, because on this machine the interesting half is
  # almost always stderr: bputil, kmutil and diskutil all report failures there
  # and a stdout-only capture reads as success.
  OUT="$(sh -c "$CMD" 2>&1)"
  RC=$?

  # --data-binary @- keeps the payload exactly as produced. No shell expansion,
  # no argument-length limit, and newlines survive.
  printf '%s' "$OUT" | curl -s -m 120 -o /dev/null \
      -X POST --data-binary @- "$BASE/out?id=$ID&rc=$RC" 2>/dev/null \
    || log "job $ID: failed to post result (rc=$RC)"

  log "job $ID: exit $RC"
done
