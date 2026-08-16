#!/bin/bash
#
# Prove what the Flipper's keyboard actually types, character by character.
#
#   ./bin/as-hid-selftest.sh          # ask first
#   ./bin/as-hid-selftest.sh -y       # no prompt
#
# WHY THIS IS A TEST AND NOT AN OPINION
#
# A wrong password at a login window is one bit of information: rejected. From
# that bit we concluded, wrongly and twice in one afternoon, first that Return
# was not being delivered and then that the shift modifier was being dropped.
# Neither was measured. Both were inferred from a blurry photograph of a field
# full of dots.
#
# This measures it instead. The Flipper types a string containing every class
# of character the recovery work needs -- uppercase, lowercase, digits, shifted
# punctuation, unshifted punctuation -- into a file on the mini, and the file
# is read back over ssh and compared byte for byte. A mismatch names the exact
# characters that were mistyped.
#
# REQUIREMENTS
#
#   * ssh to the mini works, i.e. it is booted into macOS
#   * the Flipper is plugged into the mini and running BraiNIX One
#   * a Terminal window on the mini has keyboard focus
#
# WHAT IT TOUCHES
#
# One file, /tmp/brainix-hid-test, on the mini. Nothing else. It does type a
# command into whatever window has focus, though, which is why it asks first.

set -u

MINI_HOST="${MINI_HOST:-jbrahy@baby-jesus.local}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REMOTE_FILE=/tmp/brainix-hid-test

# Every character class in one line, chosen to stay safe inside single quotes
# in the remote shell: no single quote, no backslash, no backtick.
EXPECT='Test.ABC xyz 123 !@#$%^&*()_+-={}[]|:;"<>,.?/~'

CONFIRM=1
FORCE=0
for arg in "$@"; do
  case "$arg" in
    -y) CONFIRM=0 ;;
    --force) FORCE=1 ;;
  esac
done

printf 'HID self-test\n'
printf '  target : %s\n' "$MINI_HOST"
printf '  writes : %s\n' "$REMOTE_FILE"
printf '  types  : %s\n' "$EXPECT"
printf '\n'

if [ "$CONFIRM" = 1 ]; then
  printf 'This types a shell command into whatever window has focus on the mini.\n'
  printf 'Make sure a Terminal is frontmost. Continue? [y/N] '
  read -r answer
  case "$answer" in y|Y) ;; *) printf 'aborted\n'; exit 1 ;; esac
fi

# --- preconditions, checked rather than assumed ---------------------------
ssh -o ConnectTimeout=8 -o BatchMode=yes "$MINI_HOST" "rm -f $REMOTE_FILE" 2>/dev/null || {
  printf 'FAILED: no ssh to %s. The mini must be booted into macOS.\n' "$MINI_HOST"
  exit 1
}

if ! "${HERE}/brainx-ble.py" send status 2>&1 | grep -q 'usb=linked'; then
  printf 'FAILED: the Flipper reports usb is not linked, so the mini has not\n'
  printf 'enumerated it as a keyboard. Nothing typed would arrive.\n'
  exit 1
fi

# Bring Terminal forward, then CONFIRM it is frontmost before typing anything.
#
# Without the confirmation this fires a shell command into whichever window
# happens to have focus on someone's working desktop. `open -a` reaches the
# console session only when the ssh user is the logged-in user, and it returns
# success either way, so its exit status proves nothing.
ssh -o ConnectTimeout=8 "$MINI_HOST" "open -a Terminal" 2>/dev/null || true
sleep 2

FRONT="$(ssh -o ConnectTimeout=8 "$MINI_HOST" \
  "osascript -e 'tell application \"System Events\" to get name of first application process whose frontmost is true'" 2>/dev/null)"

case "$FRONT" in
  Terminal|iTerm2|Alacritty|kitty|WezTerm)
    printf 'frontmost application: %s\n' "$FRONT" ;;
  "")
    if [ "$FORCE" = 1 ]; then
      printf 'NOTE: cannot read the frontmost application (osascript has no\n'
      printf 'Accessibility permission over ssh). Proceeding on --force; the\n'
      printf 'caller is asserting that a terminal has focus.\n'
    else
      printf 'FAILED: cannot read which application is frontmost.\n'
      printf 'osascript needs Accessibility permission for the ssh session, and\n'
      printf 'without it this test would type into an unknown window. Focus a\n'
      printf 'Terminal on the mini by hand and re-run with --force to skip this check.\n'
      exit 1
    fi ;;
  *)
    printf 'FAILED: frontmost application is "%s", not a terminal.\n' "$FRONT"
    printf 'Refusing to type a shell command into it.\n'
    exit 1 ;;
esac

# --- type it --------------------------------------------------------------
"${HERE}/brainx-ble.py" send "type printf '%s' '${EXPECT}' > ${REMOTE_FILE}" || {
  printf 'FAILED: the Flipper did not confirm the line was typed\n'
  exit 1
}
sleep 3

# --- read it back ---------------------------------------------------------
ACTUAL="$(ssh -o ConnectTimeout=8 "$MINI_HOST" "cat $REMOTE_FILE 2>/dev/null")"

if [ -z "$ACTUAL" ]; then
  printf '\nFAILED: %s is empty or absent.\n' "$REMOTE_FILE"
  printf 'The keystrokes went somewhere other than a shell. Check that a Terminal\n'
  printf 'had focus -- this is the one failure mode the test cannot distinguish\n'
  printf 'from a dead keyboard.\n'
  exit 1
fi

if [ "$ACTUAL" = "$EXPECT" ]; then
  printf '\nPASS: every character arrived exactly as sent.\n'
  printf '  %s\n' "$ACTUAL"
  exit 0
fi

printf '\nFAIL: the mini received something different.\n'
printf '  expected: %s\n' "$EXPECT"
printf '  actual  : %s\n' "$ACTUAL"
printf '\nper-character differences:\n'

# awk rather than a shell loop so the comparison is one pass and the output
# names positions, which is what tells you whether it is a modifier problem
# (only shifted characters wrong) or a timing problem (scattered drops).
awk -v e="$EXPECT" -v a="$ACTUAL" '
BEGIN {
  n = length(e); m = length(a)
  if (n != m) printf "  length: expected %d, got %d\n", n, m
  bad_shifted = 0; bad_plain = 0
  for (i = 1; i <= n; i++) {
    ec = substr(e, i, 1); ac = substr(a, i, 1)
    if (ec != ac) {
      printf "  pos %2d: expected %-3s got %-3s\n", i, "[" ec "]", (i <= m ? "[" ac "]" : "[]")
      if (ec ~ /[A-Z!@#$%^&*()_+{}|:"<>?~]/) bad_shifted++; else bad_plain++
    }
  }
  printf "\n  %d shifted characters wrong, %d unshifted characters wrong\n", bad_shifted, bad_plain
  if (bad_shifted > 0 && bad_plain == 0)
    print "  -> only shifted characters failed: the modifier is not reaching the host"
  else if (bad_plain > 0 && bad_shifted == 0)
    print "  -> only unshifted characters failed: not a modifier problem"
  else
    print "  -> both classes failed: suspect timing (KEY_DELAY_MS) or a dropped report"
}'
exit 1
