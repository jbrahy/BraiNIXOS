#!/bin/bash
#
# Install a boot object on the mini from the laptop, unattended, with every
# precondition checked before anything is at stake.
#
# This is the whole 2026-08-20/21 session compressed into a script. That
# session took roughly fourteen hours and installed nothing. Almost none of it
# was hard; it was expensive because each answer arrived as a photograph that
# had to be read by eye, and because the one precondition that actually blocks
# the install was never checked.
#
#   ./bin/as-autoinstall.sh --dry-run brainix-kernel
#   ./bin/as-autoinstall.sh brainix-kernel
#
# WHAT THIS STILL CANNOT DO, and never will
# -----------------------------------------
# Two steps require a person, both by Apple's design, not by omission:
#
#   1. Entering One True Recovery. Holding the power button IS the presence
#      check; there is no nvram key and bless has no --recovery on Apple
#      Silicon. Checked on macOS 15.3.1.
#   2. Reinstalling macOS onto the experiment volume, if the group turns out
#      to have no recoveryOS of its own. recoveryOS ships no startosinstall,
#      so it is the GUI wizard, and its disk picker is the one screen where a
#      misread costs the production OS. A person confirms that selection.
#
# Everything between those two is here.
#
# WHAT IT NEEDS ALREADY DONE
# --------------------------
#   * the mini in 1TR with a Terminal open
#   * Ethernet plugged in, Internet Sharing on the laptop
#   * the payload staged (bin/as-stage-payload.sh, run under macOS)
#   * the agent bootstrapped: as-recovery-console.py bootstrap, typed once
#
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONSOLE="${REPO}/bin/as-recovery-console.py"
STAGE="/Volumes/Data/Users/Shared/brainix-boot"

DRY_RUN=0
case "${1:-}" in --dry-run) DRY_RUN=1; shift ;; esac
PAYLOAD="${1:-brainix-kernel}"

# The admin credential is read from the environment, never from a file in the
# repo and never from the command line, where it would land in shell history
# and in every ps listing on the machine.
ADMIN_USER="${BRAINX_ADMIN_USER:-}"
ADMIN_PASS="${BRAINX_ADMIN_PASS:-}"

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; }
die()  { printf '\nSTOPPED: %s\n' "$*"; exit 1; }

# Every command goes through the console, so every result is text with an exit
# status rather than a photograph. `run` prints nothing; callers inspect $OUT.
# The default console timeout is 15 minutes, which is right for kmutil and very
# wrong for a liveness probe: a missing agent would look like a hang for the
# whole quarter hour, which is precisely the "silence means nothing" failure
# this console exists to abolish. So the timeout is per call.
OUT=""
run() {
  local timeout="${2:-900}"
  # The command goes over stdin, never argv: argv is world-readable through ps,
  # and a job may carry the admin-password placeholder.
  OUT="$(printf '%s' "$1" | "$CONSOLE" run --stdin --timeout "$timeout" 2>&1)"
  return $?
}

# ---------------------------------------------------------------------------
say "0. console"
# ---------------------------------------------------------------------------
if ! run 'echo AGENT-ALIVE; sw_vers -productVersion' 15; then
  die "no answer from the recovery agent.
  Start the listener:   $CONSOLE serve
  Then type this line into the mini's Terminal, once:
      $("$CONSOLE" bootstrap 2>/dev/null || echo '<run: as-recovery-console.py bootstrap>')"
fi
printf '%s\n' "$OUT" | sed 's/^/  /'
grep -q AGENT-ALIVE <<<"$OUT" || die "agent replied but not as expected"
ok "two-way console up"

# ---------------------------------------------------------------------------
say "1. environment is recoveryOS"
# ---------------------------------------------------------------------------
# kmutil configure-boot only works in recoveryOS, and bputil downgrades only
# work in 1TR. Running this against a booted macOS silently does nothing useful.
run 'diskutil info / | awk -F": *" "/Volume Name/{print \$2}"'
printf '  booted volume: %s\n' "$OUT"
case "$OUT" in
  *"macOS Base System"*) ok "in recoveryOS" ;;
  *) die "not in recoveryOS (booted from '$OUT'). Hold the power button for 1TR." ;;
esac

# ---------------------------------------------------------------------------
say "2. network"
# ---------------------------------------------------------------------------
# Only matters if a policy change needs Apple, but check it up front: finding
# out at step 5 costs the whole run.
run "sh ${STAGE}/as-recovery-net.sh en0" 120
printf '%s\n' "$OUT" | sed 's/^/  /'
if grep -q "NET OK" <<<"$OUT"; then
  ok "mini reaches the Internet"
  NET=1
else
  bad "no Internet from the mini"
  printf '  Not fatal yet: only a Full Security change needs it.\n'
  NET=0
fi

# ---------------------------------------------------------------------------
say "3. preflight"
# ---------------------------------------------------------------------------
run "sh ${STAGE}/as-preflight.sh" 180
printf '%s\n' "$OUT" | sed 's/^/  /'
grep -q "READY" <<<"$OUT" || die "preflight did not report READY; fix the above first"

# ---------------------------------------------------------------------------
say "4. the precondition that actually blocks installs"
# ---------------------------------------------------------------------------
# Read the target group's pairing status directly rather than trusting a
# summary. A Not Paired group cannot have its policy downgraded, which means a
# custom boot object can never be installed on it -- and no flag, credential or
# retry changes that. Nine runs on 2026-08-21 failed here, and the error text
# said so every time.
run "bputil -e 2>&1 | grep -E 'Volume Group UUID|OS Pairing Status|coih|Security Mode:'"
printf '%s\n' "$OUT" | sed 's/^/  /'
if grep -q "Not Paired" <<<"$OUT"; then
  bad "a volume group on this machine is Not Paired"
  cat <<'WHY'

  If that is the target group, stop: it has no recoveryOS of its own, so its
  LocalPolicy can never be downgraded and no boot object can be installed on
  it. Raising to Full Security still works (Apple signs that over the network);
  lowering to Permissive does not (signed locally, needs a paired OS).

  The fix is not in this script. Reinstall macOS onto that volume so the
  installer creates the paired recoveryOS, confirming the disk picker by eye.
  See docs/operations/FIRST_LIGHT_RUNBOOK.md 5.
WHY
  die "target group must be Paired before an install can succeed"
fi
ok "no Not Paired group in the way"

# ---------------------------------------------------------------------------
say "5. install"
# ---------------------------------------------------------------------------
if [ "$DRY_RUN" = "1" ]; then
  run "sh ${STAGE}/as-install-boot-object.sh --dry-run ${PAYLOAD}"
  printf '%s\n' "$OUT" | sed 's/^/  /'
  grep -q "DRY RUN COMPLETE" <<<"$OUT" \
    && ok "dry run clean; re-run without --dry-run to install" \
    || die "dry run did not complete"
  exit 0
fi

[ -n "$ADMIN_USER" ] \
  || die "set BRAINX_ADMIN_USER; kmutil prompts for it and configure-boot has no -u"
[ -n "$ADMIN_PASS" ] \
  || die "set BRAINX_ADMIN_PASS in the environment of the console \`serve\`
  process, which substitutes it in flight. Exporting it here too is harmless
  but not sufficient, and not required."

# kmutil asks three questions in order: y, Username, Password. Answering them
# by hand through a one-way keyboard is what lost two runs -- the prompt is
# invisible, because the install script's FIFO block-buffers kmutil's stdout,
# so the next thing typed at what looks like a hung shell becomes the answer.
#
# But a pipe is not sufficient either. FIRST_LIGHT_RUNBOOK.md 5 records that
# kmutil reads the PASSWORD from /dev/tty directly: piping y and the username
# works, and then it stops and waits for a human anyway. A pipe alone would
# hang here, silently, for the full timeout.
#
# So give it a real terminal. `script` allocates a pty, which satisfies a
# /dev/tty read from a non-interactive session. Whether recoveryOS ships it is
# checked rather than assumed, because assuming is how this project loses
# evenings -- and if it is missing the run stops with the manual procedure
# instead of hanging.
say "5a. terminal for kmutil's password prompt"
run 'command -v script >/dev/null 2>&1 && echo HAVE-SCRIPT || echo NO-SCRIPT' 30
if grep -q HAVE-SCRIPT <<<"$OUT"; then
  ok "script(1) present: kmutil gets a pty and all three answers are fed"
  # Two details, both established by experiment on 2026-08-22 rather than
  # assumed, because the obvious form of this command silently does the wrong
  # thing:
  #
  #   * The holder `sleep` is not padding. Without it the pipe reaches EOF
  #     before kmutil issues its reads and every answer comes back empty --
  #     the ^D races the prompt. Measured: bare pipe gives got:[], held pipe
  #     gives the right value.
  #   * The pipeline finishes only when the holder does, so the sleep sets a
  #     floor on the runtime. 120s is under kmutil's own duration, so it is
  #     absorbed completely and costs nothing.
  #
  # A fifo instead of a pipe does NOT work: macOS script(1) calls tcgetattr on
  # its stdin and refuses one.
  #
  # tr -d strips the CRs a pty adds, so the output greps like ordinary text.
  # The password is NOT interpolated here. The spooled job carries a
  # placeholder, and the console substitutes the real value from its own
  # environment at the moment it hands the job to the agent. So the credential
  # never lands in the spool, never appears in `ps`, and is not left behind in
  # the run transcript.
  INSTALL="{ printf '%s\n' y '${ADMIN_USER}' '@@BRAINX_ADMIN_PASS@@'; sleep 120; } | script -q /dev/null sh ${STAGE}/as-install-boot-object.sh ${PAYLOAD} 2>&1 | tr -d '\r' | tail -40"
else
  bad "no script(1) in this recoveryOS, so kmutil's /dev/tty read cannot be fed"
  cat <<MANUAL

  The password prompt needs a real terminal. Without script(1) this step is
  the one part that stays hands-on. In the mini's Terminal, run:

      sh ${STAGE}/as-install-boot-object.sh ${PAYLOAD}

  and answer, one at a time, waiting for each: y, then ${ADMIN_USER}, then the
  password. Expect the prompts to be INVISIBLE until the run ends -- type the
  answer anyway; if it echoes, the prompt was there.

  Then re-run this script to verify the result.
MANUAL
  die "cannot drive the password prompt unattended on this system"
fi

# The password reaches the mini over the console channel, substituted in flight,
# and is written to disk on neither machine. The console must therefore have
# BRAINX_ADMIN_PASS in ITS environment -- export it before `serve`, not here.
say "5b. install"
printf '  answering: y / %s / <password>\n' "$ADMIN_USER"
run "$INSTALL"
printf '%s\n' "$OUT" | sed 's/^/  /'

# ---------------------------------------------------------------------------
say "6. verdict, from the machine and not from an exit code"
# ---------------------------------------------------------------------------
if grep -q "INSTALL COMPLETE" <<<"$OUT"; then
  ok "installer reported INSTALL COMPLETE"
else
  bad "installer did not report INSTALL COMPLETE"
fi

# Independent confirmation. An installer that says it worked and a policy that
# disagrees is the case worth catching, and the only way to catch it is to ask
# the machine a second time by a different route.
run "bputil -d 2>&1 | grep -E 'coih|Security Mode:'"
printf '  policy now:\n'; printf '%s\n' "$OUT" | sed 's/^/    /'
if grep -q "coih): absent" <<<"$OUT"; then
  die "policy says coih is still absent -- nothing was installed"
fi
ok "a custom boot object is present in the policy"

cat <<'DONE'

Installed. Reboot and choose BraiNIX at the startup picker.

Success is NOT on the screen: the framebuffer handed to a custom boot object is
a dummy that is never scanned out. Watch the USB bus instead -- _start re-arms
the watchdog four seconds longer at each rung, so the interval between reboots
is the report:

    while :; do ls /dev/cu.usbmodem* >/dev/null 2>&1 && echo up || echo down; sleep 1; done

  ~5s   device tree parsed, watchdog armed
  ~13s  pmgr translated
  ~26s  MMU and caches on -- the whole ladder
  never it did not reach the first rung
DONE
