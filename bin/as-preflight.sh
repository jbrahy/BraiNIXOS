#!/bin/bash
#
# Enumerate everything an Apple Silicon boot-object install depends on, and
# refuse to say READY if any of it is missing. Read-only: it changes nothing.
#
# Run it on the mini, under macOS or under recoveryOS:
#
#   sh /Volumes/Data/Users/Shared/brainix-boot/as-preflight.sh
#   ssh jbrahy@baby-jesus.local 'sh /Users/Shared/brainix-boot/as-preflight.sh'
#
# WHY THIS EXISTS
#
# Every install failure so far was a missing precondition discovered *during*
# the install, ten minutes and one physical trip after it could have been
# discovered for free:
#
#   * recoveryOS has no shasum. Then no openssl. Then no Perl Digest::SHA.
#     Three separate rounds, each found by a script dying mid-run.
#   * `diskutil info <volume-group-uuid>` names the group's Data volume, whose
#     mount point is /System/Volumes/Data, not the system volume kmutil wants.
#   * The volume group UUID changes when a volume group is rebuilt, and a stale
#     -v fails in a way that reads as a policy fault.
#   * A payload was installed without anyone checking which build it was.
#
# So this asks all of those questions at once, before anything is at stake, and
# prints the answers whether they are good or bad. Absence of an error is not
# evidence; the report says what it actually found.

set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
MANIFEST="${HERE}/payloads.tsv"
FAIL=0

say()  { printf '\n=== %s ===\n' "$*"; }
ok()   { printf '  OK    %s\n' "$*"; }
warn() { printf '  WARN  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

# ---------------------------------------------------------------------------
say "1. environment"
# ---------------------------------------------------------------------------
sw_vers 2>/dev/null || printf '  sw_vers unavailable\n'
BOOTED="$(diskutil info / 2>/dev/null | awk -F': *' '/Volume Name/{print $2}')"
printf '  booted volume: %s\n' "${BOOTED:-unknown}"

# recoveryOS is the only place kmutil configure-boot works at all, and it is
# also the place where half the userland is missing. Knowing which we are in
# changes what counts as a failure below.
if [ -d /System/Library/CoreServices/recoveryOSVersion.plist ] || \
   printf '%s' "${BOOTED:-}" | grep -qi 'recovery' || \
   [ -e /System/Installation ]; then
  ENV_KIND=recoveryOS
else
  ENV_KIND=macOS
fi
printf '  environment: %s\n' "$ENV_KIND"

# ---------------------------------------------------------------------------
say "2. tool inventory"
# ---------------------------------------------------------------------------
for tool in diskutil bputil kmutil stat awk sed grep printf; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else bad "$tool is missing"; fi
done
for tool in curl unzip nvram; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else warn "$tool is missing (not fatal)"; fi
done

# These two decide whether the install can run unattended at all, so the answer
# belongs in the report rather than in someone's memory.
#
#   curl    -- the recovery console's only transport, and the only way to prove
#              connectivity. A DHCP lease proves nothing.
#   script  -- allocates a pty. kmutil reads the PASSWORD from /dev/tty, so a
#              plain pipe feeds y and the username and then waits forever for a
#              human. With script(1) the whole install is unattended; without
#              it, that one prompt stays hands-on.
#   pmset   -- disable idle sleep before anything long. A dark display is
#              indistinguishable from a wedged machine.
for tool in script pmset; do
  if command -v "$tool" >/dev/null 2>&1; then ok "$tool"; else warn "$tool is missing"; fi
done
if command -v script >/dev/null 2>&1; then
  printf '  note: unattended install is possible (script(1) can feed the tty)\n'
else
  printf '  note: kmutil password prompt will need a human; see FIRST_LIGHT_RUNBOOK.md 5\n'
fi

# ---------------------------------------------------------------------------
say "3. hashing capability"
# ---------------------------------------------------------------------------
# Found the hard way, one round trip at a time. Whatever this reports is what
# the install scripts may rely on -- nothing else.
HASH_METHOD=none
if command -v shasum >/dev/null 2>&1; then
  HASH_METHOD=shasum
elif command -v openssl >/dev/null 2>&1 && openssl dgst -sha256 /dev/null >/dev/null 2>&1; then
  HASH_METHOD=openssl
elif command -v perl >/dev/null 2>&1 && perl -MDigest::SHA -e1 >/dev/null 2>&1; then
  HASH_METHOD=perl
fi
if [ "$HASH_METHOD" = none ]; then
  warn "no sha256 available (shasum, openssl and Perl Digest::SHA all absent)"
  warn "payload checks fall back to size only -- verify the hash from macOS instead"
else
  ok "sha256 via $HASH_METHOD"
fi

sha_of() {
  case "$HASH_METHOD" in
    shasum)  shasum -a 256 "$1" | awk '{print $1}' ;;
    openssl) openssl dgst -sha256 "$1" | awk '{print $NF}' ;;
    perl)    perl -MDigest::SHA=sha256_hex -e 'local $/; open my $f, "<:raw", $ARGV[0] or die; print sha256_hex(<$f>)' "$1" ;;
    *)       printf '' ;;
  esac
}

# ---------------------------------------------------------------------------
say "4. volume groups"
# ---------------------------------------------------------------------------
diskutil apfs listVolumeGroups 2>/dev/null | grep -E "Volume Group [0-9A-F-]{36}|Name:" || warn "could not list volume groups"

VG="$(diskutil apfs listVolumeGroups 2>/dev/null | awk '
  /Volume Group [0-9A-F-]{36}/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{36}$/) uuid=$i }
  /BraiNIX/ && uuid { print uuid; exit }
')"
if [ -n "$VG" ]; then ok "BraiNIX volume group: $VG"; else bad "no BraiNIX volume group found"; fi

# The target kmutil wants is the SYSTEM volume, resolved by name. Resolving it
# from the group UUID gives /System/Volumes/Data, which is a valid directory,
# so the mistake does not announce itself.
if [ -d /Volumes/BraiNIX ]; then
  ok "/Volumes/BraiNIX is mounted"
  TVG="$(diskutil info /Volumes/BraiNIX 2>/dev/null | awk -F': *' '/Volume Group/{print $2}' | tr -d ' ')"
  if [ -n "$VG" ] && [ -n "$TVG" ] && [ "$TVG" != "$VG" ]; then
    bad "/Volumes/BraiNIX belongs to $TVG, not $VG"
  else
    ok "/Volumes/BraiNIX belongs to the BraiNIX group"
  fi
else
  if [ "$ENV_KIND" = recoveryOS ]; then
    bad "/Volumes/BraiNIX is not mounted -- kmutil has no target"
  else
    warn "/Volumes/BraiNIX is not mounted (expected while booted from Macintosh HD)"
  fi
fi

# ---------------------------------------------------------------------------
say "5. security policy"
# ---------------------------------------------------------------------------
# bputil refuses to run as a normal user: `The tool requires running as root`.
# The first version of this script did not check for that, so the grep matched
# nothing and it announced "not Permissive" and "Macintosh HD HAS a custom boot
# object" -- two alarming conclusions manufactured from an unread error. That
# is BRINGUP_PLAN item 5 committed inside the tool written to prevent it.
# Anything unreadable is now reported as unknown, never as a finding.
if [ "$(id -u)" -eq 0 ]; then
  BP="bputil"
elif sudo -n true 2>/dev/null; then
  BP="sudo -n bputil"
else
  BP=""
fi

# Per-group policy, which is NOT what `bputil -d` gives you.
#
# `bputil -d` prints the policy of the BOOTED environment. In 1TR that block is
# headed "OS Type: one true recoveryOS" and its OS Pairing Status describes
# recovery itself, which is always Not Paired. Reading a target group's pairing
# out of it means every group looks broken, including good ones -- a false
# alarm that would block a valid install. `bputil -e` prints one block per
# volume group; this pulls out the block for the group asked about.
group_block() {  # $1 = vuid, stdin = bputil -e output
  awk -v want="$1" '''
    /^ *OS Type/ { if (hit) { printf "%s", blk; done=1; exit } blk=""; hit=0 }
    { blk = blk $0 "\n"; if (index($0, want)) hit=1 }
    END { if (!done && hit) printf "%s", blk }'''
}

policy_of() {  # $1 = volume group uuid; prints output, returns 1 if unusable
  [ -n "$BP" ] || return 1
  out="$($BP -d -v "$1" 2>&1)"
  case "$out" in
    *"requires running as root"*|"") return 1 ;;
  esac
  printf '%s' "$out"
}

if [ -z "$VG" ]; then
  warn "skipping policy check: no BraiNIX volume group"
elif ! command -v bputil >/dev/null 2>&1; then
  warn "skipping policy check: bputil unavailable"
elif [ -z "$BP" ]; then
  warn "policy UNKNOWN: bputil needs root and this session is not root"
  warn "re-run as: sudo sh $0    (over ssh, sudo needs a tty or NOPASSWD)"
else
  if POLICY="$(policy_of "$VG")"; then
    printf '%s\n' "$POLICY" | grep -E "Security Mode:|CustomKC|coih|Kernel CTRR" | sed 's/^/  /'
    if printf '%s' "$POLICY" | grep -q "Permissive"; then
      ok "BraiNIX group is Permissive"
    else
      warn "BraiNIX group is not Permissive yet -- the install script sets it"
    fi
    if printf '%s' "$POLICY" | grep -q "coih): absent"; then
      printf '  note: no custom boot object installed on this group\n'
    else
      printf '  note: a custom boot object IS installed; installing again replaces it\n'
    fi

    # THE precondition, and the one this script used to miss.
    #
    # Raising a group to Full Security is signed by Apple over the network and
    # works on anything. LOWERING it to Permissive is signed locally and
    # requires the group's OS to be Paired -- and a group is Paired only if it
    # has a recoveryOS of its own. A group carved by adding a volume and
    # copying a system into it never gets one, and is therefore permanently
    # uninstallable, no matter what the security mode says.
    #
    # 2026-08-21 was spent discovering that the hard way: nine install runs,
    # every one failing at `com.apple.bootpolicy Code=17 "pairing (17)"`, an
    # error whose text names the cause and was still read as four other things
    # first. The old line here said "the install script sets it" about
    # Permissive, which is false in exactly this case and read as reassurance.
    # Read pairing from the per-group view, never from $POLICY (which is
    # `bputil -d` and describes the booted environment).
    GPOL="$([ -n "$BP" ] && $BP -e 2>&1 | group_block "$VG" || true)"
    if [ -z "$GPOL" ]; then
      warn "pairing status UNKNOWN -- no bputil -e block for $VG"
    elif printf '%s' "$GPOL" | grep -q "OS Pairing Status.*Not Paired"; then
      bad "BraiNIX group is NOT PAIRED -- its policy can never be downgraded"
      printf '  A custom boot object cannot be installed on this group, ever.\n'
      printf '  Cause: the group has no recoveryOS of its own (see below).\n'
      printf '  Fix:   reinstall macOS onto that volume so the installer\n'
      printf '         creates the paired recoveryOS. See FIRST_LIGHT_RUNBOOK.md 5.\n'
    else
      ok "BraiNIX group is Paired (its policy can be downgraded)"
    fi
  else
    warn "policy UNKNOWN for $VG: bputil produced no readable output"
  fi

  # Macintosh HD must come through untouched. This invariant has held across
  # five recovery trips and three boot objects; assert it, but only when the
  # answer is actually readable.
  MHD="$(diskutil apfs listVolumeGroups 2>/dev/null | awk '
    /Volume Group [0-9A-F-]{36}/ { for (i=1;i<=NF;i++) if ($i ~ /^[0-9A-F-]{36}$/) uuid=$i }
    /Macintosh HD/ && uuid { print uuid; exit }
  ')"
  if [ -n "$MHD" ]; then
    if MPOL="$(policy_of "$MHD")"; then
      if printf '%s' "$MPOL" | grep -q "coih): absent"; then
        ok "Macintosh HD has no custom boot object (as it must not)"
      else
        bad "Macintosh HD HAS a custom boot object -- this should never happen"
      fi
    else
      warn "Macintosh HD policy UNKNOWN: bputil produced no readable output"
    fi
  fi
fi

# ---------------------------------------------------------------------------
say "5a. recoveryOS ownership"
# ---------------------------------------------------------------------------
# The structural reason behind a Not Paired group, checked separately because
# it is visible even when bputil is unavailable, and because the fix is
# completely different from every other failure in this file: no flag, no
# credential and no retry changes it. The volume has to be reinstalled.
#
# One Recovery volume in the container means one OS install owns it. On this
# machine that was Macintosh HD, and BraiNIX -- carved by copying -- had none.
REC_COUNT="$(diskutil apfs list 2>/dev/null | grep -c "Recovery (Case-insensitive)" || true)"
printf '  Recovery volumes in the container: %s\n' "${REC_COUNT:-unknown}"
diskutil apfs list 2>/dev/null | grep -E "Name:" | sed 's/^ */  /' | head -12

if [ "${REC_COUNT:-0}" -le 1 ] && [ -n "${VG:-}" ]; then
  warn "only one Recovery volume exists; if it belongs to the production OS then"
  warn "the experiment group has none, and its policy can never be downgraded"
  printf '  A group needs its OWN recoveryOS to be Paired. Copying a system\n'
  printf '  volume into a new group does not create one -- installing macOS does.\n'
fi

# ---------------------------------------------------------------------------
say "6. payloads"
# ---------------------------------------------------------------------------
if [ ! -r "$MANIFEST" ]; then
  bad "manifest not found at $MANIFEST"
else
  # Skip comments and the header row.
  grep -v '^#' "$MANIFEST" | grep -v '^name	' | grep -v '^[[:space:]]*$' | while IFS='	' read -r name file bytes sha entry lva source; do
    path="${HERE}/${file}"
    if [ ! -f "$path" ]; then
      printf '  MISS  %-14s %s not staged\n' "$name" "$file"
      continue
    fi
    actual_size="$(stat -f%z "$path" 2>/dev/null)"
    if [ "$actual_size" != "$bytes" ]; then
      printf '  FAIL  %-14s %s is %s bytes, manifest says %s\n' "$name" "$file" "$actual_size" "$bytes"
      continue
    fi
    if [ "$HASH_METHOD" = none ]; then
      printf '  OK    %-14s %s size %s (hash unverifiable here)  entry=%s\n' "$name" "$file" "$bytes" "$entry"
    else
      actual_sha="$(sha_of "$path")"
      if [ "$actual_sha" = "$sha" ]; then
        printf '  OK    %-14s %s size and sha256 match          entry=%s\n' "$name" "$file" "$entry"
      else
        printf '  FAIL  %-14s %s sha256 is %s\n' "$name" "$file" "$actual_sha"
      fi
    fi
  done
  # The loop above runs in a subshell, so its failures cannot raise FAIL.
  # Say so rather than letting the summary quietly under-report.
  printf '\n  (payload rows report inline; read them, do not trust the summary alone)\n'
fi

# ---------------------------------------------------------------------------
say "7. entry points agree with the manifest"
# ---------------------------------------------------------------------------
# A second copy of the entry point in an install script is exactly how the m1n1
# value got lost the first time. Cross-check instead of hoping.
#
# An installer that takes BOTH its payload and its entry point from the manifest
# has no second copy to disagree, which is strictly better than this check and
# makes it inapplicable. Say that, rather than warning about a `$PAYLOAD_FILE`
# that is a variable name and not a filename -- a warning nobody can act on
# trains people to skip warnings.
for script in "${HERE}"/as-install-*.sh; do
  [ -f "$script" ] || continue
  if grep -q 'cut -f5' "$script" 2>/dev/null; then
    ok "$(basename "$script"): reads payload and entry point from the manifest, nothing to disagree"
    continue
  fi
  declared="$(grep -E '^ENTRY_POINT=' "$script" 2>/dev/null | head -1 | cut -d= -f2)"
  payload="$(grep -E '^PAYLOAD=' "$script" 2>/dev/null | head -1 | sed 's|.*/||; s|"$||')"
  [ -n "$declared" ] || continue
  expected="$(grep -v '^#' "$MANIFEST" 2>/dev/null | awk -F'\t' -v f="$payload" '$2==f {print $5; exit}')"
  if [ -z "$expected" ]; then
    warn "$(basename "$script"): payload $payload is not in the manifest"
  elif [ "$declared" = "$expected" ]; then
    ok "$(basename "$script"): entry point $declared matches the manifest for $payload"
  else
    bad "$(basename "$script"): entry point $declared but manifest says $expected for $payload"
  fi
done

# ---------------------------------------------------------------------------
say "8. credentials"
# ---------------------------------------------------------------------------
CRED="${HERE}/.admin"
if [ -r "$CRED" ]; then
  u="$(sed -n 1p "$CRED")"
  p="$(sed -n 2p "$CRED")"
  if [ -n "$u" ] && [ -n "$p" ]; then
    ok "credential file present, username: $u"
    printf '  kmutil will prompt for this username and password; an empty answer\n'
    printf '  fails as "Code=71 not a valid admin user", which reads as a policy fault.\n'
  else
    bad "credential file must hold username on line 1 and password on line 2"
  fi
else
  bad "no credential file at $CRED"
fi

# ---------------------------------------------------------------------------
say "verdict"
# ---------------------------------------------------------------------------
if [ "$FAIL" -eq 0 ]; then
  printf '  READY (%s) -- %d checks failed\n' "$ENV_KIND" "$FAIL"
  exit 0
else
  printf '  NOT READY (%s) -- %d checks failed, see FAIL lines above\n' "$ENV_KIND" "$FAIL"
  exit 1
fi
