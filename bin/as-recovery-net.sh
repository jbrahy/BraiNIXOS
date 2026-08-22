#!/bin/sh
#
# Bring the mini's network up in recoveryOS, and prove it reaches the Internet.
#
# Needed because two separate steps of the install require real connectivity
# and neither says so until it has already failed:
#
#   * `bputil -f` (raise to Full Security) is personalized against Apple's
#     servers and fails with BYErrorHint=NetworkRequired;
#   * the recovery console (as-recovery-agent.sh) needs a route to the laptop.
#
# WHAT DOES NOT WORK HERE, so nobody spends an evening rediscovering it:
#
#   * recoveryOS ships NO networksetup. Only ifconfig and ipconfig. So Wi-Fi
#     cannot be joined from the Terminal at all, and Recovery does not inherit
#     the association from macOS. The menu-bar picker is the only route and it
#     needs a mouse. Use Ethernet.
#   * A DHCP lease is not connectivity. On 2026-08-21 the mini held a lease and
#     a correct default route while routing exactly nothing, because the
#     laptop's Internet Sharing was NATing out of the wrong interface and IP
#     forwarding was off. Only an actual fetch settles it.
#
# Prints a single last line: NET OK or NET FAIL, so a caller can branch on it.

set -u

IFACE="${1:-en0}"
PROBE="${2:-http://captive.apple.com}"

say() { printf '\n=== %s ===\n' "$*"; }

say "link"
ifconfig "$IFACE" 2>&1 | grep -E "status|ether" | sed 's/^/  /'
if ! ifconfig "$IFACE" 2>/dev/null | grep -q "status: active"; then
  printf '  %s has no link. Plug Ethernet in; recoveryOS cannot join Wi-Fi.\n' "$IFACE"
  echo "NET FAIL"
  exit 1
fi

say "address"
# Ask for a lease even if one looks present: after a cable move the interface
# can hold a stale 169.254 self-assignment that looks like a configured address.
ipconfig set "$IFACE" DHCP 2>/dev/null || true
i=0
while [ "$i" -lt 15 ]; do
  ADDR="$(ipconfig getifaddr "$IFACE" 2>/dev/null || true)"
  [ -n "$ADDR" ] && break
  i=$((i + 1))
  sleep 1
done
printf '  address: %s\n' "${ADDR:-none}"
case "${ADDR:-}" in
  169.254.*)
    printf '  self-assigned: nothing answered DHCP on this segment.\n'
    printf '  If the cable goes to the laptop, turn Internet Sharing ON there\n'
    printf '  and share FROM Wi-Fi TO the Ethernet adapter -- not the reverse.\n'
    ;;
esac
route -n get default 2>/dev/null | grep -E "gateway|interface" | sed 's/^/  /'

say "reachability"
# The only test that counts. curl is present in recoveryOS; shasum, openssl and
# networksetup are not, so do not reach for those.
CODE="$(curl -m 15 -s -o /dev/null -w '%{http_code}' "$PROBE" 2>/dev/null || echo 000)"
printf '  %s -> HTTP %s\n' "$PROBE" "$CODE"

if [ "$CODE" = "000" ]; then
  printf '\n  No route to the Internet. A lease and a gateway are not enough.\n'
  printf '  On the laptop check, in this order:\n'
  printf '    1. sharing uplink != shared device (both set to the same one is\n'
  printf '       the default failure; uplink must be the Wi-Fi service)\n'
  printf '    2. sysctl net.inet.ip.forwarding  (must be 1)\n'
  printf '    3. pfctl -a com.apple.internet-sharing/shared_v4 -s nat\n'
  printf '       must read: nat on <uplink> ... -> (<uplink>)\n'
  echo "NET FAIL"
  exit 1
fi

echo "NET OK"
