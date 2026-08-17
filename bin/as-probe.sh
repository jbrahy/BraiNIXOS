#!/bin/bash
#
# Run the boot stub's decisions on the real machine and print what it decided.
#
#   ./bin/as-probe.sh
#
# This is the bring-up loop. Build, run on hardware, read the answer, in one
# command and a few seconds, with nobody in the room.
#
# WHY THIS EXISTS RATHER THAN A CHAINLOAD
#
# `chainload.py` replaces m1n1 with the payload. That is right for shipping and
# useless for debugging: the payload ends in a hang, so nothing on the machine
# is left able to report, and on this rig the serial path delivers nothing
# either (FIRST_LIGHT_RUNBOOK.md §9a). A chainload therefore yields exactly the
# one bit -- "it went quiet" -- that cost this project two days.
#
# So this calls `boot_stub_probe` instead, with m1n1 still resident. The probe
# parses the real boot_args, resolves the console from the real ADT, writes six
# u64s to a buffer, touches no MMIO, and returns. m1n1 survives and the proxy
# reads the answers back.
#
# It found a real bug on its first run: `adt_window` refused the machine's own
# firmware because `devtree - virt_base` underflows under m1n1's kernel-VA
# form. See src/adt/tests/fixtures/README.md.
#
# REQUIREMENTS
#
#   * m1n1 installed as the target's boot object and currently running
#   * m1n1 source and a venv with construct + pyserial (see the runbook §8)
#   * ld.lld reachable, for the trampoline m1n1's proxy assembles
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${BRAINIX_SCRATCH:-/private/tmp/claude-501/-Users-jbrahy-OtherProjects-brainix/3aab4a38-fd47-451e-9a65-11f8a595da95/scratchpad}"
PROXYCLIENT="${M1N1_PROXYCLIENT:-${SCRATCH}/m1n1-1.6.1/proxyclient}"
VENV_PY="${M1N1_VENV_PY:-${SCRATCH}/m1n1-venv/bin/python}"
LLDDIR="${LLDDIR:-${SCRATCH}/lldshim/}"

ELF="${REPO}/src/boot-stub-apple/target/aarch64-unknown-none-softfloat/release/brainix-boot-stub-apple"
BIN="${ELF}.bin"

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

# --- the device --------------------------------------------------------------
# m1n1 exposes two CDC-ACM interfaces. The proxy is on the SAME one as the
# console, not the second; the second times out with "Expected 1 bytes, got 0"
# and looks like a dead proxy.
if [[ -z "${M1N1DEVICE:-}" ]]; then
  M1N1DEVICE="$(ls /dev/cu.usbmodem* 2>/dev/null | head -1 || true)"
fi
[[ -n "${M1N1DEVICE}" ]] || die "no /dev/cu.usbmodem* found. Is m1n1 running?
  Recover it over the wire, no hands needed:
    sudo macvdmtool reboot   # then wait ~15 s for the port to reappear"
echo "==> device: ${M1N1DEVICE}"

[[ -d "${PROXYCLIENT}" ]] || die "m1n1 proxyclient not at ${PROXYCLIENT} (set M1N1_PROXYCLIENT)"
[[ -x "${VENV_PY}" ]]     || die "no venv python at ${VENV_PY} (set M1N1_VENV_PY)"

# --- build -------------------------------------------------------------------
echo "==> building the payload"
"${REPO}/bin/as-boot.sh" >/dev/null || die "as-boot.sh failed; run it directly for the reason"
printf '    %s bytes\n' "$(wc -c < "${BIN}" | tr -d ' ')"

# --- locate the probe --------------------------------------------------------
# Read from the ELF every time. Hardcoding this offset would be the same class
# of mistake as hardcoding an entry point, and it moves with every build.
NM="$(find "${HOME}/.rustup/toolchains" -name llvm-nm 2>/dev/null | head -1)"
[[ -n "${NM}" ]] || die "no llvm-nm in the rustup toolchains"
PROBE_OFF="$("${NM}" "${ELF}" | awk '/ T boot_stub_probe$/ {print $1}')"
[[ -n "${PROBE_OFF}" ]] || die "boot_stub_probe is not in the symbol table.
  #[no_mangle] alone does not survive LTO in a binary crate when nothing calls
  the function; it needs the #[used] anchor in main.rs."
echo "==> probe at 0x${PROBE_OFF}"

# --- run it ------------------------------------------------------------------
cat > "${SCRATCH}/as_probe_run.py" <<PYEOF
from m1n1.setup import *

BIN = "${BIN}"
PROBE_OFF = 0x${PROBE_OFF}
MAGIC = 0x427261694E495801

image = open(BIN, "rb").read()
code = u.malloc(len(image) + 0x1000)
out = u.malloc(64)

iface.writemem(code, image)
# Written as data; the instruction fetcher has not seen it. Skipping this
# executes whatever was in the I-cache, which fails in an unrepeatable way.
p.dc_cvau(code, len(image))
p.ic_ivau(code, len(image))

ba = p.get_bootargs()
ret = p.call(code + PROBE_OFF, ba, out)

print()
print("  boot_args    0x%x" % ba)
print("  loaded at    0x%x" % code)
if ret != MAGIC:
    print("  returned     0x%x  EXPECTED 0x%x -- the payload did not run" % (ret, MAGIC))
    raise SystemExit(1)

v = [p.read64(out + 8 * i) for i in range(6)]
stages = {0: "nothing", 1: "boot_args read", 2: "ADT window derived", 3: "console resolved"}
kinds = {0: "none", 1: "DockChannel", 2: "s5l UART"}

print("  returned     0x%x  OUR CODE RAN" % ret)
print("  stage        %d (%s)" % (v[1], stages.get(v[1], "?")))
print("  adt          0x%x  len 0x%x" % (v[2], v[3]))
print("  console      %s @ 0x%x" % (kinds.get(v[4], "?"), v[5]))
print()
if v[1] != 3:
    print("  STOPPED EARLY. The stage above names the last step that succeeded.")
    raise SystemExit(1)
if v[4] != 1:
    print("  WARNING: chose %s. On T6020 the console is DockChannel;" % kinds.get(v[4]))
    print("  anything else emits no bytes and looks like a payload that never ran.")
    raise SystemExit(1)
print("  OK: parsed real firmware and selected the console this SoC actually has.")
PYEOF

echo "==> running on the target"
cd "${PROXYCLIENT}"
LLDDIR="${LLDDIR}" M1N1DEVICE="${M1N1DEVICE}" PYTHONPATH=. \
  "${VENV_PY}" "${SCRATCH}/as_probe_run.py"
