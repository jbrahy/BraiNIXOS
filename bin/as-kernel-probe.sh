#!/bin/bash
#
# Run the kernel's aarch64 measurements on the real machine and print them.
#
#   ./bin/as-kernel-probe.sh
#
# The counterpart of as-probe.sh one layer up: that one probes the boot stub,
# this one probes the kernel. Same technique and same reason -- m1n1 stays
# resident, `kernel_probe` reports into a buffer and RETURNS, so the machine is
# still able to answer afterwards. A chainload would end in a hang, and on this
# rig a hang delivers no bytes at all (FIRST_LIGHT_RUNBOOK.md 9a).
#
# WHY THIS IS A COMMITTED SCRIPT
#
# Every result recorded in the runbook's 9c and 9d came out of this loop, and
# for two days it existed only as a heredoc in shell history. Anything that
# produces evidence the project reasons from has to be re-runnable by someone
# who was not there.
#
# THE FOUR THINGS THAT COST A CYCLE EACH (runbook 9c)
#
#   * Build RELEASE. A debug kernel overruns the stack `p.call` runs on.
#   * Size the allocation from `__bss_end`, not from the image. `objcopy -O
#     binary` does not emit .bss, and the 16 KiB-aligned root table lives in it.
#   * .bss is zeroed inside `kernel_probe` itself, because that entry point
#     never passes through `_start`.
#   * Not all m1n1 USB interfaces answer the proxy. Two of four time out with
#     "Expected 1 bytes, got 0", which looks exactly like a dead proxy.
#
# REQUIREMENTS
#
#   * m1n1 installed as the target's boot object and currently running
#   * m1n1 source and a venv with construct + pyserial (runbook 8)
#   * ld.lld reachable, for the trampoline m1n1's proxy assembles
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${BRAINIX_SCRATCH:-/private/tmp/claude-501/-Users-jbrahy-OtherProjects-brainix/3aab4a38-fd47-451e-9a65-11f8a595da95/scratchpad}"
PROXYCLIENT="${M1N1_PROXYCLIENT:-${SCRATCH}/m1n1-1.6.1/proxyclient}"
VENV_PY="${M1N1_VENV_PY:-${SCRATCH}/m1n1-venv/bin/python}"
LLDDIR="${LLDDIR:-${SCRATCH}/lldshim/}"

TOOLCHAIN="nightly-2025-12-01"
TARGET="aarch64-unknown-none-softfloat"
TOOLCHAIN_BIN="${HOME}/.rustup/toolchains/${TOOLCHAIN}-aarch64-apple-darwin/bin"
ELF="${REPO}/target/${TARGET}/release/brainix"
BIN="${SCRATCH}/brainix-kernel-aarch64.bin"

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

[[ -x "${TOOLCHAIN_BIN}/cargo" ]] || die "pinned toolchain missing at ${TOOLCHAIN_BIN}
  run: rustup toolchain install ${TOOLCHAIN}"
[[ -d "${PROXYCLIENT}" ]] || die "m1n1 proxyclient not at ${PROXYCLIENT} (set M1N1_PROXYCLIENT)"
[[ -x "${VENV_PY}" ]]     || die "no venv python at ${VENV_PY} (set M1N1_VENV_PY)"

# --- the device --------------------------------------------------------------
# The port carrying m1n1 MOVES BETWEEN BOOTS. With two cables attached there are
# four /dev/cu.usbmodem* nodes; which one carries the console and proxy is not
# stable across reboots, and the three that do not answer fail with
# "Expected 1 bytes, got 0 bytes" -- indistinguishable from a target that is
# wedged. Taking the first node, or remembering which one worked last time, is
# how a healthy machine gets diagnosed as dead.
#
# m1n1 buffers its boot log and flushes it when the port is opened, so a couple
# of bytes of console output is a positive identification and costs one second.
if [[ -z "${M1N1DEVICE:-}" ]]; then
  for candidate in /dev/cu.usbmodem*; do
    [[ -e "${candidate}" ]] || continue
    if [[ -n "$(timeout 2 head -c 64 "${candidate}" 2>/dev/null | tr -d '\0')" ]]; then
      M1N1DEVICE="${candidate}"
      break
    fi
  done
fi
[[ -n "${M1N1DEVICE:-}" ]] || die "no /dev/cu.usbmodem* is talking. Is m1n1 running?
  Recover it over the wire, no hands needed:
    sudo macvdmtool reboot   # then wait ~15 s for the port to reappear"
echo "==> device: ${M1N1DEVICE}"

# --- build -------------------------------------------------------------------
# Homebrew's cargo shadows rustup's on this workstation and does not understand
# rust-toolchain.toml, so the pinned toolchain is invoked by absolute path. The
# crate directory is the working directory because cargo discovers
# .cargo/config.toml from there, and the repo root's pins
# build.target = "x86_64-unknown-none".
echo "==> building the kernel (release)"
cd "${REPO}/src/kernel"
RUSTC="${TOOLCHAIN_BIN}/rustc" RUSTDOC="${TOOLCHAIN_BIN}/rustdoc" \
  "${TOOLCHAIN_BIN}/cargo" build --target "${TARGET}" --features kernel-binary --release \
  >/dev/null || die "kernel build failed; run it directly for the reason"

OBJCOPY="$(find "${HOME}/.rustup/toolchains" -name llvm-objcopy 2>/dev/null | head -1)"
NM="$(find "${HOME}/.rustup/toolchains" -name llvm-nm 2>/dev/null | head -1)"
[[ -n "${OBJCOPY}" && -n "${NM}" ]] || die "no llvm-objcopy/llvm-nm in the rustup toolchains"
"${OBJCOPY}" -O binary "${ELF}" "${BIN}"
printf '    %s bytes\n' "$(wc -c < "${BIN}" | tr -d ' ')"

# --- locate the probe and the end of .bss -------------------------------------
# Read both from the ELF every time. Hardcoding either is the same class of
# mistake as hardcoding an entry point: they move with every build, and an
# allocation sized from a stale __bss_end puts the root page table on top of
# m1n1.
PROBE_OFF="$("${NM}" "${ELF}" | awk '/ T kernel_probe$/ {print $1}')"
[[ -n "${PROBE_OFF}" ]] || die "kernel_probe is not in the symbol table.
  #[no_mangle] alone does not survive LTO in a binary crate when nothing calls
  the function; it needs the #[used] anchor in main.rs."
DROP_OFF="$("${NM}" "${ELF}" | awk '/ T el1_probe$/ {print $1}')"
[[ -n "${DROP_OFF}" ]] || die "el1_probe is not in the symbol table (see above)"
BSS_END="$("${NM}" "${ELF}" | awk '/ B __bss_end$/ {print $1}')"
[[ -n "${BSS_END}" ]] || die "__bss_end is not in the symbol table"
echo "==> kernel_probe at 0x${PROBE_OFF}, el1_probe at 0x${DROP_OFF}, __bss_end at 0x${BSS_END}"

# --- run it ------------------------------------------------------------------
cat > "${SCRATCH}/as_kernel_probe_run.py" <<PYEOF
from m1n1.setup import *

BIN = "${BIN}"
PROBE_OFF = 0x${PROBE_OFF}
DROP_OFF = 0x${DROP_OFF}
BSS_END = 0x${BSS_END}
MAGIC = 0x4B726E6C4E495802
DROP_MAGIC = 0x4B726E6C4E495803
EL1_FAULT_POISON = 0xE11FA01700000000

def par(name, value):
    # PAR_EL1 bit 0 set means the translation FAILED, and the failure is the
    # answer rather than an error: it says EL1 genuinely cannot reach that
    # address, which is a drop that lands nowhere.
    if value & 1:
        return "  %-16s 0x%016x  UNREACHABLE FROM EL1 (FST 0x%x)" % (
            name, value, (value >> 1) & 0x3F)
    return "  %-16s 0x%016x  -> PA 0x%x" % (name, value, value & 0x000FFFFFFFFFF000)

image = open(BIN, "rb").read()
# Allocate to __bss_end, not to len(image). .bss lives past the end of the flat
# image and holds the 16 KiB-aligned root table; sizing from the image puts it
# outside the allocation, on top of m1n1.
span = max(len(image), BSS_END) + 0x4000

# ALIGN THE LOAD ADDRESS. u.malloc does not, and this image contains two
# 2 KiB-aligned vector tables and a 16 KiB-aligned root page table -- all aligned
# relative to the start of the image, which only makes them aligned in memory if
# the image starts aligned.
#
# Getting this wrong does not fail loudly. `VBAR_EL2` ignores bits [10:0], so a
# misaligned table is not rejected: every exception simply branches that many
# bytes short of the real table, into the middle of whatever precedes it. The
# machine hangs, with no console and no fault, and nothing about the symptom
# points at the load address.
#
# It was luck that this ever worked. m1n1's allocator returns whatever the heap
# happens to be at, so the alignment changes with the size of the preceding
# allocations -- which means it changes with the size of the image. Adding
# 2 KiB of vector table was enough to turn a working probe into a hang, and
# nothing in the diff looked like it could.
#
# 16 KiB, not 2 KiB: it is the granule this SoC uses and the alignment the root
# page table needs, and it satisfies the vector tables as well.
raw = u.malloc(span + 0x4000)
code = (raw + 0x3FFF) & ~0x3FFF
out = u.malloc(8 * 96)

iface.writemem(code, image)
# Written as data; the instruction fetcher has not seen it. Skipping this
# executes whatever was in the I-cache, which fails in an unrepeatable way.
p.dc_cvau(code, len(image))
p.ic_ivau(code, len(image))

ba = p.get_bootargs()
print()
print("  boot_args    0x%x" % ba)
print("  loaded at    0x%x  span 0x%x  (raw 0x%x)" % (code, span, raw))
if code & 0x3FFF:
    print("  load address is not 16 KiB aligned -- refusing to run")
    raise SystemExit(1)
sys.stdout.flush()

ret = p.call(code + PROBE_OFF, ba, out)
if ret != MAGIC:
    print("  returned     0x%x  EXPECTED 0x%x -- the payload did not run" % (ret, MAGIC))
    raise SystemExit(1)
print("  returned     0x%x  OUR CODE RAN" % ret)

def r(i):
    return p.read64(out + 8 * i)

print()
print("  -- identity ------------------------------------------------------")
print("  CurrentEL        EL%d" % r(1))
print("  console base     0x%-16x  from ADT: %d" % (r(2), r(3)))
print("  MIDR             0x%x" % r(4))
print("  MPIDR            0x%x" % r(5))

print()
print("  -- exception level bisect (item 7) -------------------------------")
print("  HCR before       0x%016x" % r(59))
print("  HCR TGE cleared  0x%016x" % r(60))
print("  HCR restored     0x%016x" % r(61))
print("  TTBR0_EL12 wrote 0x%016x" % r(62))
print("  TTBR0_EL12 read  0x%016x  %s" % (r(63), "MATCH" if r(62) == r(63) else "MISMATCH"))
print("  eret-to-self     %d  (1 = exception return works at this level)" % r(64))

# Each EL1 stage is its own p.call. A returning call leaves m1n1 alive for the
# next one, so a stage that hangs costs only itself -- everything already printed
# stays printed.
dout = u.malloc(8 * 16)

def d(i):
    return p.read64(dout + 8 * i)

print()
print("  -- stage 1: what EL1 can reach, asked without going there ---------")
if p.call(code + DROP_OFF, 1, dout) != DROP_MAGIC:
    print("  stage 1 did not return the magic")
    raise SystemExit(1)
print("  HCR while asking 0x%016x  TGE %d" % (d(1), (d(1) >> 27) & 1))
print(par("code", d(2)))
print(par("EL1 vectors", d(3)))
print(par("EL1 stack", d(4)))
unreachable = [n for n, v in (("code", d(2)), ("vectors", d(3)), ("stack", d(4))) if v & 1]
if unreachable:
    print()
    print("  STOP: %s not reachable from EL1. The drop would land nowhere." % ", ".join(unreachable))
    print("  Not attempting it -- a hang here would cost a reboot to learn less.")
    raise SystemExit(1)

print()
print("  -- stage 2: dropping to EL1 (this is the one that can hang) -------")
if p.call(code + DROP_OFF, 2, dout) != DROP_MAGIC:
    print("  stage 2 did not return the magic")
    raise SystemExit(1)

observed, hcr_before, hcr_after, vec = d(1), d(2), d(3), d(4)
print("  observed EL      EL%d  %s" % (observed, "DROPPED TO EL1" if observed == 1 else "NOT EL1"))
print("  HCR before       0x%016x" % hcr_before)
print("  HCR after        0x%016x  %s" % (hcr_after, "RESTORED" if hcr_after == hcr_before else "NOT RESTORED"))
print("  return vector    %d  (8 = lower EL, AArch64, synchronous)" % vec)

fault = [d(5), d(6), d(7), d(8)]
if all(v == EL1_FAULT_POISON for v in fault):
    print("  EL1 fault        none -- EL1 reached its hvc without faulting")
else:
    print("  EL1 fault        vector %d" % fault[0])
    print("    ESR_EL1        0x%016x  EC 0x%x" % (fault[1], (fault[1] >> 26) & 0x3F))
    print("    ELR_EL1        0x%016x" % fault[2])
    print("    FAR_EL1        0x%016x" % fault[3])

print()
ok = (observed == 1 and vec == 8 and hcr_before == hcr_after
      and all(v == EL1_FAULT_POISON for v in fault))
if ok:
    print("  OK: dropped to EL1, came back through the HVC, HCR_EL2 restored intact.")
else:
    print("  NOT YET. The lines above say which half is wrong.")
    raise SystemExit(1)
PYEOF

echo "==> running on the target"
cd "${PROXYCLIENT}"
LLDDIR="${LLDDIR}" M1N1DEVICE="${M1N1DEVICE}" PYTHONPATH=. \
  "${VENV_PY}" "${SCRATCH}/as_kernel_probe_run.py"
