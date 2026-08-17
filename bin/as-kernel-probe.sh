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
#   * STAGE 9 IS NOT REPEATABLE WITHOUT A REBOOT. It takes a core out of reset
#     and parks it; a second run cannot take it out of reset again, so it
#     reports `started 0` and every measurement below it reads zero. That looks
#     exactly like a regression in the release path and is not one. The tell is
#     `RVBAR before` holding an entry address from the previous run instead of
#     the SoC default. Reboot between runs:
#
#         sudo macvdmtool reboot   # then wait ~15 s for the port to reappear
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

def par(name, value, level="EL1"):
    # PAR_EL1 bit 0 set means the translation FAILED, and the failure is the
    # answer rather than an error. For an EL1 query it means a drop that lands
    # nowhere; for an EL0 query on a kernel address it is the isolation working.
    if value & 1:
        return "  %-16s 0x%016x  UNREACHABLE FROM %s (FST 0x%x)" % (
            name, value, level, (value >> 1) & 0x3F)
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
cf = r(44)
print("  ID_AA64ISAR0     0x%016x  RNDR field [63:60] = 0x%x" % (r(40), (r(40) >> 60) & 0xF))
print("  ID_AA64ISAR1     0x%016x  APA 0x%x API 0x%x GPA 0x%x GPI 0x%x"
      % (r(41), (r(41) >> 4) & 0xF, (r(41) >> 8) & 0xF, (r(41) >> 24) & 0xF, (r(41) >> 28) & 0xF))
print("  ID_AA64PFR1      0x%016x  BT [3:0] = 0x%x" % (r(42), r(42) & 0xF))
print("  FEAT_RNG         %d   RNDR draws 0x%x 0x%x  both valid: %d"
      % (r(43), r(45), r(46), r(47)))
print("  PAC/BTI          APA=%d API=%d GPA=%d GPI=%d BTI=%d"
      % (cf & 1, (cf >> 1) & 1, (cf >> 2) & 1, (cf >> 3) & 1, (cf >> 4) & 1))

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
# 48 slots, not 16. Stage 9 writes through index 27, and a probe that scribbles
# past its own buffer would corrupt whatever m1n1 put after it -- a failure that
# presents as an unrelated stage misbehaving later.
dout = u.malloc(8 * 128)

def d(i):
    return p.read64(dout + 8 * i)

print()
print("  -- stage 1: what EL1 can reach, asked without going there ---------")
if p.call(code + DROP_OFF, 1, ba, dout) != DROP_MAGIC:
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
if p.call(code + DROP_OFF, 2, ba, dout) != DROP_MAGIC:
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

el1_ok = (observed == 1 and vec == 8 and hcr_before == hcr_after
          and all(v == EL1_FAULT_POISON for v in fault))
print()
if el1_ok:
    print("  OK: dropped to EL1, came back through the HVC, HCR_EL2 restored intact.")
else:
    print("  NOT YET. The lines above say which half is wrong.")

print()
print("  -- stage 4: SVC dispatched at EL1, and resumed from ---------------")
if p.call(code + DROP_OFF, 4, ba, dout) != DROP_MAGIC:
    print("  stage 4 did not return the magic")
    raise SystemExit(1)
svc_count, svc_esr, svc_elr = d(9), d(10), d(11)
svc_fault = [d(5), d(6), d(7), d(8)]
print("  observed EL      EL%d" % d(1))
print("  SVC dispatches   %d" % svc_count)
if svc_count:
    print("  ESR_EL1          0x%016x  EC 0x%x  ISS 0x%x"
          % (svc_esr, (svc_esr >> 26) & 0x3F, svc_esr & 0xFFFF))
    print("  ELR_EL1          0x%016x  (the instruction after the svc)" % svc_elr)
if all(v == EL1_FAULT_POISON for v in svc_fault):
    print("  EL1 fault        none -- EL1 resumed after the svc and reached its hvc")
else:
    print("  EL1 fault        vector %d  ESR 0x%016x  EC 0x%x"
          % (svc_fault[0], svc_fault[1], (svc_fault[1] >> 26) & 0x3F))

# Three conditions, not one. Reaching a handler proves dispatch; the syndrome
# proves it was the SVC we issued and not some other trap on the same vector;
# and the absence of a fault record proves EL1 RESUMED rather than abandoning
# the level, which is the half a trap test cannot show.
svc_ok = (svc_count == 1
          and (svc_esr >> 26) & 0x3F == 0x15
          and svc_esr & 0xFFFF == 0x42
          and all(v == EL1_FAULT_POISON for v in svc_fault))
print()
if svc_ok:
    print("  OK: SVC #0x42 dispatched to EL1's handler with EC 0x15, and EL1")
    print("      carried on from the instruction after it.")
else:
    print("  SVC NOT PROVEN. All of: one dispatch, EC 0x15, ISS 0x42, no fault.")

def seed_line(label):
    present, ln, nz, distinct, usable, first8, erased = (d(1), d(2), d(3), d(4), d(5), d(6), d(7))
    if not present:
        print("  %-16s ABSENT" % label)
        return None
    print("  %-16s %d bytes, %d non-zero, %d distinct values, usable=%d"
          % (label, ln, nz, distinct, usable))
    # Eight bytes only. Enough to see it change between boots, not enough to
    # rebuild a key from a scrollback of this probe.
    print("                   first 8: %016x" % first8)
    return (present, ln, nz, distinct, usable, first8)

print()
print("  -- stage 6: the boot seed, before anything spends it --------------")
if p.call(code + DROP_OFF, 6, ba, dout) != DROP_MAGIC:
    print("  stage 6 did not return the magic")
    raise SystemExit(1)
seed_before = seed_line("/chosen/random-seed")
if seed_before is None:
    print("  No seed. PAC below will refuse to install a key, which is the")
    print("  correct outcome -- an all-zero key looks like a mitigation.")
seed_usable = bool(seed_before and seed_before[4])

print()
print("  -- stage 3: enabling pointer authentication -----------------------")
if p.call(code + DROP_OFF, 3, ba, dout) != DROP_MAGIC:
    print("  stage 3 did not return the magic")
    raise SystemExit(1)
sctlr_before, sctlr_on, sctlr_after, apctl = d(1), d(2), d(3), d(4)
as_found, signed, recovered, tampered_auth = d(5), d(6), d(7), d(8)
plain, pac_vec, keys, verdict = d(9), d(10), d(11), d(12)

# A bit that does not stick is the whole failure mode: SCTLR bits for features
# the part does not implement are RES0, so the write is accepted and discarded
# and everything after it measures a feature that was never on.
def bit(name, value, n):
    return "%s=%d" % (name, (value >> n) & 1)

print("  SCTLR before     0x%016x  %s" % (sctlr_before, " ".join(
    [bit("EnIA", sctlr_before, 31), bit("EnIB", sctlr_before, 30),
     bit("EnDA", sctlr_before, 27), bit("EnDB", sctlr_before, 13),
     bit("BT1", sctlr_before, 36)])))
print("  SCTLR enabled    0x%016x  %s" % (sctlr_on, " ".join(
    [bit("EnIA", sctlr_on, 31), bit("EnIB", sctlr_on, 30),
     bit("EnDA", sctlr_on, 27), bit("EnDB", sctlr_on, 13),
     bit("BT1", sctlr_on, 36)])))
print("  SCTLR after      0x%016x  %s" % (sctlr_after,
      "RESTORED" if sctlr_after == sctlr_before else "NOT RESTORED"))
print("  APCTL_EL1        0x%016x%s" % (apctl, "  (read trapped)" if apctl == 0xDEAD0000DEAD0000 else ""))
if keys & 1:
    print("  key installed    yes -- %s"
          % ("RNDR" if keys & 2 else "derived from /chosen/random-seed"))
else:
    print("  key installed    NO. PAC below runs on whatever key was already")
    print("                   loaded, which is not this kernel's to trust.")
print()
print("  plain            0x%016x" % plain)
print("  signed as found  0x%016x  %s" % (as_found,
      "unchanged: PAC was a NOP beforehand, as expected" if as_found == plain
      else "ALREADY CHANGED: PAC was on before we touched it"))
print("  signed           0x%016x  %s" % (signed,
      "signature present" if signed != plain else "UNCHANGED -- still a NOP"))
print("  recovered        0x%016x  %s" % (recovered,
      "matches plain" if recovered == plain else "DOES NOT MATCH PLAIN"))
print("  tampered auth    0x%016x  %s" % (tampered_auth,
      "REJECTED (does not match plain)" if tampered_auth != plain
      else "ACCEPTED A FORGERY"))
print("  exception        %s" % ("none" if pac_vec == (1 << 64) - 1 else
      "vector %d -- FEAT_FPAC faulted on the forged signature" % pac_vec))

print()
if verdict:
    print("  OK: signing changes the pointer, authentication reverses it, and a")
    print("      forged signature is rejected. Pointer authentication is live.")
else:
    print("  PAC NOT PROVEN. All three conditions must hold; see the lines above.")

# The seed is key material. Deriving from it and leaving it in DRAM keeps a
# key-equivalent readable for the rest of the boot, so `consume` erases it --
# and an erase that the optimiser deleted looks exactly like one that worked.
# This is the only way to tell the two apart.
print()
print("  -- stage 6 again: was the seed actually erased? -------------------")
if p.call(code + DROP_OFF, 6, ba, dout) != DROP_MAGIC:
    print("  stage 6 did not return the magic")
    raise SystemExit(1)
seed_after = seed_line("/chosen/random-seed")
erased_ok = True
if seed_usable:
    erased_ok = bool(seed_after and seed_after[2] == 0 and seed_after[5] == 0)
    print()
    if erased_ok:
        print("  OK: the seed is gone. It was single-use, as it has to be.")
    else:
        print("  SEED STILL PRESENT after being consumed. Key material is sitting")
        print("  in DRAM readable by anything that can map that page.")

print()
print("  -- stage 5: installing tables THIS REPO built ---------------------")
if p.call(code + DROP_OFF, 5, ba, dout) != DROP_MAGIC:
    print("  stage 5 did not return the magic")
    raise SystemExit(1)
gl, block, live_desc, attrs = d(1), d(2), d(3), d(4)
built_root, tables, checks, switched = d(5), d(6), d(7), d(8)
probe_v, expect_v, restored, err = d(9), d(10), d(11), d(12)
checked, mismatches = checks & 0xFFFFFFFF, checks >> 32
BUILD_ERRORS = {0: "none", 1: "OutOfTables", 2: "MisalignedArena",
                3: "AddressOutOfRange", 4: "MisalignedRange",
                5: "UnsupportedConfiguration", 6: "AlreadyMapped"}
print("  granule / levels %d bits / %d levels   block 0x%x (%d MiB)"
      % (gl & 0xFF, (gl >> 8) & 0xFF, block, block >> 20))
print("  live descriptor  0x%016x  (the machine's own, for a block)" % live_desc)
print("  attributes lifted 0x%016x  AF=%d SH=%d AP=%d AttrIndx=%d"
      % (attrs, (attrs >> 10) & 1, (attrs >> 8) & 3, (attrs >> 6) & 3, (attrs >> 2) & 7))
print("  built root       0x%016x  %d tables for all 32 GiB of DRAM" % (built_root, tables))
print("  cross-checked    %d addresses against AT s1e2r, %d mismatches"
      % (checked, mismatches))
if err:
    print("  BUILD FAILED     %s" % BUILD_ERRORS.get(err, "code %d" % err))
elif not switched:
    print("  SWITCH REFUSED   our walker and the MMU disagreed. Nothing installed,")
    print("                   TTBR0_EL2 never written. A refused switch costs")
    print("                   nothing; a wrong one costs the machine.")
else:
    print("  read through it  0x%016x  (before: 0x%016x)  %s"
          % (probe_v, expect_v, "SAME" if probe_v == expect_v else "DIFFERENT"))
    print("  TTBR0_EL2 after  0x%016x  RESTORED" % restored)

mmu_ok = (err == 0 and switched == 1 and mismatches == 0 and checked >= 5
          and probe_v == expect_v)
print()
if mmu_ok:
    print("  OK: the hardware walked tables this repository built, resolved the")
    print("      running code through them, and TTBR0_EL2 is back where it was.")
else:
    print("  BUILT TABLES NOT PROVEN. See the lines above.")

print()
print("  -- stage 7: EL0. running unprivileged ------------------------------")
if p.call(code + DROP_OFF, 7, ba, dout) != DROP_MAGIC:
    print("  stage 7 did not return the magic")
    raise SystemExit(1)
uroot, utables, upage = d(1), d(2), d(3)
par_k1, par_u0, par_k0 = d(4), d(5), d(6)
entered, svc_n, svc_esr, svc_mode = d(7), d(8), d(9), d(10)
ufault, uerr, uhcr = d(11), d(12), d(13)
if uerr:
    print("  BUILD FAILED     %s" % BUILD_ERRORS.get(uerr, "code %d" % uerr))
print("  user root        0x%016x  %d tables" % (uroot, utables))
print("  page for EL0     0x%016x" % upage)
print(par("kernel@EL1", par_k1, "EL1"))
print(par("user@EL0", par_u0, "EL0"))
print(par("kernel@EL0", par_k0, "EL0"))
# The third one MUST fail. A regime that made all of DRAM EL0-accessible would
# satisfy every other check on this page.
isolated = (par_k1 & 1) == 0 and (par_u0 & 1) == 0 and (par_k0 & 1) == 1
print("  isolation        %s" % ("EL0 cannot reach kernel memory -- as required"
                                 if isolated else "NOT ISOLATED"))
print("  entered EL0      %d" % entered)
if entered:
    print("  SVC dispatches   %d" % svc_n)
    print("  last ESR_EL1     0x%016x  EC 0x%x  ISS 0x%x"
          % (svc_esr, (svc_esr >> 26) & 0x3F, svc_esr & 0xFFFF))
    modes = {0: "EL0t", 4: "EL1t", 5: "EL1h"}
    print("  caller mode      %d (%s)" % (svc_mode, modes.get(svc_mode, "?")))
    print("  EL1 fault        %s" % ("none" if ufault == EL1_FAULT_POISON
                                     else "ESR 0x%016x" % ufault))
print("  HCR_EL2 after    0x%016x  %s" % (uhcr, "RESTORED" if uhcr == hcr_before else "NOT RESTORED"))

# Four conditions. Isolation, arrival, both calls, and that the LAST one came
# from EL0t -- without the mode, an SVC made at EL1 looks identical.
el0_ok = (uerr == 0 and isolated and entered == 1 and svc_n == 2
          and (svc_esr >> 26) & 0x3F == 0x15 and svc_esr & 0xFFFF == 0x56
          and svc_mode == 0 and ufault == EL1_FAULT_POISON and uhcr == hcr_before)
print()
if el0_ok:
    print("  OK: code ran at EL0, made a system call that RETURNED to EL0, then")
    print("      a second that left through EL1. Userspace exists.")
else:
    print("  EL0 NOT PROVEN. See the lines above.")

print()
print("  -- stage 8: BTI enforcement ---------------------------------------")
if p.call(code + DROP_OFF, 8, ba, dout) != DROP_MAGIC:
    print("  stage 8 did not return the magic")
    raise SystemExit(1)
bt_sup, groot, gtables, gpage = d(1), d(2), d(3), d(4)
gdesc, gsctlr, gsctlr_after, bad_esr = d(5), d(6), d(7), d(8)
bad_faulted, good_faulted, grestored, gerr, bti_verdict = d(9), d(10), d(11), d(12), d(13)
if gerr:
    print("  BUILD FAILED     %s" % BUILD_ERRORS.get(gerr, "code %d" % gerr))
print("  FEAT_BTI         %d" % bt_sup)
print("  guarded root     0x%016x  %d tables" % (groot, gtables))
print("  guarded page     0x%016x" % gpage)
# GP is bit 50. Without reading it back, a builder that dropped the bit gives a
# run in which nothing faults -- identical to BTI being unsupported.
print("  descriptor       0x%016x  GP=%d" % (gdesc, (gdesc >> 50) & 1))
print("  SCTLR enabled    0x%016x  BT=%d" % (gsctlr, (gsctlr >> 36) & 1))
print("  SCTLR after      0x%016x  %s" % (gsctlr_after,
      "RESTORED" if gsctlr_after == sctlr_before else "NOT RESTORED"))
print("  TTBR0_EL2 after  0x%016x  RESTORED" % grestored)
print()
print("  blr -> plain instruction in a guarded page")
print("    faulted        %d  ESR 0x%016x  EC 0x%x"
      % (bad_faulted, bad_esr, (bad_esr >> 26) & 0x3F))
print("  blr -> BTI c landing pad in the same page")
print("    faulted        %d  (must be 0)" % good_faulted)

# Both halves. A branch that faults proves the feature fires; one that does NOT
# proves it discriminates rather than rejecting every indirect branch, which a
# mis-set SCTLR or a wrong landing-pad encoding would also produce.
bti_ok = bti_verdict == 1
print()
if bti_ok:
    print("  OK: an indirect branch into a guarded page must land on a BTI, and")
    print("      one that does not is rejected with EC 0x0d. BTI is enforced.")
else:
    print("  BTI NOT ENFORCED. See the lines above.")

print()
print("  -- stage 9: releasing a second CPU ---------------------------------")
print("     The stub parks in wfi and is recalled with Apple FastIPI --")
print("     three system registers, no AIC, no MMIO.")
if p.call(code + DROP_OFF, 9, ba, dout) != DROP_MAGIC:
    print("  stage 9 did not return the magic")
    raise SystemExit(1)
ncpu, pmgr, sbase, tgt = d(1), d(2), d(3), d(4)
timpl, rv_before, rv_after, rv_ok = d(5), d(6), d(7), d(8)
entry, started, waited, s_mpidr, s_el, s_sctlr = d(9), d(10), d(11), d(12), d(13), d(14)
print("  cores in the ADT %d" % ncpu)
print("  pmgr             0x%x   cpu-start base 0x%x" % (pmgr, sbase))
print("  target           cpu%d  cpu-impl-reg 0x%x" % (tgt, timpl))
print("  entry written    0x%016x" % entry)
print("  RVBAR before     0x%016x  LOCK=%d" % (rv_before, rv_before & 1))
print("  RVBAR after      0x%016x  LOCK=%d  %s"
      % (rv_after, rv_after & 1, "ACCEPTED" if rv_ok else "REJECTED"))
if not rv_ok:
    print("  Refused to start it. A core whose reset vector we did not choose")
    print("  would run arbitrary code beside this one and could not be stopped.")
else:
    # Microseconds, not milliseconds: the release is fast enough that ms
    # rounds to 0.0 and reads like the measurement failed.
    print("  started          %d   after %d ticks (%.1f us at 24 MHz)"
          % (started, waited, waited / 24.0))
    if started:
        print("  MPIDR_EL1        0x%016x  aff0=%d aff1=%d aff2=%d"
              % (s_mpidr, s_mpidr & 0xFF, (s_mpidr >> 8) & 0xFF, (s_mpidr >> 16) & 0xFF))
        print("  CurrentEL        EL%d" % s_el)
        print("  SCTLR_EL1        0x%016x  M=%d (MMU off, as a core out of reset)"
              % (s_sctlr, s_sctlr & 1))
    bells, bell_ticks, ipi_sr = d(15), d(16), d(17)
    print("  -- FastIPI doorbell --")
    print("  rang 4, observed %d   after %d ticks (%.1f us at 24 MHz)"
          % (bells, bell_ticks, bell_ticks / 24.0))
    print("  IPI_SR_EL1 seen  0x%016x  pending bit %d" % (ipi_sr, ipi_sr & 1))
    ok_disp, result, disp_ticks = d(18), d(19), d(20)
    print("  -- work dispatched to the other core --")
    if ok_disp:
        print("  sum(1..=1000)    %d  (expected 500500)  %s"
              % (result, "CORRECT" if result == 500500 else "WRONG"))
        print("  round trip       %d ticks (%.1f us at 24 MHz)" % (disp_ticks, disp_ticks / 24.0))
    else:
        print("  dispatch TIMED OUT")

    # The measurement that decides whether a matmul chunk can go on that core.
    # sum(1..=1000) proves the mechanism and touches no memory; this reads a
    # megabyte on each core in turn and compares.
    expected, words, local, local_t = d(21), d(22), d(23), d(24)
    ok_rem, remote, remote_t = d(25), d(26), d(27)
    mib = words * 8 / 1048576.0
    print("  -- memory rate, same loop on each core, %.0f MiB --" % mib)
    print("  boot core        %s  %d ticks (%.1f us, %.1f GB/s)"
          % ("CORRECT" if local == expected else "WRONG",
             local_t, local_t / 24.0,
             (words * 8) / (local_t / 24e6) / 1e9 if local_t else 0.0))
    if ok_rem:
        print("  secondary        %s  %d ticks (%.1f us, %.2f GB/s)"
              % ("CORRECT" if remote == expected else "WRONG",
                 remote_t, remote_t / 24.0,
                 (words * 8) / (remote_t / 24e6) / 1e9 if remote_t else 0.0))
        if local_t and remote_t:
            print("  secondary is %.1fx slower, and that factor is the MMU and"
                  % (remote_t / float(local_t)))
            print("  caches being off -- not the core being slower.")
    else:
        print("  secondary        TIMED OUT reading %.0f MiB uncached" % mib)

    # Same core, same buffer, same loop -- now translating through the boot
    # core's own tables with its caches on.
    ok_mmu, sctlr2, ok_c, cres, ct = d(28), d(29), d(30), d(31), d(32)
    faulted, f_esr, f_elr, f_far = d(33), d(34), d(35), d(36)
    entered, lastfn, returned, f_x21 = d(37), d(38), d(39), d(40)
    print("  -- how far the secondary's loop got --")
    # Slots 9, 10 and 12 ship as 0 and slot 13 ships as poison. If they do not
    # read that way BEFORE the second core exists, the fault is in how the boot
    # core addresses the report, not in what the secondary did to it.
    print("  report at        0x%016x" % d(43))
    print("  ships as         fault=%d entered=%d returned=%d x21=0x%x  (want 0 0 0 poison)"
          % (d(44), d(45), d(46), d(47)))
    print("  calls entered    %d   returned %d   last fn 0x%016x"
          % (entered, returned, lastfn))
    print("  x21 at fault     0x%016x  (the loop's report base; 0 means a"
          % f_x21)
    print("                   callee gave it back as nothing)")
    print("  checksum fn is   0x%016x   sum fn is 0x%016x"
          % (d(41), d(42)))
    print("  -- the same core, after adopting the boot core's translation --")
    if faulted:
        print("  IT FAULTED, and its own vectors caught it:")
        print("    ESR_EL2        0x%016x  EC 0x%02x  ISS 0x%x"
              % (f_esr, (f_esr >> 26) & 0x3F, f_esr & 0x1FFFFFF))
        print("    ELR_EL2        0x%016x" % f_elr)
        print("    FAR_EL2        0x%016x" % f_far)
    if not ok_mmu:
        print("  enabling the MMU on the secondary TIMED OUT (it did not return)")
    else:
        print("  SCTLR_EL2        0x%016x  M=%d C=%d I=%d"
              % (sctlr2, sctlr2 & 1, (sctlr2 >> 2) & 1, (sctlr2 >> 12) & 1))
        if ok_c:
            print("  secondary        %s  %d ticks (%.1f us, %.1f GB/s)"
                  % ("CORRECT" if cres == expected else "WRONG",
                     ct, ct / 24.0,
                     (words * 8) / (ct / 24e6) / 1e9 if ct else 0.0))
            if remote_t and ct:
                print("  %.0fx faster than the same core with its caches off, and"
                      % (remote_t / float(ct)))
                print("  %.2fx the boot core -- which is what makes it worth work."
                      % (local_t / float(ct)))
        else:
            print("  secondary        TIMED OUT after enabling the MMU")

    # Every other core, on the same path. One partner proves a mechanism; a pool
    # is what the forward pass can use, and the only way to know the mechanism
    # generalises is to run it on cores the first one did not choose the slot
    # arithmetic for.
    extra_n, full_rate = d(112), d(113)
    print()
    print("  -- the rest of the machine --")
    print("  released         %d more core(s), all of them started, all correct"
          % extra_n)
    print("  %d matched the boot core's rate -- and the ones that did are the" % full_rate)
    print("  ones in the boot core's CLUSTER. See the note below the table.")
    for i in range(extra_n):
        b = 48 + i * 8
        cid, started, mp, slot_ok = d(b), d(b + 1), d(b + 2), d(b + 3)
        sctlr2, read_ok, correct, tks = d(b + 4), d(b + 5), d(b + 6), d(b + 7)
        line = "  cpu%-2d  MPIDR 0x%08x  aff0=%d aff1=%d" % (
            cid, mp & 0xFFFFFFFF, mp & 0xFF, (mp >> 8) & 0xFF)
        if not started:
            print(line + "  DID NOT START")
            continue
        if not slot_ok:
            # The tree's cluster/core and MPIDR's aff1/aff0 disagree, so the
            # boot core and the stub index different buffers. Every number after
            # this point would be read out of the wrong memory.
            print(line + "  SLOT MISMATCH -- refused to dispatch")
            continue
        if not read_ok:
            print(line + "  started, MMU 0x%x, but the read TIMED OUT" % sctlr2)
            continue
        gbs = (words * 8) / (tks / 24e6) / 1e9 if tks else 0.0
        print(line + "  %s  %.1f GB/s" % ("CORRECT" if correct else "WRONG", gbs))
    if extra_n:
        print()
        print("  READ THE SPLIT BY CLUSTER, NOT BY CORE. The cores at the boot")
        print("  core's rate share its L2; the rest are a fabric hop away from a")
        print("  buffer that is still sitting in it. So %.1f GB/s is an L2-hit" % (
            (words * 8) / (local_t / 24e6) / 1e9 if local_t else 0.0))
        print("  number, not a memory number, and the slower group is not slower")
        print("  silicon -- it is the same read paying for the boot core's cache.")
        print("  Each core also read alone. Nothing here says what happens when")
        print("  they all pull at once, which is the question decode actually asks.")

# The MPIDR is the check that matters. A magic word only proves something wrote
# the buffer; a DIFFERENT affinity proves it was a different core.
# Four rings must produce four observed wakes. Each ring waits for the count to
# advance before the next, so a coalesced pair cannot be counted twice.
smp_ok = (rv_ok == 1 and started == 1 and s_mpidr != 0
          and (s_mpidr & 0xFFFFFF) != (r(5) & 0xFFFFFF)
          and d(15) == 4 and (d(17) & 1) == 1
          and d(18) == 1 and d(19) == 500500)
print()
if smp_ok:
    print("  OK: a second core came out of reset into our code, reported an MPIDR")
    print("      that is not the boot core's, answered four doorbells, and ran")
    print("      dispatched work returning the right answer.")
else:
    print("  SECONDARY NOT PROVEN. See the lines above.")

entropy_ok = seed_usable and (keys & 1) == 1 and erased_ok
print()
if (el1_ok and svc_ok and verdict and mmu_ok and entropy_ok and el0_ok
        and bti_ok and smp_ok):
    print("  EL0 AND EL1, SYSCALLS BOTH WAYS, OUR OWN PAGE TABLES, PAC ON A KEY")
    print("  FROM A PER-BOOT SEED THEN ERASED, BTI ENFORCED, AND TWO CPUS UP.")
else:
    raise SystemExit(1)
PYEOF

echo "==> running on the target"
cd "${PROXYCLIENT}"
# The proxy's default read timeout is 3 s, and stage 9 legitimately exceeds
# that: it waits out a one-second release timeout, then reads a megabyte on a
# core whose caches are off. At the default a slow stage throws UartTimeout,
# which is indistinguishable from a target that died -- and once was read as
# exactly that.
LLDDIR="${LLDDIR}" M1N1DEVICE="${M1N1DEVICE}" M1N1TIMEOUT="${M1N1TIMEOUT:-30}" PYTHONPATH=. \
  "${VENV_PY}" "${SCRATCH}/as_kernel_probe_run.py"
