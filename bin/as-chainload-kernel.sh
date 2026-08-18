#!/bin/bash
#
# Chainload the BraiNIX kernel on the mini and measure whether it ran.
#
#   ./bin/as-chainload-kernel.sh
#
# WHAT THIS IS FOR
#
# The goal is BraiNIX running with m1n1 out of the loop. Installing it as the
# boot object needs recoveryOS, which needs the power button held, which needs
# somebody in the room. A chainload does not: m1n1 shuts its own MMU down and
# jumps to the payload with `x0` holding the boot_args pointer, at EL2, with the
# MMU off -- which is the entry state iBoot gives a custom boot object. So this
# is a faithful rehearsal of the install, available over the wire, and it
# exercises exactly the code the install would.
#
# THE MACHINE HAS NO OUTPUT DEVICE, SO THE MEASUREMENT IS THE CLOCK
#
# Chainloading destroys m1n1, and with it the only working console on this rig:
# the SBU serial path delivers zero bytes (runbook 9a, measured with m1n1's own
# output too) and the framebuffer handed to a custom boot object is a dummy that
# is never scanned out (runbook 9). A chainloaded payload that hangs and a
# chainloaded payload that was never entered produce the same silence.
#
# So the kernel arms the watchdog before parking, and this script times the
# reset. The USB device disappearing is the signal:
#
#   reset ~LIVENESS_SECONDS after handover  -> the kernel ran, reached the end
#                                              of _start, parsed the device
#                                              tree, found the watchdog, and
#                                              armed it
#   no reset at all                         -> it did not get that far
#   reset much sooner                       -> it faulted into something that
#                                              reset the machine on its own
#
# One bit, plus a duration. That is more than silence, which is the only other
# thing on offer.
#
# RECOVERY
#
# Chainloading always destroys m1n1. Whatever happens, the machine is brought
# back with `macvdmtool reboot`, which this script does at the end, so the next
# run starts from a known state.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
SCRATCH="${BRAINIX_SCRATCH:-/private/tmp/claude-501/-Users-jbrahy-OtherProjects-brainix/3aab4a38-fd47-451e-9a65-11f8a595da95/scratchpad}"
PROXYCLIENT="${M1N1_PROXYCLIENT:-${SCRATCH}/m1n1-1.6.1/proxyclient}"
VENV_PY="${M1N1_VENV_PY:-${SCRATCH}/m1n1-venv/bin/python}"
MACVDM="${MACVDM:-/Users/jbrahy/OtherProjects/_tools/macvdmtool/macvdmtool}"
# m1n1 assembles its handover stub at run time and links it with ld.lld, which
# it looks for at a hardcoded Homebrew path that does not exist here. The shim
# points at rustup's rust-lld. Without it the chainload dies with exit 127
# BEFORE handover, which the reset watcher below correctly reports as "no
# reset" -- an accurate verdict about a test that never ran.
LLDDIR="${LLDDIR:-${SCRATCH}/lldshim/}"

TOOLCHAIN="nightly-2025-12-01"
TARGET="aarch64-unknown-none-softfloat"
TOOLCHAIN_BIN="${HOME}/.rustup/toolchains/${TOOLCHAIN}-aarch64-apple-darwin/bin"
ELF="${REPO}/target/${TARGET}/release/brainix"
BIN="${SCRATCH}/brainix-kernel-boot.bin"

# What the kernel's `_start` arms the watchdog for. Kept in step with
# LIVENESS_SECONDS in src/kernel/src/main.rs by this comment and nothing else,
# so if that constant moves, move this one.
EXPECT_SECONDS=5

die() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }

[[ -x "${TOOLCHAIN_BIN}/cargo" ]] || die "pinned toolchain missing at ${TOOLCHAIN_BIN}"
[[ -d "${PROXYCLIENT}" ]] || die "m1n1 proxyclient not at ${PROXYCLIENT}"
[[ -x "${VENV_PY}" ]] || die "no venv python at ${VENV_PY}"
[[ -x "${MACVDM}" ]] || die "macvdmtool not at ${MACVDM}"
[[ -x "${LLDDIR}ld.lld" ]] || die "no ld.lld shim at ${LLDDIR} -- m1n1 needs it to assemble its handover stub"

# --- build, WITHOUT smp-bench -------------------------------------------------
# The boot image must not carry the 64 MiB measurement buffer: .bss is zeroed
# past the load address, and nothing has reserved that memory here. See the
# feature's note in src/kernel/Cargo.toml.
echo "==> building the kernel as a boot object (no smp-bench)"
cd "${REPO}/src/kernel"
RUSTC="${TOOLCHAIN_BIN}/rustc" RUSTDOC="${TOOLCHAIN_BIN}/rustdoc" \
  "${TOOLCHAIN_BIN}/cargo" build --target "${TARGET}" --features kernel-binary --release \
  >/dev/null || die "kernel build failed; run it directly for the reason"

OBJCOPY="$(find "${HOME}/.rustup/toolchains" -name llvm-objcopy 2>/dev/null | head -1)"
NM="$(find "${HOME}/.rustup/toolchains" -name llvm-nm 2>/dev/null | head -1)"
[[ -n "${OBJCOPY}" && -n "${NM}" ]] || die "no llvm-objcopy/llvm-nm in the rustup toolchains"
"${OBJCOPY}" -O binary "${ELF}" "${BIN}"

# Entry MUST be at offset 0, and it must be the assembly shim rather than a Rust
# function whose prologue uses a stack pointer nobody set. Checking it here
# because getting it wrong is this project's single most expensive mistake:
# m1n1 was once installed at entry 0, never ran, and was judged useless.
START_ADDR="$("${NM}" "${ELF}" | awk '/ T _start$/ {print $1}')"
[[ "${START_ADDR}" == "0000000000000000" ]] || die "_start is at 0x${START_ADDR}, not 0 -- the image cannot be entered"

# .bss is zeroed past the load address by the kernel itself, so its size is a
# blast radius, not an implementation detail.
BSS_END="$("${NM}" "${ELF}" | awk '/ B __bss_end$/ {print $1}')"
printf '    image %s bytes, footprint through .bss 0x%s\n' \
  "$(wc -c < "${BIN}" | tr -d ' ')" "${BSS_END}"

# --- get m1n1 up --------------------------------------------------------------
# Always from a fresh boot. m1n1 that has already had a payload called into it
# is not a known state, and a stale one is how a run gets diagnosed against the
# wrong image.
echo "==> rebooting the mini into m1n1"
sudo -n "${MACVDM}" reboot >/dev/null 2>&1 || die "macvdmtool reboot failed (needs passwordless sudo)"

echo "==> waiting for a port that answers"
DEVICE=""
for _ in $(seq 1 60); do
  sleep 1
  for candidate in /dev/cu.usbmodem*; do
    [[ -e "${candidate}" ]] || continue
    # m1n1 flushes its buffered boot log when the port is opened, so a couple of
    # bytes is a positive identification. Three of the four nodes never answer
    # and look exactly like a wedged machine (runbook, and the probe script).
    if [[ -n "$(timeout 2 head -c 64 "${candidate}" 2>/dev/null | tr -d '\0')" ]]; then
      DEVICE="${candidate}"
      break 2
    fi
  done
done
[[ -n "${DEVICE}" ]] || die "no /dev/cu.usbmodem* answered within 60s"
echo "    device: ${DEVICE}"

# --- hand over ----------------------------------------------------------------
echo "==> chainloading (this destroys m1n1)"
HANDOVER_EPOCH="$(date +%s)"
cd "${PROXYCLIENT}"
# --raw       : a flat image, not a Mach-O
# -E 0        : our entry point, from payloads.tsv. m1n1's own is 2048 and the
#               two must never be copied from one another.
# --call      : shuts the MMU down and jumps, rather than reloading m1n1's
#               stage. This is the path that reproduces iBoot's entry state.
LLDDIR="${LLDDIR}" M1N1DEVICE="${DEVICE}" PYTHONPATH=. timeout 120 "${VENV_PY}" tools/chainload.py \
  --raw -E 0 --call "${BIN}" 2>&1 | tail -12 || true

# --- measure ------------------------------------------------------------------
# From here the machine has no console. The only thing it can say is whether it
# resets, and when.
echo "==> watching for the reset (up to 60s)"
GONE_AT=""
BACK_AT=""
for _ in $(seq 1 120); do
  sleep 0.5
  NOW="$(date +%s)"
  if [[ -z "${GONE_AT}" ]]; then
    # Every port gone means the machine dropped off the bus, which is what a
    # reset looks like from here.
    if ! ls /dev/cu.usbmodem* >/dev/null 2>&1; then
      GONE_AT="${NOW}"
      echo "    port disappeared at +$((GONE_AT - HANDOVER_EPOCH))s"
    fi
  elif ls /dev/cu.usbmodem* >/dev/null 2>&1; then
    BACK_AT="${NOW}"
    echo "    port returned at    +$((BACK_AT - HANDOVER_EPOCH))s"
    break
  fi
done

echo
echo "=============================== VERDICT ==============================="
if [[ -z "${GONE_AT}" ]]; then
  echo "  NO RESET. The machine never left the bus."
  echo
  echo "  The kernel either was not entered, or did not reach the end of"
  echo "  _start. It cannot say which, because it has no output device --"
  echo "  that is the whole reason the watchdog is the signal."
else
  ELAPSED=$((GONE_AT - HANDOVER_EPOCH))
  echo "  RESET at +${ELAPSED}s after handover (expected about ${EXPECT_SECONDS}s)."
  echo
  if (( ELAPSED >= EXPECT_SECONDS - 3 && ELAPSED <= EXPECT_SECONDS + 8 )); then
    echo "  THE KERNEL RAN WITH M1N1 GONE. To reset on that cadence it had to"
    echo "  be entered at offset 0, establish a stack, zero .bss, parse the"
    echo "  boot_args firmware handed it, walk the device tree to /arm-io/wdt,"
    echo "  translate its reg through /arm-io's ranges, and write the alarm."
  else
    echo "  Reset, but not on our cadence. Either the watchdog counts at a"
    echo "  different rate than the system counter -- in which case"
    echo "  ${ELAPSED}/${EXPECT_SECONDS} is the ratio and that is a"
    echo "  measurement -- or something else reset the machine."
  fi
fi
echo "======================================================================="

# --- leave it usable ----------------------------------------------------------
echo
echo "==> returning the mini to m1n1"
sudo -n "${MACVDM}" reboot >/dev/null 2>&1 || echo "    macvdmtool reboot failed; recover by hand"
