#!/usr/bin/env bash
# docker/test.sh — Local GRUB2 ISO boot test for BraiNIX
#
# Mirrors the CI integration-test job (ci.yml integration-test job).
# Run this script from the repository root inside the dev container.
#
# Per D-07: GRUB2 loads the bootloader binary, not -kernel with raw ELF.
# Per D-10: asserts "BraiNIX: boot complete" in serial output.

set -euo pipefail

REPOSITORY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPOSITORY_ROOT}"

# Non-interactive SSH sessions (e.g. ssh host "cmd") do not source ~/.bashrc or
# ~/.profile, so ~/.cargo/bin is absent from PATH. Add it explicitly if it exists.
if [[ -d "${HOME}/.cargo/bin" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

# Ensure the nightly Rust toolchain (pinned in rust-toolchain.toml) takes
# precedence over any system cargo/rustc (e.g. Homebrew on macOS). The
# toolchain is discovered from rust-toolchain.toml; if rustup is not on PATH
# at all, bare `cargo` is used and will fail with a clear error.
if command -v rustup &>/dev/null; then
    TOOLCHAIN_CHANNEL=$(grep '^channel' rust-toolchain.toml | sed 's/.*"\(.*\)"/\1/')
    TOOLCHAIN_DIR="$(rustup toolchain list --verbose 2>/dev/null \
        | grep "^${TOOLCHAIN_CHANNEL}" | awk '{print $NF}' | head -1)"
    if [[ -n "${TOOLCHAIN_DIR}" && -d "${TOOLCHAIN_DIR}/bin" ]]; then
        export PATH="${TOOLCHAIN_DIR}/bin:${PATH}"
    fi
fi

echo "[test.sh] Building kernel..."
cargo build --target x86_64-unknown-none --release \
    --manifest-path src/kernel/Cargo.toml

echo "[test.sh] Building bootloader..."
cargo build -p brainix-bootloader --target x86_64-unknown-none --release

echo "[test.sh] Building shell binary..."
cargo build -p brainix-shell --target x86_64-unknown-none --release

echo "[test.sh] Building kernel binary (requires --features kernel-binary,dev-build)..."
# dev-build enables the attestation-gate warn-and-continue path so the
# integration test can complete without a fully provisioned vTPM.
cargo build --features kernel-binary,dev-build -p brainix-kernel --target x86_64-unknown-none --release

echo "[test.sh] Creating GRUB2 ISO directory structure..."
rm -rf iso
mkdir -p iso/boot/grub
cp target/x86_64-unknown-none/release/brainix-bootloader iso/boot/
cp target/x86_64-unknown-none/release/brainix iso/boot/kernel.elf
cp target/x86_64-unknown-none/release/brainix-shell iso/boot/shell.elf

echo "[test.sh] Writing grub.cfg..."
# NOTE on `module2` vs `module`: with multiboot2, GRUB's `module` command
# tries to load a Multiboot 1 module (and silently fails with
# "you need to load the kernel first"). `module2` is the multiboot2 module
# command. This distinction was confirmed via `set debug=all` which showed
# `module` loaded GRUB's multiboot.mod (multiboot1) instead of the
# already-loaded multiboot2 context. Discovered 2026-04-20.
cat > iso/boot/grub/grub.cfg << 'GRUBEOF'
set timeout=0
menuentry "BraiNIX" {
    multiboot2 /boot/brainix-bootloader
    module2 /boot/kernel.elf kernel
    module2 /boot/shell.elf shell
    boot
}
GRUBEOF

echo "[test.sh] Building GRUB2 ISO with grub-mkrescue..."
grub-mkrescue -o brainix.iso iso/

echo "[test.sh] Provisioning swtpm for Phase 6 attestation test..."
rm -rf /tmp/brainix-tpm
mkdir -p /tmp/brainix-tpm
SWTPM_READY=0
if timeout 10 swtpm_setup \
    --tpmstate /tmp/brainix-tpm \
    --tpm2 \
    --createek \
    --overwrite \
    2>/dev/null; then
    SWTPM_READY=1
else
    echo "[test.sh] WARN: swtpm_setup failed (swtpm not installed; attestation skipped)"
fi

if [ "${SWTPM_READY}" -eq 1 ] && command -v swtpm &>/dev/null; then
    swtpm socket \
        --tpmstate dir=/tmp/brainix-tpm \
        --ctrl type=unixio,path=/tmp/brainix-tpm/swtpm.sock \
        --tpm2 \
        --log level=0 &
    SWTPM_PID=$!
    echo "[test.sh] swtpm started (PID ${SWTPM_PID})"

    # Provision monotonic counter NV index (0x01500001 per D-21)
    tpm2_nvdefine 0x01500001 \
        --size 8 \
        --attributes "nt=counter|ownerread|ownerwrite" \
        --tcti "swtpm:path=/tmp/brainix-tpm/swtpm.sock" \
        2>/dev/null || true

    QEMU_TPM_ARGS="-chardev socket,id=chrtpm,path=/tmp/brainix-tpm/swtpm.sock \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0"
else
    SWTPM_PID=""
    QEMU_TPM_ARGS=""
    echo "[test.sh] swtpm not available; running without TPM device"
fi

echo "[test.sh] Creating GRUB2 memdisk boot image..."
# Embed the bootloader binary directly into the GRUB2 core image as a memdisk
# (tar archive served from RAM). This avoids all BIOS CD-ROM disk reads after
# core.img loads — GRUB finds grub.cfg and the bootloader in RAM instantly.
# Required because TCG+Rosetta makes BIOS INT 13h CD-ROM reads prohibitively slow.
MEMDISK_DIR=/tmp/brainix-memdisk
rm -rf "${MEMDISK_DIR}"
mkdir -p "${MEMDISK_DIR}/boot/grub"
cp target/x86_64-unknown-none/release/brainix-bootloader "${MEMDISK_DIR}/boot/"
cat > "${MEMDISK_DIR}/boot/grub/grub.cfg" << 'GRUBCFGEOF'
set timeout=0
menuentry "BraiNIX" {
    multiboot2 (memdisk)/boot/brainix-bootloader
    boot
}
GRUBCFGEOF

tar -C "${MEMDISK_DIR}" -cf /tmp/brainix-memdisk.tar .

GRUB_LIB=/usr/lib/grub/i386-pc
grub-mkimage \
    --directory="${GRUB_LIB}" \
    --format=i386-pc \
    --output=/tmp/brainix-core.img \
    --prefix='(memdisk)/boot/grub' \
    --memdisk=/tmp/brainix-memdisk.tar \
    memdisk tar biosdisk multiboot2 normal echo

# Assemble bootable disk: boot.img (MBR) at sector 0, core.img at sector 1.
# boot.img's core.img sector reference lives at byte offset 92 (little-endian u32).
dd if=/dev/zero of=brainix-boot.img bs=512 count=16384 2>/dev/null
dd if="${GRUB_LIB}/boot.img" of=brainix-boot.img bs=512 count=1 conv=notrunc 2>/dev/null
printf '\x01\x00\x00\x00' | dd of=brainix-boot.img bs=1 seek=92 count=4 conv=notrunc 2>/dev/null
dd if=/tmp/brainix-core.img of=brainix-boot.img bs=512 seek=1 conv=notrunc 2>/dev/null

echo "[test.sh] Booting BraiNIX via hybrid ISO as hard disk in QEMU (300s timeout)..."
# brainix.iso is a hybrid image (boot_hybrid.img MBR) — bootable as hard disk too.
# Presenting it as an IDE hard drive avoids the slow CD-ROM emulation path; the
# embedded MBR boots GRUB2 the same way a real hybrid USB drive would.
#
# Networking:
#   -netdev user,id=net0           — user-mode (slirp) networking, no root needed
#   -device e1000,netdev=net0,mac=… — Intel e1000 NIC, fixed MAC for repeatable hashes
#   -object filter-dump,…           — captures all guest network frames to a pcap
# Inspect after boot:  tshark -r /tmp/qemu-net.pcap   or   tcpdump -nnXr /tmp/qemu-net.pcap
# shellcheck disable=SC2086
rm -f /tmp/qemu-net.pcap
# Set QEMU_NO_NET=1 to omit the guest NIC entirely (useful when debugging
# the boot chain without a network stack on the bus).
if [[ "${QEMU_NO_NET:-0}" == "1" ]]; then
    QEMU_NET_ARGS=""
else
    # hostfwd forwards container-localhost:2222 -> guest:2222 so the inbound
    # TCP/SSH service can be reached from the test harness.
    QEMU_NET_ARGS="-netdev user,id=net0,hostfwd=tcp::2222-:2222 \
        -device e1000,netdev=net0,mac=52:54:00:12:34:56 \
        -object filter-dump,id=net0,netdev=net0,file=/tmp/qemu-net.pcap"
fi

# Background inbound-connectivity probe: once the guest's network service is up,
# connect to the forwarded port and exchange a line, proving the inbound TCP
# server datapath. Result is written for printing after QEMU exits.
rm -f /tmp/inbound_tcp_result.txt
(
    sleep 75
    probe_payload="brainix-inbound-probe"
    if command -v nc >/dev/null 2>&1; then
        reply="$(printf '%s\n' "${probe_payload}" | timeout 8 nc -w 5 127.0.0.1 2222 2>/dev/null | head -c 100)"
    else
        reply="$(printf '%s\n' "${probe_payload}" | timeout 8 python3 -c 'import socket,sys; s=socket.create_connection(("127.0.0.1",2222),5); s.sendall(sys.stdin.buffer.read()); s.settimeout(4); print(s.recv(100).decode("latin1"),end="")' 2>/dev/null)"
    fi
    printf 'INBOUND_TCP_SENT: %s\nINBOUND_TCP_REPLY: %s\n' "${probe_payload}" "${reply}" > /tmp/inbound_tcp_result.txt
) &
# Honor KEEP_RUNNING=1 (set by bin/run-brainx.sh in its default "always have
# the latest version running" mode): omit the 300s `timeout` wrapper so qemu
# stays alive after the kernel reaches its halt loop, until the user
# interrupts (Ctrl-A X for the qemu monitor, or Ctrl-C from the host).
# CI / one-shot mode keeps the 300s bound so a stuck boot can't hang a job.
if [[ "${KEEP_RUNNING:-0}" == "1" ]]; then
    QEMU_TIMEOUT_CMD=()
else
    QEMU_TIMEOUT_CMD=(timeout 300)
fi
# Persistent writable data disk (16 MiB) for credential/filesystem storage.
# Created once and reused across boots so on-disk state survives a reboot —
# this is what lets a changed password persist (the disk+FS milestone). The
# driver will live in the devd-disk userspace server (virtio-blk over PCI).
BRAINIX_DATA_DISK="${REPOSITORY_ROOT}/brainix-disk.img"
if [[ ! -f "${BRAINIX_DATA_DISK}" ]]; then
    echo "[test.sh] Creating persistent 16 MiB data disk (brainix-disk.img)..."
    dd if=/dev/zero of="${BRAINIX_DATA_DISK}" bs=1M count=16 2>/dev/null
fi
# shellcheck disable=SC2086
"${QEMU_TIMEOUT_CMD[@]}" qemu-system-x86_64 \
    -drive file=brainix.iso,format=raw,if=ide \
    -drive file="${BRAINIX_DATA_DISK}",format=raw,if=none,id=bxdata \
    -device virtio-blk-pci,drive=bxdata \
    -boot order=c \
    -nographic \
    -machine q35,accel=tcg \
    -cpu qemu64,+smep,+smap,+rdrand,+rdseed \
    -m 512M \
    ${QEMU_NET_ARGS} \
    ${QEMU_TPM_ARGS} \
    2>&1 | tee /tmp/boot.log || true

echo "[test.sh] === INBOUND TCP PROBE ==="
wait
cat /tmp/inbound_tcp_result.txt 2>/dev/null || echo "no inbound result"
echo "[test.sh] === END INBOUND TCP PROBE ==="

echo "[test.sh] Asserting boot completion..."
BOOT_PASS=0
if grep -q "BraiNIX: boot complete" /tmp/boot.log; then
    BOOT_PASS=1
fi

if [ -n "${SWTPM_PID}" ]; then
    echo "[test.sh] Reading PCR values from swtpm..."
    tpm2_pcrread sha256:0,1,2 \
        --tcti "swtpm:path=/tmp/brainix-tpm/swtpm.sock" \
        2>/dev/null || true

    echo "[test.sh] Cleaning up swtpm (PID ${SWTPM_PID})..."
    kill "${SWTPM_PID}" 2>/dev/null || true
    rm -rf /tmp/brainix-tpm
fi

if [ "${BOOT_PASS}" -eq 1 ]; then
    echo "[test.sh] PASS: kernel booted successfully via GRUB2 ISO"
    exit 0
else
    echo "[test.sh] FAIL: 'BraiNIX: boot complete' not found in serial output"
    echo "[test.sh] --- boot log ---"
    cat /tmp/boot.log
    echo "[test.sh] ---------------"
    exit 1
fi
