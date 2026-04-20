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

echo "[test.sh] Building kernel binary (requires --features kernel-binary)..."
cargo build --features kernel-binary -p brainix-kernel --target x86_64-unknown-none --release

echo "[test.sh] Creating GRUB2 ISO directory structure..."
rm -rf iso
mkdir -p iso/boot/grub
cp target/x86_64-unknown-none/release/brainix-bootloader iso/boot/
cp target/x86_64-unknown-none/release/brainix iso/boot/kernel.elf
cp target/x86_64-unknown-none/release/brainix-shell iso/boot/shell.elf

echo "[test.sh] Writing grub.cfg..."
# Note: as of 2026-04-20, GRUB 2.06's multiboot2 command validates the
# brainix-bootloader header successfully via `grub-file --is-x86-multiboot2`
# but at boot time fails silently — subsequent `module` and `boot` commands
# report "you need to load the kernel first". Root cause not yet identified;
# suspects are (1) segment load address conflicting with GRUB's working RAM,
# (2) an address-tag expectation specific to GRUB 2.06 that the minimal
# multiboot2 header does not satisfy. Tracked as follow-up.
cat > iso/boot/grub/grub.cfg << 'GRUBEOF'
set timeout=0
menuentry "BraiNIX" {
    multiboot2 /boot/brainix-bootloader
    module /boot/kernel.elf
    module /boot/shell.elf
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
# shellcheck disable=SC2086
timeout 300 qemu-system-x86_64 \
    -drive file=brainix.iso,format=raw,if=ide \
    -boot order=c \
    -nographic \
    -machine q35,accel=tcg \
    -cpu qemu64,+smep,+smap \
    -m 512M \
    ${QEMU_TPM_ARGS} \
    2>&1 | tee /tmp/boot.log || true

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
