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

echo "[test.sh] Creating GRUB2 ISO directory structure..."
rm -rf iso
mkdir -p iso/boot/grub
cp target/x86_64-unknown-none/release/brainix-bootloader iso/boot/

echo "[test.sh] Writing grub.cfg..."
cat > iso/boot/grub/grub.cfg << 'GRUBEOF'
set timeout=0
menuentry "BraiNIX" {
    multiboot2 /boot/brainix-bootloader
    boot
}
GRUBEOF

echo "[test.sh] Building GRUB2 ISO with grub-mkrescue..."
grub-mkrescue -o brainix.iso iso/

echo "[test.sh] Provisioning swtpm for Phase 6 attestation test..."
mkdir -p /tmp/brainix-tpm
swtpm_setup \
    --tpmstate /tmp/brainix-tpm \
    --tpm2 \
    --createek \
    --overwrite \
    2>/dev/null || echo "[test.sh] WARN: swtpm_setup failed (swtpm not installed; attestation skipped)"

if command -v swtpm &>/dev/null && [ -f /tmp/brainix-tpm/tpm2-00.permall ]; then
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

echo "[test.sh] Booting GRUB2 ISO in QEMU (30s timeout)..."
# shellcheck disable=SC2086
timeout 30 qemu-system-x86_64 \
    -cdrom brainix.iso \
    -nographic \
    -serial stdio \
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
