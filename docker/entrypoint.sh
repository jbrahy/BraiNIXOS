#!/usr/bin/env bash
# Container entrypoint — starts SSH, optionally starts QEMU serial bridge.
set -euo pipefail

# Ensure SSH host keys exist
ssh-keygen -A

# Start SSH daemon in the background
/usr/sbin/sshd

echo "Brainix dev container ready."
echo "SSH listening on port 22 (mapped to 2222 on host)."

# If a kernel binary was built, launch QEMU with serial-over-TCP on port 4444.
# This path is exercised from Phase 1 onward once a _start entry point exists.
KERNEL=/home/dev/brainix/target/x86_64-unknown-none/release/brainix-kernel

if [[ -f "$KERNEL" ]]; then
    echo "Kernel binary found — starting QEMU. Serial console on port 4444."
    exec qemu-system-x86_64 \
        -machine q35,accel=tcg \
        -cpu qemu64,+smep,+smap \
        -m 512M \
        -nographic \
        -serial tcp::4444,server,nowait \
        -kernel "$KERNEL" \
        -append "smt=off"
else
    echo "No kernel binary at ${KERNEL} — QEMU not started."
    echo "Build one first:  cargo build --release --target x86_64-unknown-none -p brainix-kernel"
    # Keep container alive so SSH remains reachable
    exec tail -f /dev/null
fi
