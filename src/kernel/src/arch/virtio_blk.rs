//! Minimal polled virtio-blk driver over the legacy PCI I/O interface.
//!
//! Scope and rationale: the kernel needs trustworthy access to a small,
//! security-critical region of disk to persist the authentication credential
//! store (the auth TCB). Rather than trust an untrusted userspace disk driver
//! for credentials, the kernel reads/writes the credential block itself. Bulk,
//! general-purpose disk I/O for userspace remains the job of the devd-disk
//! server; this driver is intentionally tiny and TCB-scoped.
//!
//! Interrupts are never used (userspace runs IF-masked under KPTI, and the
//! kernel polls): block requests complete by spinning on the used ring.
//!
//! This sub-step implements device discovery + the reset/feature handshake +
//! reading the device capacity. The single-request virtqueue path (actual
//! sector read/write) builds on this.
//!
//! Allowlist: `src/kernel/src/arch/` — port I/O has no safe Rust interface.
#![allow(unsafe_code)]

use crate::arch::pci::{find_device, VIRTIO_PCI_VENDOR_ID};

/// PCI device ID of the transitional virtio-blk device (legacy interface).
const VIRTIO_BLK_TRANSITIONAL_DEVICE_ID: u16 = 0x1001;

// Legacy virtio PCI I/O register offsets (relative to BAR0 base, MSI-X absent).
const REGISTER_DEVICE_FEATURES: u16 = 0x00;
const REGISTER_DRIVER_FEATURES: u16 = 0x04;
const REGISTER_DEVICE_STATUS: u16 = 0x12;
/// virtio-blk device-specific config begins here; `capacity` (u64, in 512-byte
/// sectors) is at offset 0 of that region.
const REGISTER_BLOCK_CAPACITY_LOW: u16 = 0x14;
const REGISTER_BLOCK_CAPACITY_HIGH: u16 = 0x18;

// Device status bits (virtio spec §2.1).
const STATUS_RESET: u8 = 0x00;
const STATUS_ACKNOWLEDGE: u8 = 0x01;
const STATUS_DRIVER: u8 = 0x02;
const STATUS_FEATURES_OK: u8 = 0x08;

/// A discovered virtio-blk device: its legacy I/O port base and capacity.
#[derive(Copy, Clone, Debug)]
pub struct VirtioBlockDevice {
    /// Base I/O port (from BAR0, low bits masked off).
    io_base_port: u16,
    /// Disk capacity in 512-byte sectors, read from device config.
    capacity_in_sectors: u64,
}

impl VirtioBlockDevice {
    /// Disk capacity in 512-byte sectors.
    pub fn capacity_in_sectors(&self) -> u64 {
        self.capacity_in_sectors
    }

    /// Base I/O port of the legacy register window.
    pub fn io_base_port(&self) -> u16 {
        self.io_base_port
    }
}

/// Discovers the transitional virtio-blk device, performs the reset/feature
/// handshake (negotiating no optional features — the baseline read/write path),
/// and reads its capacity. Returns `None` if the device is absent.
pub fn initialize_block_device() -> Option<VirtioBlockDevice> {
    let location = find_device(VIRTIO_PCI_VENDOR_ID, VIRTIO_BLK_TRANSITIONAL_DEVICE_ID)?;
    let bar0 = crate::arch::pci::read_base_address_register(location, 0);
    // Bit 0 set => I/O-space BAR; the base is the value with the low two bits cleared.
    let io_base_port = (bar0 & 0xFFFC) as u16;

    write_status(io_base_port, STATUS_RESET);
    write_status(io_base_port, STATUS_ACKNOWLEDGE);
    write_status(io_base_port, STATUS_ACKNOWLEDGE | STATUS_DRIVER);
    // Read (and ignore) the device feature bits, then negotiate none for the
    // minimal read/write path.
    let _device_features = read_port_dword(io_base_port + REGISTER_DEVICE_FEATURES);
    write_port_dword(io_base_port + REGISTER_DRIVER_FEATURES, 0);
    write_status(
        io_base_port,
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK,
    );

    let capacity_low = read_port_dword(io_base_port + REGISTER_BLOCK_CAPACITY_LOW) as u64;
    let capacity_high = read_port_dword(io_base_port + REGISTER_BLOCK_CAPACITY_HIGH) as u64;
    Some(VirtioBlockDevice {
        io_base_port,
        capacity_in_sectors: capacity_low | (capacity_high << 32),
    })
}

fn write_status(io_base_port: u16, status: u8) {
    write_port_byte(io_base_port + REGISTER_DEVICE_STATUS, status);
}

fn write_port_byte(port_address: u16, value: u8) {
    // SAFETY: virtio-blk legacy register write. Port I/O; no memory-safety
    // invariant. Ring 0. Allowlist: src/kernel/src/arch/.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port_address,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn read_port_dword(port_address: u16) -> u32 {
    // SAFETY: virtio-blk legacy register read. Port I/O; no memory-safety
    // invariant. Ring 0. Allowlist: src/kernel/src/arch/.
    let value: u32;
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            in("dx") port_address,
            out("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

fn write_port_dword(port_address: u16, value: u32) {
    // SAFETY: virtio-blk legacy register write. Port I/O; no memory-safety
    // invariant. Ring 0. Allowlist: src/kernel/src/arch/.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port_address,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}
