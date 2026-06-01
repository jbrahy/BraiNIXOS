//! Minimal polled Intel e1000 (82540EM) NIC driver — bring-up stage.
//!
//! The QEMU NIC is an MMIO-mapped Intel e1000, not a virtio device. This module
//! discovers it via PCI, maps its register BAR strong-uncacheable into the
//! kernel PML4, resets the device, and reads its MAC address. Descriptor-ring
//! transmit/receive (polled, no interrupts — the chosen most-secure design)
//! builds on this.
//!
//! The kernel performs NIC bring-up; per the microkernel design the packet I/O
//! path will ultimately live in a userspace network server driven through
//! capability-gated MMIO, but discovery + reset stay here.
//!
//! Allowlist: `src/kernel/src/arch/` — MMIO register access has no safe
//! interface.
#![allow(unsafe_code)]

use crate::arch::pci::{find_device, read_base_address_register};
use crate::arch::paging::kernel_page_table::map_mmio_region_into_kernel;

/// PCI vendor:device for the QEMU Intel 82540EM e1000.
const INTEL_VENDOR_ID: u16 = 0x8086;
const E1000_82540EM_DEVICE_ID: u16 = 0x100E;

/// e1000 register MMIO window size (128 KiB = 32 pages).
const E1000_REGISTER_SPACE_PAGES: usize = 32;

// e1000 register offsets.
const REGISTER_CONTROL: u64 = 0x0000;
const REGISTER_RECEIVE_ADDRESS_LOW: u64 = 0x5400;
const REGISTER_RECEIVE_ADDRESS_HIGH: u64 = 0x5404;

/// CTRL.RST — device reset (self-clearing).
const CONTROL_RESET: u32 = 1 << 26;

/// A discovered and reset e1000 NIC.
#[derive(Copy, Clone, Debug)]
pub struct E1000Device {
    mmio_base_address: u64,
    mac_address: [u8; 6],
}

impl E1000Device {
    /// The NIC's 6-byte MAC address, read from RAL/RAH after reset.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Base of the mapped register window.
    pub fn mmio_base_address(&self) -> u64 {
        self.mmio_base_address
    }
}

/// Discovers the e1000 via PCI, maps its register BAR, resets it, and reads the
/// MAC address. Returns `None` if the NIC is absent or its BAR is not memory-mapped.
pub fn initialize_nic() -> Option<E1000Device> {
    let location = find_device(INTEL_VENDOR_ID, E1000_82540EM_DEVICE_ID)?;
    let bar0 = read_base_address_register(location, 0);
    // Memory BAR: bit 0 clears for memory space; base masks off the low 4 flag bits.
    if bar0 & 0x1 != 0 {
        return None;
    }
    let mmio_base_address = (bar0 & 0xFFFF_FFF0) as u64;

    // SAFETY: mmio_base_address is the NIC's real BAR from PCI enumeration.
    unsafe { map_mmio_region_into_kernel(mmio_base_address, E1000_REGISTER_SPACE_PAGES).ok()? };

    reset_device(mmio_base_address);
    let mac_address = read_mac_address(mmio_base_address);
    Some(E1000Device {
        mmio_base_address,
        mac_address,
    })
}

/// Resets the device via CTRL.RST and spins until the bit self-clears.
fn reset_device(mmio_base_address: u64) {
    let control = read_register(mmio_base_address, REGISTER_CONTROL);
    write_register(mmio_base_address, REGISTER_CONTROL, control | CONTROL_RESET);
    // RST self-clears once the reset completes; bound the spin so a stuck device
    // cannot hang boot.
    let mut attempts = 0u32;
    while read_register(mmio_base_address, REGISTER_CONTROL) & CONTROL_RESET != 0 {
        core::hint::spin_loop();
        attempts = attempts.wrapping_add(1);
        if attempts > 1_000_000 {
            break;
        }
    }
}

/// Reads the 6-byte MAC from the Receive Address registers (RAL/RAH), which
/// QEMU pre-populates from the `-device e1000,mac=...` option.
fn read_mac_address(mmio_base_address: u64) -> [u8; 6] {
    let low = read_register(mmio_base_address, REGISTER_RECEIVE_ADDRESS_LOW);
    let high = read_register(mmio_base_address, REGISTER_RECEIVE_ADDRESS_HIGH);
    [
        (low & 0xFF) as u8,
        ((low >> 8) & 0xFF) as u8,
        ((low >> 16) & 0xFF) as u8,
        ((low >> 24) & 0xFF) as u8,
        (high & 0xFF) as u8,
        ((high >> 8) & 0xFF) as u8,
    ]
}

/// Reads a 32-bit e1000 register at `offset` from `mmio_base_address`.
fn read_register(mmio_base_address: u64, offset: u64) -> u32 {
    let pointer = mmio_base_address.wrapping_add(offset) as *const u32;
    // SAFETY: the register window was mapped strong-uncacheable; offset is in range.
    unsafe { core::ptr::read_volatile(pointer) }
}

/// Writes a 32-bit e1000 register at `offset` from `mmio_base_address`.
fn write_register(mmio_base_address: u64, offset: u64, value: u32) {
    let pointer = mmio_base_address.wrapping_add(offset) as *mut u32;
    // SAFETY: the register window was mapped strong-uncacheable; offset is in range.
    unsafe { core::ptr::write_volatile(pointer, value) }
}
