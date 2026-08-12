//! Minimal PCI configuration-space access via the legacy 0xCF8/0xCFC I/O ports.
//!
//! Used at boot to locate virtio devices (the NIC and the block disk) and read
//! their BARs, so the kernel can validate — rather than blindly trust — the
//! MMIO base addresses hardcoded in `boot/device_table.rs` before granting a
//! `CapDevice` to a device server.
//!
//! Scope: enumeration and BAR reads only. The kernel never drives a device
//! directly — drivers live in userspace device servers (devd-nic, devd-disk).
//! This module exists purely to discover the device topology for the
//! capability grant.
//!
//! Allowlist: `src/kernel/src/arch/` — port I/O has no safe Rust interface
//! (see UNSAFE_CODE_POLICY.md).
#![allow(unsafe_code)]

/// PCI CONFIG_ADDRESS port (write the address here first).
const PCI_CONFIG_ADDRESS_PORT: u16 = 0x0CF8;

/// PCI CONFIG_DATA port (then read/write the 32-bit datum here).
const PCI_CONFIG_DATA_PORT: u16 = 0x0CFC;

/// The PCI vendor ID assigned to virtio devices (Red Hat / Qumranet).
pub const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;

/// Returned in the vendor field when no device exists at a (bus, device, function).
const PCI_NO_DEVICE_VENDOR: u16 = 0xFFFF;

/// A located PCI function and the identifiers read from its config header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PciDeviceLocation {
    /// PCI bus number (0..=255).
    pub bus: u8,
    /// Device (slot) number on the bus (0..=31).
    pub device: u8,
    /// Function number (0..=7).
    pub function: u8,
    /// Vendor ID from config offset 0x00.
    pub vendor_id: u16,
    /// Device ID from config offset 0x02.
    pub device_id: u16,
}

/// Builds the 32-bit CONFIG_ADDRESS value for a config-space dword access.
///
/// Layout: bit 31 = enable, bits 23:16 = bus, bits 15:11 = device,
/// bits 10:8 = function, bits 7:2 = dword offset (the low two bits are
/// always zero — config-space reads are dword-aligned).
pub fn compute_config_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    const ENABLE_BIT: u32 = 0x8000_0000;
    ENABLE_BIT
        | ((bus as u32) << 16)
        | (((device as u32) & 0x1F) << 11)
        | (((function as u32) & 0x07) << 8)
        | ((offset as u32) & 0xFC)
}

/// Reads one 32-bit dword from PCI config space.
pub fn read_config_dword(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = compute_config_address(bus, device, function, offset);
    write_port_dword(PCI_CONFIG_ADDRESS_PORT, address);
    read_port_dword(PCI_CONFIG_DATA_PORT)
}

/// Writes one 32-bit dword to PCI config space.
pub fn write_config_dword(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = compute_config_address(bus, device, function, offset);
    write_port_dword(PCI_CONFIG_ADDRESS_PORT, address);
    write_port_dword(PCI_CONFIG_DATA_PORT, value);
}

/// PCI Command register offset (low 16 bits of the dword at 0x04).
const PCI_COMMAND_REGISTER_OFFSET: u8 = 0x04;
/// Command bits: Memory Space Enable (bit 1) and Bus Master Enable (bit 2).
const PCI_COMMAND_MEMORY_SPACE: u32 = 1 << 1;
const PCI_COMMAND_BUS_MASTER: u32 = 1 << 2;

/// Enables memory-space decoding and bus-mastering DMA for a device. A device
/// cannot DMA (read descriptor rings / packet buffers) until Bus Master is set;
/// QEMU's e1000 reports `pci_master 0` and silently drops transmits otherwise.
pub fn enable_memory_space_and_bus_master(location: PciDeviceLocation) {
    let command_and_status = read_config_dword(
        location.bus,
        location.device,
        location.function,
        PCI_COMMAND_REGISTER_OFFSET,
    );
    let updated = command_and_status | PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_BUS_MASTER;
    write_config_dword(
        location.bus,
        location.device,
        location.function,
        PCI_COMMAND_REGISTER_OFFSET,
        updated,
    );
}

/// Reads the vendor (low 16 bits) and device (high 16 bits) IDs at offset 0x00.
fn read_vendor_and_device(bus: u8, device: u8, function: u8) -> (u16, u16) {
    let identifiers = read_config_dword(bus, device, function, 0x00);
    ((identifiers & 0xFFFF) as u16, (identifiers >> 16) as u16)
}

/// Reads base address register `bar_index` (0..=5) of a function.
pub fn read_base_address_register(location: PciDeviceLocation, bar_index: u8) -> u32 {
    let offset = 0x10u8.wrapping_add(bar_index.wrapping_mul(4));
    read_config_dword(location.bus, location.device, location.function, offset)
}

/// Scans bus 0 for the first function whose vendor and device IDs match.
///
/// Bus 0 is where QEMU's q35 machine places the virtio PCI devices. Returns
/// the located function, or `None` if no match is present.
pub fn find_device(vendor_id: u16, device_id: u16) -> Option<PciDeviceLocation> {
    for device in 0..32u8 {
        for function in 0..8u8 {
            let (found_vendor, found_device) = read_vendor_and_device(0, device, function);
            if found_vendor == PCI_NO_DEVICE_VENDOR {
                continue;
            }
            if found_vendor == vendor_id && found_device == device_id {
                return Some(PciDeviceLocation {
                    bus: 0,
                    device,
                    function,
                    vendor_id: found_vendor,
                    device_id: found_device,
                });
            }
        }
    }
    None
}

/// Visits every present function on bus 0, invoking `visitor` with each. Used to
/// log the device topology at boot.
pub fn for_each_device_on_bus_zero(mut visitor: impl FnMut(PciDeviceLocation)) {
    for device in 0..32u8 {
        for function in 0..8u8 {
            let (vendor_id, device_id) = read_vendor_and_device(0, device, function);
            if vendor_id == PCI_NO_DEVICE_VENDOR {
                continue;
            }
            visitor(PciDeviceLocation {
                bus: 0,
                device,
                function,
                vendor_id,
                device_id,
            });
        }
    }
}

/// Writes a 32-bit value to an I/O port.
fn write_port_dword(port_address: u16, value: u32) {
    // SAFETY: PCI config port write (0xCF8). Port I/O is a separate address
    // space from RAM; no memory-safety invariant is involved.
    // - Precondition: ring 0.
    // - Invariant: enumeration only; the kernel never drives the device.
    // Allowlist: src/kernel/src/arch/ — port I/O.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port_address,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Reads a 32-bit value from an I/O port.
fn read_port_dword(port_address: u16) -> u32 {
    // SAFETY: PCI config port read (0xCFC). Read of a device register; no
    // memory-safety invariant is involved.
    // - Precondition: ring 0.
    // - Invariant: enumeration only.
    // Allowlist: src/kernel/src/arch/ — port I/O.
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
