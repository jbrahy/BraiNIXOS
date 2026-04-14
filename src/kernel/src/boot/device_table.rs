//! Compile-time QEMU virtio MMIO and IRQ constants for Phase 8 device isolation.
//!
//! These constants define the physical address ranges and IRQ lines for
//! virtio devices as configured in the QEMU machine model. They are used
//! during boot to populate CapDevice fields for devd-nic and devd-disk.
//!
//! See: .planning/phases/08-device-isolation/08-CONTEXT.md D-03
//! See: docs/operations/DEVICE_ISOLATION_POLICY.md §2

use crate::capability::device_capability::{DeviceCapabilityData, DeviceType, IRQ_NONE};

/// Physical base address of the virtio-net-pci MMIO region in QEMU.
pub const VIRTIO_NET_MMIO_BASE_ADDRESS: u64 = 0xFEBE_0000;

/// Size in bytes of the virtio-net-pci MMIO region.
pub const VIRTIO_NET_MMIO_SIZE: u32 = 0x1000;

/// IRQ number assigned to the virtio-net-pci device in QEMU.
pub const VIRTIO_NET_IRQ_NUMBER: u8 = 11;

/// Physical base address of the virtio-blk-pci MMIO region in QEMU.
pub const VIRTIO_BLK_MMIO_BASE_ADDRESS: u64 = 0xFEBD_0000;

/// Size in bytes of the virtio-blk-pci MMIO region.
pub const VIRTIO_BLK_MMIO_SIZE: u32 = 0x1000;

/// IRQ number assigned to the virtio-blk-pci device in QEMU.
pub const VIRTIO_BLK_IRQ_NUMBER: u8 = 10;

/// Static DeviceCapabilityData for the NIC device.
///
/// Stored in kernel read-only data. Its address is written into the
/// CapabilitySlot.object_pointer field when devd-nic's CapDevice is granted
/// at boot, so Phase 9 syscall handlers can recover the MMIO bounds.
///
/// Mitigates T-DEV-018: CapDevice payload is associated at grant time.
pub static NIC_DEVICE_CAPABILITY_DATA: DeviceCapabilityData = DeviceCapabilityData {
    device_type: DeviceType::NetworkInterface,
    mmio_base_address: VIRTIO_NET_MMIO_BASE_ADDRESS,
    mmio_size: VIRTIO_NET_MMIO_SIZE,
    irq_set: [VIRTIO_NET_IRQ_NUMBER, IRQ_NONE, IRQ_NONE, IRQ_NONE],
};

/// Static DeviceCapabilityData for the disk device.
///
/// Stored in kernel read-only data. Its address is written into the
/// CapabilitySlot.object_pointer field when devd-disk's CapDevice is granted
/// at boot, so Phase 9 syscall handlers can recover the MMIO bounds.
///
/// Mitigates T-DEV-018: CapDevice payload is associated at grant time.
pub static DISK_DEVICE_CAPABILITY_DATA: DeviceCapabilityData = DeviceCapabilityData {
    device_type: DeviceType::BlockStorage,
    mmio_base_address: VIRTIO_BLK_MMIO_BASE_ADDRESS,
    mmio_size: VIRTIO_BLK_MMIO_SIZE,
    irq_set: [VIRTIO_BLK_IRQ_NUMBER, IRQ_NONE, IRQ_NONE, IRQ_NONE],
};

/// Builds the DeviceCapabilityData for the virtio-net-pci NIC device.
///
/// Returns a DeviceCapabilityData scoped to the NIC's MMIO region and IRQ.
/// Enforces INV-DEV-002: each device service receives least privilege.
/// Verified by: test_build_nic_device_capability_data_has_correct_fields
pub fn build_nic_device_capability_data() -> DeviceCapabilityData {
    DeviceCapabilityData {
        device_type: DeviceType::NetworkInterface,
        mmio_base_address: VIRTIO_NET_MMIO_BASE_ADDRESS,
        mmio_size: VIRTIO_NET_MMIO_SIZE,
        irq_set: [VIRTIO_NET_IRQ_NUMBER, IRQ_NONE, IRQ_NONE, IRQ_NONE],
    }
}

/// Builds the DeviceCapabilityData for the virtio-blk-pci disk device.
///
/// Returns a DeviceCapabilityData scoped to the disk's MMIO region and IRQ.
/// Enforces INV-DEV-002: each device service receives least privilege.
/// Verified by: test_build_disk_device_capability_data_has_correct_fields
pub fn build_disk_device_capability_data() -> DeviceCapabilityData {
    DeviceCapabilityData {
        device_type: DeviceType::BlockStorage,
        mmio_base_address: VIRTIO_BLK_MMIO_BASE_ADDRESS,
        mmio_size: VIRTIO_BLK_MMIO_SIZE,
        irq_set: [VIRTIO_BLK_IRQ_NUMBER, IRQ_NONE, IRQ_NONE, IRQ_NONE],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_disk_device_capability_data, build_nic_device_capability_data, VIRTIO_BLK_IRQ_NUMBER,
        VIRTIO_BLK_MMIO_BASE_ADDRESS, VIRTIO_BLK_MMIO_SIZE, VIRTIO_NET_IRQ_NUMBER,
        VIRTIO_NET_MMIO_BASE_ADDRESS, VIRTIO_NET_MMIO_SIZE,
    };
    use crate::capability::device_capability::{DeviceType, IRQ_NONE};

    /// Verifies that the NIC capability data builder produces correct field values.
    ///
    /// Enforces INV-DEV-002: NIC server receives only NIC-scoped authority.
    #[test]
    fn test_build_nic_device_capability_data_has_correct_fields() {
        let nic_data = build_nic_device_capability_data();
        assert_eq!(nic_data.device_type, DeviceType::NetworkInterface);
        assert_eq!(nic_data.mmio_base_address, VIRTIO_NET_MMIO_BASE_ADDRESS);
        assert_eq!(nic_data.mmio_size, VIRTIO_NET_MMIO_SIZE);
        assert_eq!(nic_data.irq_set[0], VIRTIO_NET_IRQ_NUMBER);
        assert_eq!(nic_data.irq_set[1], IRQ_NONE);
        assert_eq!(nic_data.irq_set[2], IRQ_NONE);
        assert_eq!(nic_data.irq_set[3], IRQ_NONE);
    }

    /// Verifies that the disk capability data builder produces correct field values.
    ///
    /// Enforces INV-DEV-002: disk server receives only disk-scoped authority.
    #[test]
    fn test_build_disk_device_capability_data_has_correct_fields() {
        let disk_data = build_disk_device_capability_data();
        assert_eq!(disk_data.device_type, DeviceType::BlockStorage);
        assert_eq!(disk_data.mmio_base_address, VIRTIO_BLK_MMIO_BASE_ADDRESS);
        assert_eq!(disk_data.mmio_size, VIRTIO_BLK_MMIO_SIZE);
        assert_eq!(disk_data.irq_set[0], VIRTIO_BLK_IRQ_NUMBER);
        assert_eq!(disk_data.irq_set[1], IRQ_NONE);
        assert_eq!(disk_data.irq_set[2], IRQ_NONE);
        assert_eq!(disk_data.irq_set[3], IRQ_NONE);
    }
}
