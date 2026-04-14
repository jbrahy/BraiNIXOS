//! Compile-time QEMU virtio MMIO and IRQ constants for Phase 8 device isolation.
//!
//! These constants define the physical address ranges and IRQ lines for
//! virtio devices as configured in the QEMU machine model. They are used
//! during boot to populate CapDevice fields for devd-nic and devd-disk.
//!
//! See: .planning/phases/08-device-isolation/08-CONTEXT.md D-03
//! See: docs/operations/DEVICE_ISOLATION_POLICY.md §2

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
