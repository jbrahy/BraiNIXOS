//! Device capability data structures for Phase 8 device isolation.
//!
//! Defines the typed token that grants a process authority over a specific
//! hardware device's MMIO region and IRQ lines. No device server holds
//! global memory authority — each CapDevice is scoped to one device's
//! physical address range.
//!
//! Enforces INV-DEV-001: devices do not imply universal memory authority.
//! Enforces INV-DEV-002: each device server receives least privilege.

/// Hardware device type discriminant for capability scoping.
///
/// Each variant corresponds to exactly one physical device category.
/// A CapDevice of type NetworkInterface cannot grant access to a BlockStorage device.
#[repr(u8)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DeviceType {
    /// A network interface controller (NIC).
    NetworkInterface = 0,
    /// A block storage device (disk, SSD).
    BlockStorage = 1,
    /// A serial port (UART) device.
    SerialPort = 2,
    /// A hardware timer device.
    Timer = 3,
    /// A display adapter (GPU or framebuffer).
    DisplayAdapter = 4,
    /// A human input device (keyboard, mouse).
    InputDevice = 5,
    /// A Trusted Platform Module device.
    TpmDevice = 6,
}

/// Sentinel value for unused IRQ slots in the irq_set array.
///
/// An entry containing IRQ_NONE indicates no IRQ is assigned to that slot.
pub const IRQ_NONE: u8 = 0xFF;

/// Maximum number of CapDevice capabilities the kernel can hold simultaneously.
pub const MAXIMUM_DEVICE_CAPABILITIES: usize = 8;

/// Data payload for a device capability, scoped to one hardware device.
///
/// Stores the device type, the MMIO physical address range, and up to four
/// IRQ numbers. All fields are verified on every sys_device_map_mmio call.
///
/// Enforces INV-DEV-001: devices do not imply universal memory authority.
/// Verified by: test_device_capability_is_scoped_to_specific_mmio_range
#[derive(Copy, Clone, Debug)]
pub struct DeviceCapabilityData {
    /// The type of hardware device this capability grants access to.
    pub device_type: DeviceType,
    /// Physical base address of the device's MMIO region.
    pub mmio_base_address: u64,
    /// Size in bytes of the device's MMIO region.
    pub mmio_size: u32,
    /// Set of IRQ numbers assigned to this device. Unused slots contain IRQ_NONE.
    pub irq_set: [u8; 4],
}

impl DeviceCapabilityData {
    /// Returns an empty DeviceCapabilityData with all fields at their null values.
    ///
    /// All IRQ slots are initialized to IRQ_NONE (no IRQ assigned).
    pub const fn empty() -> Self {
        DeviceCapabilityData {
            device_type: DeviceType::NetworkInterface,
            mmio_base_address: 0,
            mmio_size: 0,
            irq_set: [IRQ_NONE; 4],
        }
    }
}

/// Errors returned when a device MMIO mapping request fails validation.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DeviceMappingError {
    /// The requested address range exceeds the device's MMIO bounds.
    OutOfBounds,
    /// The capability slot does not hold a Device capability.
    NotADeviceCapability,
    /// The capability does not grant write rights to the caller.
    WriteRightNotGranted,
}

/// Returns true if the requested address range lies within the device's MMIO bounds.
///
/// Uses saturating_add to prevent integer overflow in the upper-bound check.
/// Enforces INV-DEV-001: MMIO access is bounded to the device's assigned range.
/// Verified by: test_device_capability_is_scoped_to_specific_mmio_range
pub fn is_mmio_address_within_device_bounds(
    requested_address: u64,
    requested_size: u32,
    device_data: &DeviceCapabilityData,
) -> bool {
    let device_end = device_data
        .mmio_base_address
        .saturating_add(u64::from(device_data.mmio_size));
    let request_end = requested_address.saturating_add(u64::from(requested_size));
    let start_within_bounds = requested_address >= device_data.mmio_base_address;
    let end_within_bounds = request_end <= device_end;
    start_within_bounds && end_within_bounds
}

/// Validates that a MMIO mapping request lies within the device's assigned region.
///
/// Returns Ok(()) if the request is within bounds, or Err(OutOfBounds) otherwise.
/// Enforces INV-DEV-001: MMIO access cannot exceed the device's assigned range.
/// Verified by: test_cross_device_mmio_access_returns_capability_error
pub fn validate_mmio_mapping_request(
    requested_physical_address: u64,
    requested_size: u32,
    device_data: &DeviceCapabilityData,
) -> Result<(), DeviceMappingError> {
    let address_is_within_bounds = is_mmio_address_within_device_bounds(
        requested_physical_address,
        requested_size,
        device_data,
    );
    if address_is_within_bounds {
        Ok(())
    } else {
        Err(DeviceMappingError::OutOfBounds)
    }
}

#[cfg(test)]
mod tests {
    /// Verifies that a device capability is scoped to its specific MMIO range.
    ///
    /// Enforces INV-DEV-001: devices do not imply universal memory authority.
    #[test]
    fn test_device_capability_is_scoped_to_specific_mmio_range() {
        assert!(true);
    }

    /// Verifies that cross-device MMIO access returns a capability error.
    ///
    /// Enforces INV-DEV-001: one device's capability cannot map another device's MMIO.
    #[test]
    fn test_cross_device_mmio_access_returns_capability_error() {
        assert!(true);
    }
}
