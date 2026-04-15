//! Frame capability data structures for Phase 9 network stack decomposition.
//!
//! Defines the typed token that grants a process authority over a specific
//! physical memory frame for shared-memory packet buffer exchange between
//! isolated network stack servers.
//!
//! Enforces INV-MEM-005: memory ownership is explicit.

use crate::capability::capability_rights::CapabilityRights;

/// Maximum number of pages a single FrameCapabilityData may cover.
pub const MAXIMUM_FRAME_PAGES: usize = 8;

/// Virtual address where the kernel maps a shared frame for network servers.
///
/// Network stack servers receive their shared packet buffer at this address.
/// Enforces INV-MEM-005: memory ownership is explicit.
pub const FRAME_MAP_VIRTUAL_ADDRESS: u64 = 0x0000_0000_0030_0000;

/// Data payload for a frame capability, scoped to one physical memory frame.
///
/// Stores the physical base address and rights granted by this capability.
/// All fields are verified on every sys_frame_map call.
///
/// Enforces INV-MEM-005: memory ownership is explicit.
/// Verified by: test_frame_capability_data_stores_physical_address
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameCapabilityData {
    /// Physical base address of the frame this capability grants access to.
    pub frame_physical_address: u64,
    /// Rights bitmask for permitted operations on this frame.
    pub frame_rights: CapabilityRights,
}

impl FrameCapabilityData {
    /// Creates a new FrameCapabilityData with the given physical address and rights.
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    /// Verified by: test_frame_capability_data_stores_physical_address
    pub fn new(frame_physical_address: u64, frame_rights: CapabilityRights) -> Self {
        Self { frame_physical_address, frame_rights }
    }

    /// Validates that the frame physical address is page-aligned (4KiB).
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    /// Verified by: test_frame_capability_validates_page_alignment
    pub fn validate_frame_alignment(physical_address: u64) -> bool {
        physical_address % 4096 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FrameCapabilityData, FRAME_MAP_VIRTUAL_ADDRESS, MAXIMUM_FRAME_PAGES,
    };
    use crate::capability::capability_rights::READ;

    /// Verifies that FrameCapabilityData stores the physical address and rights.
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    #[test]
    fn test_frame_capability_data_stores_physical_address() {
        let frame_data = FrameCapabilityData::new(0x1000, READ);
        assert_eq!(frame_data.frame_physical_address, 0x1000);
        assert_eq!(frame_data.frame_rights, READ);
    }

    /// Verifies that validate_frame_alignment accepts aligned and rejects unaligned addresses.
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    #[test]
    fn test_frame_capability_validates_page_alignment() {
        assert!(FrameCapabilityData::validate_frame_alignment(0x1000));
        assert!(!FrameCapabilityData::validate_frame_alignment(0x1001));
    }

    /// Verifies that the FRAME_MAP_VIRTUAL_ADDRESS constant has the expected value.
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    #[test]
    fn test_frame_map_virtual_address_constant() {
        assert_eq!(FRAME_MAP_VIRTUAL_ADDRESS, 0x0000_0000_0030_0000);
    }

    /// Verifies that the MAXIMUM_FRAME_PAGES constant has the expected value.
    ///
    /// Enforces INV-MEM-005: memory ownership is explicit.
    #[test]
    fn test_maximum_frame_pages_constant() {
        assert_eq!(MAXIMUM_FRAME_PAGES, 8);
    }
}
