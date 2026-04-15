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
/// Verified by: test_frame_capability_is_scoped_to_specific_physical_frame
#[derive(Copy, Clone, Debug)]
pub struct FrameCapabilityData {
    /// Physical base address of the frame this capability grants access to.
    pub frame_physical_address: u64,
    /// Rights bitmask for permitted operations on this frame.
    pub frame_rights: CapabilityRights,
}
