//! Capability rights bitmask type.
//!
//! Enforces invariant INV-AUTH-003: rights are monotonic under derivation.
//! A derived capability can never have rights not present in its parent.

/// Bitmask of permitted operations for a capability.
///
/// Enforces INV-AUTH-003: rights monotonicity foundation.
/// Derivation enforces `child_rights & !parent_rights == 0`.
///
/// Verified by: tests::test_derived_capability_cannot_have_rights_not_in_parent
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct CapabilityRights(u32);

/// Permission to read the object's state.
pub const READ: CapabilityRights = CapabilityRights(0b0001);

/// Permission to modify the object's state.
pub const WRITE: CapabilityRights = CapabilityRights(0b0010);

/// Permission to derive a child capability and transfer it to another process.
pub const GRANT: CapabilityRights = CapabilityRights(0b0100);

/// Permission to create a single-use CapReply capability during IPC receive.
pub const GRANT_REPLY: CapabilityRights = CapabilityRights(0b1000);

impl CapabilityRights {
    /// Returns a rights value with no permissions set.
    pub const fn empty() -> Self {
        CapabilityRights(0)
    }

    /// Returns the raw bitmask value.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns true if all bits in `other` are set in `self`.
    pub const fn contains(self, other: CapabilityRights) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true if no permission bits are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::ops::BitOr for CapabilityRights {
    type Output = CapabilityRights;

    fn bitor(self, other: CapabilityRights) -> CapabilityRights {
        CapabilityRights(self.0 | other.0)
    }
}

impl core::ops::BitAnd for CapabilityRights {
    type Output = CapabilityRights;

    fn bitand(self, other: CapabilityRights) -> CapabilityRights {
        CapabilityRights(self.0 & other.0)
    }
}

impl core::ops::Not for CapabilityRights {
    type Output = CapabilityRights;

    fn not(self) -> CapabilityRights {
        CapabilityRights(!self.0)
    }
}

impl From<u32> for CapabilityRights {
    fn from(raw_bitmask: u32) -> CapabilityRights {
        CapabilityRights(raw_bitmask)
    }
}
