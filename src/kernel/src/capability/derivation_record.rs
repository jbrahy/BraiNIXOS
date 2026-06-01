//! Derivation record: parent/child/sibling links for a single capability slot.
//!
//! Each slot in the derivation tree has one record tracking its position.
//! SENTINEL_INDEX marks "no link" (root, no parent, no child, no sibling).
//!
//! Enforces INV-AUTH-003: derivation tree structure enables rights monotonicity audit.
//! Enforces INV-AUTH-004: tree structure enables complete descendant revocation.

/// Sentinel value for "no link" in the derivation tree.
///
/// A parent_index of SENTINEL_INDEX means the slot is a root capability.
/// A first_child_index or next_sibling_index of SENTINEL_INDEX means no link.
pub const SENTINEL_INDEX: u32 = u32::MAX;

/// Parent, first-child, and next-sibling links for one capability slot.
///
/// Forms a left-child right-sibling tree. Each slot's children are linked
/// as a singly-linked list via next_sibling_index. The derivation tree uses
/// an array of these records indexed by slot number.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DerivationRecord {
    /// Slot index of the parent capability. SENTINEL_INDEX for root capabilities.
    pub parent_index: u32,
    /// Slot index of the first child capability. SENTINEL_INDEX if no children.
    pub first_child_index: u32,
    /// Slot index of the next sibling capability. SENTINEL_INDEX if last sibling.
    pub next_sibling_index: u32,
}

impl DerivationRecord {
    /// Returns a record with all links set to SENTINEL_INDEX (no parent, no child, no sibling).
    pub const fn empty() -> Self {
        DerivationRecord {
            parent_index: SENTINEL_INDEX,
            first_child_index: SENTINEL_INDEX,
            next_sibling_index: SENTINEL_INDEX,
        }
    }
}
