//! Capability manager module — Phase 3.
//!
//! Defines the complete type foundation for Brainix's capability-based access control:
//! typed capabilities, rights bitmasks, capability slots, the CSpace flat array,
//! and all error types.

pub mod audit_event_type;
pub mod audit_log;
pub mod audit_log_protection;
pub mod capability_error;
pub mod capability_rights;
pub mod capability_slot;
pub mod capability_space;
pub mod capability_type;
pub mod derivation_record;
pub mod derivation_tree;
pub mod derive_capability;
pub mod revocation;

pub use capability_error::CapabilityError;
pub use capability_rights::CapabilityRights;
pub use capability_slot::CapabilitySlot;
pub use capability_slot::CapabilitySlotState;
pub use capability_space::CapabilitySpace;
pub use capability_space::MAXIMUM_CAPABILITY_SLOTS_PER_PROCESS;
pub use capability_type::CapabilityType;
pub use derivation_tree::CapabilityDerivationTree;
pub use derive_capability::derive_capability;
pub use revocation::revoke_capability;

#[cfg(test)]
mod tests;
