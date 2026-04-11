//! Memory subsystem module root.
//!
//! Provides core memory types: page types, allocation errors, and virtual
//! address layout constants. These are pure data structures testable on any host.

pub mod allocation_error;
pub mod page_type;
pub mod virtual_address_layout;
