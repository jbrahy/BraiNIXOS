//! Paging module: page table construction, W^X enforcement, and KPTI structure.
//!
//! All page table entry writes go through the W^X validator before being committed.
//!
//! Security invariants enforced:
//! - INV-MEM-001: Userspace cannot read kernel memory (KPTI: empty user PML4)
//! - INV-MEM-002: Userspace cannot write kernel memory (KPTI: empty user PML4)
//! - INV-MEM-003: W^X is global (validator rejects writable+executable)
//! - INV-MEM-007: Kernel stack guard page is never mapped

pub mod direct_map;
pub mod kernel_page_table;
pub mod mapping_error;
pub mod page_table_flags_validator;
pub mod page_table_walk_helpers;
pub mod stack_guard;
pub mod user_page_table;
