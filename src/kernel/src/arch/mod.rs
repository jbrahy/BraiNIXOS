//! Architecture-specific hardware abstraction modules.

pub mod interrupts;
pub mod paging;

#[cfg(target_arch = "x86_64")]
pub mod syscall_entry;
