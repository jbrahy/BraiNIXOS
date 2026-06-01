//! Architecture-specific hardware abstraction modules.

pub mod context_switch_assembly;
pub mod hardware_registers;
pub mod interrupts;
pub mod paging;
pub mod timer;

#[cfg(target_arch = "x86_64")]
pub mod syscall_entry;
