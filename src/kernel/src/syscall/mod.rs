//! Syscall dispatch module — gated to x86-64 (contains inline asm context).

#[cfg(target_arch = "x86_64")]
pub mod dispatch;

pub mod audit_read;
#[cfg(target_arch = "x86_64")]
#[cfg(bare_metal_x86)]
pub mod auth_syscalls;
pub mod device_map_mmio;
pub mod frame_map;
pub mod ipc_dispatch_handlers;
pub mod irq_bind;
pub mod kernel_ipc_state;
pub mod kernel_syscall_registers;
pub mod process_exit;
#[cfg(target_arch = "x86_64")]
#[cfg(bare_metal_x86)]
pub mod serial_read;
#[cfg(target_arch = "x86_64")]
#[cfg(bare_metal_x86)]
pub mod serial_write;
#[cfg(target_arch = "x86_64")]
#[cfg(bare_metal_x86)]
pub mod user_memory;
