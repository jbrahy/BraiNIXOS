//! Syscall dispatch module — gated to x86-64 (contains inline asm context).

#[cfg(target_arch = "x86_64")]
pub mod dispatch;

pub mod audit_read;
pub mod device_map_mmio;
pub mod frame_map;
pub mod ipc_dispatch_handlers;
pub mod irq_bind;
pub mod kernel_ipc_state;
pub mod kernel_syscall_registers;
pub mod process_exit;
pub mod serial_read;
