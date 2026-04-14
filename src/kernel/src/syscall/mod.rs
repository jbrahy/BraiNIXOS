//! Syscall dispatch module — gated to x86-64 (contains inline asm context).

#[cfg(target_arch = "x86_64")]
pub mod dispatch;

pub mod audit_read;
pub mod device_map_mmio;
pub mod irq_bind;
pub mod process_exit;
