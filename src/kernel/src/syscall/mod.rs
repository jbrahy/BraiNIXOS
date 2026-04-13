//! Syscall dispatch module — gated to x86-64 (contains inline asm context).

#[cfg(target_arch = "x86_64")]
pub mod dispatch;

pub mod audit_read;
pub mod process_exit;
