//! IPC syscall argument register globals written by the SYSCALL entry stub.
//!
//! The assembly entry stub (`syscall_entry_point` in `arch/syscall_entry.rs`)
//! saves the seven IPC argument registers to these globals via RIP-relative
//! stores immediately after the push sequence, before `dispatch_syscall` is called.
//!
//! These globals are read by IPC dispatch handlers to obtain the caller's
//! endpoint slot, capability slot, timeout, message registers, and capability register.
//!
//! Phase 11, D-01: argument propagation via `#[no_mangle]` AtomicU64 globals.
//!
//! Falls under `src/kernel/src/syscall/kernel_syscall_registers.rs` allowlist entry
//! in `docs/security/UNSAFE_CODE_POLICY.md`.
#![allow(unsafe_code)]

use core::sync::atomic::AtomicU64;

/// Endpoint CSlot index (rdi). Written from [rsp+48] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE: AtomicU64 = AtomicU64::new(0);

/// Capability slot for transfer (rsi). Written from [rsp+40] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_CAP_SLOT_VALUE: AtomicU64 = AtomicU64::new(0);

/// Timeout in ticks (rdx). Written from [rsp+32] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE: AtomicU64 = AtomicU64::new(0);

/// Message Register 0 (r8). Written from [rsp+24] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE: AtomicU64 = AtomicU64::new(0);

/// Message Register 1 (r9). Written from [rsp+16] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE: AtomicU64 = AtomicU64::new(0);

/// Message Register 2 (r10). Written from [rsp+8] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE: AtomicU64 = AtomicU64::new(0);

/// Capability register for transfer (r12). Written from [rsp+0] by the SYSCALL entry stub.
#[no_mangle]
pub static KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE: AtomicU64 = AtomicU64::new(0);
