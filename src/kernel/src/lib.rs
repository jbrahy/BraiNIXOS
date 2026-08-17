// Kernel library crate for integration tests and host-target inspection.
//
// On x86_64-unknown-none (bare-metal), this crate exposes all kernel modules.
// On host targets (e.g. aarch64-apple-darwin for cargo test), the x86-specific
// modules are excluded so that source-inspection integration tests can compile.
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

#[cfg(any(bare_metal_x86, bare_metal_aarch64))]
pub mod arch;

/// aarch64 identification decoding: pure, host-tested, no instructions.
pub mod aarch64_ident;

/// Stage-1 page-table walking: pure, host-tested, no instructions.
pub mod aarch64_walk;

/// Stage-1 table construction: pure, host-tested, no instructions.
pub mod aarch64_tables;

/// CPU feature detection: pure, host-tested, no instructions.
pub mod aarch64_features;

#[cfg(bare_metal_x86)]
pub mod boot;

pub mod auth;

pub mod capability;

pub mod db;

/// Device table constants and builder functions (pure data, host-testable).
///
/// This module is exposed outside the x86_64-gated boot module so that
/// unit tests can run on aarch64-apple-darwin host targets. The file lives
/// in boot/ but contains no hardware access — only compile-time constants
/// and pure constructor functions for DeviceCapabilityData.
#[cfg(not(bare_metal_x86))]
#[path = "boot/device_table.rs"]
pub mod device_table;

pub mod ipc;

pub mod memory;

pub mod net;

pub mod ssh;

pub mod thread;

pub mod scheduler;

pub mod hardware_security;

pub mod process;

pub mod syscall;
