// Kernel library crate for integration tests and host-target inspection.
//
// On x86_64-unknown-none (bare-metal), this crate exposes all kernel modules.
// On host targets (e.g. aarch64-apple-darwin for cargo test), the x86-specific
// modules are excluded so that source-inspection integration tests can compile.
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![cfg_attr(target_arch = "x86_64", feature(abi_x86_interrupt))]

#[cfg(target_arch = "x86_64")]
pub mod arch;

#[cfg(target_arch = "x86_64")]
pub mod boot;

pub mod capability;

pub mod memory;
