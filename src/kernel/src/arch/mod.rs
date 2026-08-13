//! Architecture-specific hardware abstraction modules.
//!
//! # Frozen x86-64 reference — not scheduled
//!
//! Everything here is the **frozen reference implementation** of ROADMAP
//! decision #26: it keeps building, nothing is scheduled against it, and it is
//! not a deployment target. The only supported platform is aarch64/Apple
//! Silicon, whose first code lives in `src/boot-stub-apple/`.

// Lint suppression, scoped to the frozen tree and justified rather than
// blanket-applied.
//
// These fire ~35 times across the MMIO and paging code -- pointer arithmetic and
// register math that `arithmetic_side_effects` flags by design. They have been
// failing CI continuously, invisible until 2026-08-12 because Style Check died
// at `cargo fmt` before reaching clippy.
//
// Suppressed rather than fixed because decision #26 freezes this tree: changing
// it earns no platform progress and risks the one build that currently works.
// The aarch64 code that replaces it is held to the unsuppressed bar.
//
// REMOVE THIS BLOCK if any of this is ever unfrozen.
#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::unnecessary_cast)]

pub mod context_switch_assembly;
pub mod hardware_registers;
pub mod interrupts;
pub mod paging;
pub mod timer;

#[cfg(target_arch = "x86_64")]
pub mod syscall_entry;

#[cfg(target_arch = "x86_64")]
pub mod syscall_trampoline;

#[cfg(target_arch = "x86_64")]
pub mod pci;

#[cfg(target_arch = "x86_64")]
pub mod virtio_blk;

#[cfg(target_arch = "x86_64")]
pub mod e1000;
