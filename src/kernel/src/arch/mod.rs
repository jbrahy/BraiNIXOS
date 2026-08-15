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
#![allow(clippy::identity_op)]
// A TSS field kept for layout fidelity with the hardware structure even though
// nothing reads it; removing it would misalign the struct against the manual.
#![allow(dead_code)]

// AS-1c, step 1 — the seam.
//
// These five were declared **ungated** until 2026-08-14, which is why
// `cargo build --target aarch64-unknown-none-softfloat` succeeded on a tree
// containing no aarch64 code: the x86-64 modules were compiled into the aarch64
// build. `interrupts/halt.rs` carries a bare `asm!("cli")`, so that build was
// only ever green because a library build is not a link.
//
// Gating them makes the aarch64 build fail honestly. Every error it now emits
// is a real item of AS-1c work that was previously invisible.
//
// On `x86_64-unknown-none` the predicate is true and the module set is
// byte-identical to before, so the frozen reference (#26) is untouched.
#[cfg(target_arch = "x86_64")]
pub mod context_switch_assembly;
#[cfg(target_arch = "x86_64")]
pub mod hardware_registers;
#[cfg(target_arch = "x86_64")]
pub mod interrupts;
#[cfg(target_arch = "x86_64")]
pub mod paging;
#[cfg(target_arch = "x86_64")]
pub mod timer;

/// The aarch64/Apple Silicon backend — **the only supported platform**.
///
/// Empty of implementations by design at this step. AS-1c is delivered as a
/// seam first and a backend second, because until the seam exists the aarch64
/// build cannot say what is missing.
#[cfg(target_arch = "aarch64")]
pub mod aarch64;

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
