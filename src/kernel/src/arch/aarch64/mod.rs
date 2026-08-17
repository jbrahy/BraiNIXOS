//! The aarch64 / Apple Silicon architecture backend.
//!
//! # Status: a seam, not a backend
//!
//! This module exists so the aarch64 build has somewhere to fail *towards*.
//! It deliberately implements nothing yet, and that is the honest state of
//! AS-1c as of 2026-08-14.
//!
//! # Why the seam had to come first
//!
//! Until 2026-08-14 `src/kernel/src/arch/mod.rs` declared its x86-64 modules
//! **ungated**, so `cargo build --target aarch64-unknown-none-softfloat`
//! succeeded against a tree with no aarch64 code in it — compiling an x86-64
//! page-table walker and a bare `asm!("cli")` into an aarch64 library. It only
//! ever passed because a library build is not a link.
//!
//! That made AS-1c's original verify criterion ("it compiles for aarch64 or it
//! does not") green before the work started. Gating the x86-64 modules replaces
//! a meaningless success with a list of real errors, and every one of those
//! errors is a piece of this module that has to exist.
//!
//! # What belongs here, and where each piece already exists
//!
//! Two of these are further along than a blank module suggests, because their
//! decidable halves were built as standalone crates under the Track C rule —
//! write everything that is a pure function over bytes, stop at the hardware:
//!
//! - **MMU / page tables.** `src/aarch64-mmu/` already encodes VMSAv8-64
//!   descriptors with W^X unrepresentable in the type system and three Kani
//!   proofs over every address, permission, level and granule. What is owed
//!   here is the table *walk*, TTBR programming, and TLB maintenance.
//! - **IOMMU.** `src/dart/` holds the DART trait and its no-widening proof
//!   (`INV-DEV-006`), which already discharged one of AS-5-T0's five signed
//!   preconditions. Owed here: per-instance ADT discovery and register
//!   programming.
//! - **Exception vectors, generic timer, SVC entry, context switch,
//!   RNDR/PAC-BTI.** Not started anywhere. These are AS-1b.
//!
//! # The rule this module is held to
//!
//! The frozen x86-64 tree carries a scoped `arithmetic_side_effects` suppression
//! because decision #26 says changing it earns no platform progress. **That
//! allowance does not extend here.** Per `arch/mod.rs`: *"The aarch64 code that
//! replaces it is held to the unsuppressed bar."*
//!
//! Page size on this platform is **16 KiB** and every size in this module is
//! expressed in pages rather than bytes (`INV-MEM-009`). With the QEMU `virt`
//! harness cancelled (#22) there is no 4 KiB build left to disagree with a
//! hardcoded constant, so the discipline is enforced by review and by
//! construction rather than by a second target.

// No implementations yet. Items land here as AS-1b completes them, each one
// removing a specific error from the aarch64 build rather than adding a stub
// that reports success it has not earned.

// ---------------------------------------------------------------------------
// AS-1c, step 2 -- the backend starts here.
// ---------------------------------------------------------------------------

pub mod bss;
pub mod console;
pub mod el;
pub mod entropy;
pub mod halt;
pub mod mmu;
pub mod pac;
pub mod registers;
pub mod timer;
pub mod vectors;
pub mod watchdog;

pub use console::Console;
pub use halt::{current_exception_level, park};
pub use crate::aarch64_ident::MemoryModel;
pub use registers::memory_model;
pub use timer::Timer;
pub use vectors::{last_exception, with_vectors, LastException, NO_EXCEPTION};

// ---------------------------------------------------------------------------
// EL2 -> EL1: why it is not a bounded probe under m1n1.
//
// Measured on the target 2026-08-16, read-only, before attempting anything:
//
//     HCR_EL2   0x32488000038    RW=1  TGE=1  E2H=1
//     TCR_EL1   0x37510b510      identical to TCR_EL2
//     TTBR0_EL1 0x1000369c000    identical to TTBR0_EL2
//
// The machine runs in **VHE** (`E2H=1`) with **`TGE=1`**. Under that
// configuration the EL1-named registers are aliases of the EL2 ones -- which is
// why the two pairs above are identical, and why `SCTLR_EL1` reports the MMU
// enabled -- and `TGE` routes general exceptions to EL2, so EL1 is not a place
// code can simply be dropped into.
//
// Getting to a genuine EL1 therefore means clearing `TGE`, deciding what to do
// about `E2H`, and establishing a real EL1 translation regime. That is a
// wholesale change to the machine's configuration, and m1n1 -- which is
// resident, hosting the measurement, and the only reason we can see anything at
// all -- depends on the configuration being changed.
//
// So this belongs in the boot path, entered from iBoot with the machine ours,
// not in a probe. Attempting it here would trade the debugging loop for the
// thing being debugged.
//
// The pre-check that establishes all of this is in `kernel_probe` and is
// read-only: `HCR_EL2` for RW/TGE, and `AT s1e1r` for whether a landing pad
// would even translate. It refused, and refusing was correct.
// ---------------------------------------------------------------------------
