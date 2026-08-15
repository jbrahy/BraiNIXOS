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
