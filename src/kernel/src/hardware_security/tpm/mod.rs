//! TPM 2.0 interface for BraiNIX kernel.
//!
//! Phase 6 Plans 03-05: Hand-rolled TPM 2.0 CRB/TIS MMIO interface. No external
//! TPM crate is used -- no viable no_std TPM2 crate exists for bare-metal.
//!
//! Submodules:
//! - `registers`: TPM TIS register definitions and MMIO accessor stubs
//! - `commands`: TPM2_GetRandom, TPM2_PCR_Extend, TPM2_Quote command encoders
//! - `quote`: TPM quote structure parsing and signature verification
//! - `monotonic_counter`: NV index read, verify, and increment for rollback protection
//!
//! All MMIO access to TPM TIS registers (base 0xFED40000) is delegated to
//! `src/kernel/src/arch/hardware_registers.rs` per the UNSAFE_CODE_POLICY.md allowlist.

pub mod commands;
pub mod monotonic_counter;
pub mod quote;
#[cfg(bare_metal_x86)]
pub mod registers;
