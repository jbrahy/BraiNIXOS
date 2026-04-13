//! CET Indirect Branch Tracking (IBT) enablement.
//!
//! Phase 6 Plan 02: Enables CET IBT by setting bit 23 (ENDBR64 enforcement) in CR4
//! after verifying CPUID reports IBT support. CPL0 shadow stack is NOT enabled --
//! Intel hardware does not support CPL0 shadow stack on current silicon (D-17, locked
//! Phase 0 decision).
//!
//! CR4 write is delegated to `src/kernel/src/arch/hardware_registers.rs` per the
//! UNSAFE_CODE_POLICY.md allowlist. ENDBR64 instructions are inserted in assembly
//! stubs via inline assembly in the same allowlisted arch/ module.

#[cfg(test)]
mod tests {}
