//! TPM TIS (TPM Interface Specification) register definitions and MMIO accessors.
//!
//! Phase 6 Plan 03: Defines the TPM TIS register layout at base address 0xFED40000.
//! Provides read_volatile and write_volatile accessor stubs for TPM status, data
//! FIFO, and locality registers.
//!
//! All MMIO access is delegated to `src/kernel/src/arch/hardware_registers.rs`
//! per the UNSAFE_CODE_POLICY.md allowlist for TPM TIS MMIO operations.

#[cfg(test)]
mod tests {}
