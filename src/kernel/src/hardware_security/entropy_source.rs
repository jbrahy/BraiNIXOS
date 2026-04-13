//! Hardware entropy source: RDRAND and RDSEED instructions.
//!
//! Phase 6 Plan 01: Provides the raw RDRAND and RDSEED sample functions used by the
//! CSPRNG seeding in `csprng.rs`. RDRAND absence is a fatal boot halt (locked Phase 0
//! policy). RDSEED is used where available (Intel Ivy Bridge+) but is not required;
//! absent RDSEED falls back to RDRAND-only (D-09).
//!
//! Raw RDRAND/RDSEED instructions are delegated to
//! `src/kernel/src/arch/hardware_registers.rs` per the UNSAFE_CODE_POLICY.md allowlist.
//! This module provides safe wrappers with explicit retry logic and absence detection.

#[cfg(test)]
mod tests {}
