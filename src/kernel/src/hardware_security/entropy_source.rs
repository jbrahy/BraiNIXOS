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
//!
//! x86_64-specific functions are gated with `#[cfg(target_arch = "x86_64")]`.
//! The pure logic function `should_halt_due_to_absent_rdrand` is ungated for host tests.

/// Error type for hardware entropy collection failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// The RDRAND instruction failed after all retries are exhausted.
    HardwareEntropyUnavailable,
}

/// Maximum number of retries for a single RDRAND sample before returning an error.
#[cfg(target_arch = "x86_64")]
const MAXIMUM_RDRAND_RETRY_COUNT: usize = 10;

/// Maximum number of retries for a single RDSEED sample before treating as absent.
#[cfg(target_arch = "x86_64")]
const MAXIMUM_RDSEED_RETRY_COUNT: usize = 3;

/// Pure logic: returns true if the kernel should halt due to absent RDRAND.
///
/// Separates the halt decision from the halt action for independent testability.
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit and conservative).
/// Verified by: test_should_halt_when_rdrand_is_absent
pub fn should_halt_due_to_absent_rdrand(rdrand_is_available: bool) -> bool {
    !rdrand_is_available
}

/// Returns true if RDRAND hardware entropy is available on this CPU.
///
/// Queries CPUID leaf 1 and checks the RDRAND feature bit (ECX bit 30).
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit).
/// Verified by: test_rdrand_detection_from_cpuid_when_bit_is_set
#[cfg(target_arch = "x86_64")]
pub fn is_hardware_entropy_available() -> bool {
    let cpuid_leaf_one_result = crate::arch::hardware_registers::execute_cpuid_query(1, 0);
    crate::hardware_security::cpu_feature_detection::is_rdrand_supported(&cpuid_leaf_one_result)
}

/// Halt the processor if RDRAND is unavailable.
///
/// Enforces invariant INV-BOOT-005: the kernel must not proceed without hardware entropy.
/// RDRAND absence is a fatal boot halt per D-07 and the locked Phase 0 policy.
///
/// Verified by: test_boot_halts_when_rdrand_is_unavailable
#[cfg(target_arch = "x86_64")]
pub fn halt_if_rdrand_unavailable() {
    let rdrand_is_available = is_hardware_entropy_available();
    if should_halt_due_to_absent_rdrand(rdrand_is_available) {
        crate::arch::interrupts::halt::disable_interrupts_and_halt();
    }
}

/// Collect the requested number of RDRAND samples (up to 8).
///
/// Each sample retries up to MAXIMUM_RDRAND_RETRY_COUNT times on failure.
/// Returns EntropyError::HardwareEntropyUnavailable if any sample fails all retries.
///
/// Enforces invariant INV-BOOT-005 (entropy initialization is explicit).
/// Verified by: test_rdrand_samples_collected_successfully
#[cfg(target_arch = "x86_64")]
pub fn collect_rdrand_samples(sample_count: usize) -> Result<[u64; 8], EntropyError> {
    let mut samples = [0u64; 8];
    let bounded_count = sample_count.min(8);
    for sample_slot in samples.iter_mut().take(bounded_count) {
        *sample_slot = collect_single_rdrand_sample()?;
    }
    Ok(samples)
}

/// Collect a single RDRAND sample with up to MAXIMUM_RDRAND_RETRY_COUNT retries.
#[cfg(target_arch = "x86_64")]
fn collect_single_rdrand_sample() -> Result<u64, EntropyError> {
    for _retry_index in 0..MAXIMUM_RDRAND_RETRY_COUNT {
        if let Some(sample_value) = crate::arch::hardware_registers::execute_rdrand_instruction() {
            return Ok(sample_value);
        }
    }
    Err(EntropyError::HardwareEntropyUnavailable)
}

/// Attempt to collect 4 RDSEED samples.
///
/// Each slot retries up to MAXIMUM_RDSEED_RETRY_COUNT times.
/// Returns None for slots where RDSEED failed (absent or exhausted).
/// This is non-fatal per D-09 (RDSEED is optional).
///
/// Verified by: test_rdseed_fallback_when_unavailable
#[cfg(target_arch = "x86_64")]
pub fn collect_rdseed_samples() -> [Option<u64>; 4] {
    let mut samples = [None; 4];
    for sample_slot in &mut samples {
        *sample_slot = collect_single_rdseed_sample();
    }
    samples
}

/// Attempt a single RDSEED sample with up to MAXIMUM_RDSEED_RETRY_COUNT retries.
#[cfg(target_arch = "x86_64")]
fn collect_single_rdseed_sample() -> Option<u64> {
    for _retry_index in 0..MAXIMUM_RDSEED_RETRY_COUNT {
        if let Some(seed_value) = crate::arch::hardware_registers::execute_rdseed_instruction() {
            return Some(seed_value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pure logic: should_halt returns true when RDRAND is absent.
    #[test]
    fn test_should_halt_when_rdrand_is_absent() {
        let rdrand_is_available = false;
        assert!(should_halt_due_to_absent_rdrand(rdrand_is_available));
    }

    /// Pure logic: should_halt returns false when RDRAND is present.
    #[test]
    fn test_should_not_halt_when_rdrand_is_present() {
        let rdrand_is_available = true;
        assert!(!should_halt_due_to_absent_rdrand(rdrand_is_available));
    }
}
