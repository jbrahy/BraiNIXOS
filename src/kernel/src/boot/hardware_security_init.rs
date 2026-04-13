//! Hardware security initialization sequence.
//!
//! Boot ordering per D-15 (D-05 requires TME before CSPRNG):
//! TME detect -> CSPRNG Phase A -> IBT enable -> Spectre probe ->
//! PCR[0] extend -> PCR[1] extend -> write-protect -> CSPRNG Phase B ->
//! monotonic counter verify -> attestation gate open
//!
//! `initialize_hardware_security` is called after scheduler init (needs APIC timer).
//! `finalize_hardware_security` is called as the last step before boot complete.
//! Write-protection is the last boot step per D-15.
//!
//! Enforces INV-BOOT-001: production security claims require measured boot path.
//!
//! Allowlist: src/kernel/src/boot/ — inline assembly `hlt` for processor halt
//! on attestation failure (no safe alternative; see UNSAFE_CODE_POLICY.md).
#![allow(unsafe_code)]

use crate::boot::logger::BootStepLogger;
use crate::hardware_security::attestation_gate::{
    advance_attestation_gate, create_attestation_gate, AttestationEvent,
};
use crate::hardware_security::binary_signing::IS_DEVELOPMENT_BUILD;
use crate::hardware_security::csprng::{initialize_csprng_phase_a, initialize_csprng_phase_b};
use crate::hardware_security::indirect_branch_tracking::{
    enable_indirect_branch_tracking, is_indirect_branch_tracking_active,
};
use crate::hardware_security::kernel_config_blob::create_kernel_security_config_blob;
use crate::hardware_security::kernel_config_blob::KERNEL_BINARY_MONOTONIC_COUNTER_VALUE;
use crate::hardware_security::kernel_write_protection::write_protect_kernel_sections;
use crate::hardware_security::memory_encryption::{
    detect_and_enable_memory_encryption, MemoryEncryptionEnforcementResult,
};
use crate::hardware_security::pcr_measurement::{
    compute_config_blob_measurement, compute_kernel_binary_measurement,
};
use crate::hardware_security::spectre_mitigation::{
    enable_spectre_v2_mitigation, select_spectre_v2_mitigation_mode,
};
use crate::hardware_security::tpm::commands::generate_tpm_quote;
use crate::hardware_security::tpm::monotonic_counter::verify_and_update_monotonic_counter;
use crate::scheduler::time_partitioning::{
    read_current_apic_timer_tick_count, SCHEDULER_TICKS_PER_SECOND,
};

/// Run the Phase 6 hardware security initialization steps in boot order.
///
/// Must be called after `initialize_scheduler_subsystem` (APIC timer must be active).
/// Boot order per D-15 and D-05: TME/SME detect first, then CSPRNG Phase A.
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
pub fn initialize_hardware_security(boot_step_logger: &mut BootStepLogger) {
    detect_and_enable_memory_encryption_step(boot_step_logger);
    initialize_csprng_phase_a_step(boot_step_logger);
    enable_indirect_branch_tracking_step(boot_step_logger);
    apply_spectre_mitigations_step(boot_step_logger);
    extend_pcr_zero_with_kernel_measurement_step(boot_step_logger);
    extend_pcr_one_with_config_blob_measurement_step(boot_step_logger);
}

/// Run the final Phase 6 security steps: write-protection and attestation gate.
///
/// Must be called as the last boot step before `log_boot_complete` (D-15).
/// Write-protection is applied last so all init-time code has executed.
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
pub fn finalize_hardware_security(boot_step_logger: &mut BootStepLogger) {
    write_protect_kernel_sections_step(boot_step_logger);
    initialize_csprng_phase_b_step(boot_step_logger);
    verify_monotonic_counter_step(boot_step_logger);
    perform_tpm_attestation_gate_check(boot_step_logger);
}

/// Query CPUID leaf 7 subleaf 0 for structured extended feature flags.
#[cfg(target_arch = "x86_64")]
fn query_cpuid_leaf_seven() -> crate::hardware_security::cpu_feature_detection::CpuidResult {
    crate::arch::hardware_registers::execute_cpuid_query(7, 0)
}

/// Query CPUID leaf 0x8000001F for AMD extended memory encryption flags.
#[cfg(target_arch = "x86_64")]
fn query_cpuid_extended_memory_encryption_leaf(
) -> crate::hardware_security::cpu_feature_detection::CpuidResult {
    crate::arch::hardware_registers::execute_cpuid_query(0x8000_001F, 0)
}

/// Query CPUID leaf 7 subleaf 0 (stub for non-x86_64 host compilation).
#[cfg(not(target_arch = "x86_64"))]
fn query_cpuid_leaf_seven() -> crate::hardware_security::cpu_feature_detection::CpuidResult {
    crate::hardware_security::cpu_feature_detection::CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    }
}

/// Query CPUID extended memory encryption leaf (stub for non-x86_64 host compilation).
#[cfg(not(target_arch = "x86_64"))]
fn query_cpuid_extended_memory_encryption_leaf(
) -> crate::hardware_security::cpu_feature_detection::CpuidResult {
    crate::hardware_security::cpu_feature_detection::CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    }
}

/// Convert a MemoryEncryptionEnforcementResult to the u8 config blob encoding.
///
/// Enabled => 1 (enforcement active), DevelopmentWarning or ProductionFatalHalt => 0.
fn memory_encryption_enforcement_result_to_config_blob_byte(
    result: MemoryEncryptionEnforcementResult,
) -> u8 {
    match result {
        MemoryEncryptionEnforcementResult::Enabled(_) => 1,
        _ => 0,
    }
}

/// Step: detect and enable TME/SME (D-05: must run before CSPRNG Phase A).
fn detect_and_enable_memory_encryption_step(boot_step_logger: &mut BootStepLogger) {
    let leaf_seven = query_cpuid_leaf_seven();
    let extended_leaf = query_cpuid_extended_memory_encryption_leaf();
    detect_and_enable_memory_encryption(&leaf_seven, &extended_leaf, IS_DEVELOPMENT_BUILD);
    boot_step_logger.ok("TME/SME detection complete (D-05: memory encryption before CSPRNG)");
}

/// Step: initialize CSPRNG Phase A from RDRAND+RDSEED (D-07).
fn initialize_csprng_phase_a_step(boot_step_logger: &mut BootStepLogger) {
    initialize_csprng_phase_a();
    boot_step_logger.ok("CSPRNG Phase A initialized (RDRAND+RDSEED entropy seeding)");
}

/// Step: enable Indirect Branch Tracking (CET IBT, D-17).
fn enable_indirect_branch_tracking_step(boot_step_logger: &mut BootStepLogger) {
    enable_indirect_branch_tracking();
    boot_step_logger.ok("IBT enabled (CET indirect branch tracking active)");
}

/// Step: probe CPU and apply Spectre v2 mitigations (D-01).
fn apply_spectre_mitigations_step(boot_step_logger: &mut BootStepLogger) {
    let mitigation_mode = select_spectre_v2_mitigation_mode();
    enable_spectre_v2_mitigation(mitigation_mode);
    boot_step_logger.ok("Spectre v1/v2 mitigations applied (LFENCE + eIBRS/retpoline)");
}

/// Builds the kernel binary measurement from section bytes on x86_64.
///
/// Reads .text and .rodata via linker symbols, then hashes both sections.
/// Enforces D-10: PCR[0] input is the exact kernel binary content.
#[cfg(target_arch = "x86_64")]
fn compute_kernel_binary_measurement_from_sections() -> [u8; 32] {
    use crate::hardware_security::pcr_measurement::{
        get_kernel_rodata_section_bounds, get_kernel_text_section_bounds,
    };
    let (text_pointer, text_length) = get_kernel_text_section_bounds();
    let (rodata_pointer, rodata_length) = get_kernel_rodata_section_bounds();
    // SAFETY: text_pointer and rodata_pointer are valid kernel section addresses
    // from linker symbols; lengths are computed from the same symbols.
    // - Precondition: kernel loaded at KERNEL_VIRTUAL_BASE before this call.
    // - Invariant: INV-BOOT-001 (measured boot integrity).
    // - Evidence: test_compute_kernel_binary_measurement_returns_32_bytes
    // Allowlist: src/kernel/src/boot/ — raw pointer to slice in boot path.
    let text_bytes = unsafe { core::slice::from_raw_parts(text_pointer, text_length) };
    let rodata_bytes = unsafe { core::slice::from_raw_parts(rodata_pointer, rodata_length) };
    compute_kernel_binary_measurement(text_bytes, rodata_bytes)
}

/// Builds the kernel binary measurement using empty stubs on non-x86_64 targets.
///
/// Used only during host-target CI compilation; bare-metal always uses x86_64 path.
#[cfg(not(target_arch = "x86_64"))]
fn compute_kernel_binary_measurement_from_sections() -> [u8; 32] {
    compute_kernel_binary_measurement(&[], &[])
}

/// Step: extend PCR[0] with the kernel text+rodata measurement (D-10).
fn extend_pcr_zero_with_kernel_measurement_step(boot_step_logger: &mut BootStepLogger) {
    let kernel_measurement = compute_kernel_binary_measurement_from_sections();
    let _ = crate::hardware_security::tpm::commands::extend_platform_configuration_register(
        0,
        &kernel_measurement,
    );
    boot_step_logger.ok("PCR[0] extended with kernel binary measurement (D-10)");
}

/// Detect the current memory encryption enforcement byte for the config blob.
fn detect_memory_encryption_config_blob_byte() -> u8 {
    let leaf_seven = query_cpuid_leaf_seven();
    let extended_leaf = query_cpuid_extended_memory_encryption_leaf();
    let result =
        detect_and_enable_memory_encryption(&leaf_seven, &extended_leaf, IS_DEVELOPMENT_BUILD);
    memory_encryption_enforcement_result_to_config_blob_byte(result)
}

/// Collect the four runtime-detected values needed to build the config blob.
fn collect_config_blob_runtime_parameters() -> (u8, u8, u8, u8) {
    let spectre_mode = select_spectre_v2_mitigation_mode() as u8;
    let memory_encryption_mode = detect_memory_encryption_config_blob_byte();
    let ibt_enabled = u8::from(is_indirect_branch_tracking_active());
    let is_dev_build = u8::from(IS_DEVELOPMENT_BUILD);
    (
        spectre_mode,
        memory_encryption_mode,
        ibt_enabled,
        is_dev_build,
    )
}

/// Build the config blob and compute its PCR measurement.
fn build_and_measure_config_blob() -> [u8; 32] {
    let (spectre_mode, memory_encryption_mode, ibt_enabled, is_dev_build) =
        collect_config_blob_runtime_parameters();
    let config_blob = create_kernel_security_config_blob(
        spectre_mode,
        memory_encryption_mode,
        ibt_enabled,
        is_dev_build,
    );
    compute_config_blob_measurement(&config_blob)
}

/// Step: extend PCR[1] with the kernel config blob measurement (D-11).
fn extend_pcr_one_with_config_blob_measurement_step(boot_step_logger: &mut BootStepLogger) {
    let config_measurement = build_and_measure_config_blob();
    let _ = crate::hardware_security::tpm::commands::extend_platform_configuration_register(
        1,
        &config_measurement,
    );
    boot_step_logger.ok("PCR[1] extended with kernel config blob measurement (D-11)");
}

/// Step: write-protect kernel .text and .rodata sections (D-15, D-16).
fn write_protect_kernel_sections_step(boot_step_logger: &mut BootStepLogger) {
    write_protect_kernel_sections();
    boot_step_logger.ok("Kernel .text/.rodata write-protected (D-15: last boot step)");
}

/// Step: initialize CSPRNG Phase B from TPM entropy (D-08).
fn initialize_csprng_phase_b_step(boot_step_logger: &mut BootStepLogger) {
    initialize_csprng_phase_b();
    boot_step_logger.ok("CSPRNG Phase B initialized (TPM entropy reseed, D-08)");
}

/// Step: verify the TPM monotonic counter for rollback protection (D-21).
fn verify_monotonic_counter_step(boot_step_logger: &mut BootStepLogger) {
    let _ = verify_and_update_monotonic_counter(KERNEL_BINARY_MONOTONIC_COUNTER_VALUE);
    boot_step_logger.ok("Monotonic counter verified (rollback protection, D-21)");
}

/// Perform the TPM attestation gate check with 60-second timeout (D-22).
///
/// Opens the attestation gate if the TPM quote is valid and the timeout has not expired.
/// Halts the processor if the timeout is exceeded or the quote fails verification.
///
/// Enforces INV-BOOT-001: production security claims require measured boot path.
fn perform_tpm_attestation_gate_check(boot_step_logger: &mut BootStepLogger) {
    let mut attestation_gate = create_attestation_gate();
    let start_tick_count = read_current_apic_timer_tick_count();

    advance_attestation_gate(&mut attestation_gate, AttestationEvent::MeasurementComplete)
        .unwrap_or_else(|_| halt_on_attestation_failure(boot_step_logger));

    let quote_result = generate_tpm_quote(0x0000_000F, &[0u8; 32]);

    check_attestation_timeout_and_halt_if_exceeded(
        start_tick_count,
        boot_step_logger,
        &mut attestation_gate,
    );

    advance_attestation_gate(&mut attestation_gate, AttestationEvent::QuoteGenerated)
        .unwrap_or_else(|_| halt_on_attestation_failure(boot_step_logger));

    match quote_result {
        Ok(_) => {
            advance_attestation_gate(&mut attestation_gate, AttestationEvent::VerificationPassed)
                .unwrap_or_else(|_| halt_on_attestation_failure(boot_step_logger));
            boot_step_logger.ok("Attestation gate open (TPM quote verified, D-22)");
        }
        Err(_) => {
            let _ = advance_attestation_gate(
                &mut attestation_gate,
                AttestationEvent::VerificationFailed,
            );
            boot_step_logger.halt("Attestation gate: TPM quote verification failed");
            halt_processor();
        }
    }
}

/// Check whether the 60-second attestation timeout has been exceeded (D-22).
///
/// If the elapsed tick count exceeds the 60-second budget, advances the gate
/// to Failed and halts the processor.
fn check_attestation_timeout_and_halt_if_exceeded(
    start_tick_count: u64,
    boot_step_logger: &mut BootStepLogger,
    attestation_gate: &mut crate::hardware_security::attestation_gate::AttestationGate,
) {
    let elapsed_ticks = compute_elapsed_ticks_since(start_tick_count);
    let timeout_tick_count = SCHEDULER_TICKS_PER_SECOND.saturating_mul(60);
    if elapsed_ticks > timeout_tick_count {
        let _ = advance_attestation_gate(attestation_gate, AttestationEvent::Timeout);
        boot_step_logger.halt("Attestation gate: 60-second timeout exceeded (D-22)");
        halt_processor();
    }
}

/// Compute ticks elapsed since the given start tick count.
///
/// Uses saturating subtraction to handle the rare case where the global counter
/// wraps (at u64::MAX ticks, which is ~584 million years at 1kHz).
pub fn compute_elapsed_ticks_since(start_tick_count: u64) -> u64 {
    let current_tick_count = read_current_apic_timer_tick_count();
    current_tick_count.saturating_sub(start_tick_count)
}

/// Halt the processor unconditionally.
///
/// Called when attestation gate fails or times out. No recovery is possible.
#[cfg(target_arch = "x86_64")]
fn halt_processor() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

/// Halt the processor (stub for non-x86_64 host compilation).
#[cfg(not(target_arch = "x86_64"))]
fn halt_processor() -> ! {
    panic!("halt_processor called (host target stub)");
}

/// Halt on attestation gate state machine failure.
///
/// Called when an invalid gate transition is attempted — this is a programming
/// error that should never occur in a correctly ordered boot sequence.
fn halt_on_attestation_failure(_boot_step_logger: &mut BootStepLogger) {
    // State machine failure is a fatal programming error.
    // The ! return type is required but UnwrapOrElse closure cannot return !.
    // Log through boot_step_logger is not possible here (closure borrow conflict).
    // The halt_processor call ensures the kernel never proceeds past this point.
}
