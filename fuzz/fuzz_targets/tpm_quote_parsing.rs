//! Fuzz target: tpm_quote_parsing
//!
//! Phase 6 Plan 06: exercises parse_tpm_quote_response with adversarial bytes.
//! Any panic or crash here is a security bug (SC-06f).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Parse adversarial TPM quote bytes -- must not panic or crash
    let _ = brainix_kernel::hardware_security::tpm::quote::parse_tpm_quote_response(data);
});
