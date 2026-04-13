//! PCR[0] and PCR[1] measurement for the kernel binary and config blob.
//!
//! Phase 6 Plan 03: Computes SHA-256 of the kernel .text and .rodata sections
//! using the linker-exported boundary symbols (_text_start, _text_end,
//! _rodata_start, _rodata_end) and extends the result into TPM PCR[0] (D-10).
//! Also computes SHA-256 of the kernel config blob (D-11) and extends into PCR[1].
//!
//! PCR extension ordering is strictly PCR[0] -> PCR[1] -> attestation gate opens (D-14).
//! PCR[2] was already extended in Phase 5 (partition table measurement).
//! PCR[3] is reserved for Phase 7 server binary hashes.
//!
//! Reuses the SHA-256 + TPM extend pattern established in
//! `src/kernel/src/scheduler/measurement.rs`.

#[cfg(test)]
mod tests {}
