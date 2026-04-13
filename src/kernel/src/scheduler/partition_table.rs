//! Compile-time partition table defining CPU time allocation per security domain.
//!
//! The partition table is a `const` array of time slots. Each slot assigns a
//! security domain to a fixed-length CPU time window. The major frame repeats
//! cyclically. The table is measured into TPM PCR[2] at boot (SCHED-05).
