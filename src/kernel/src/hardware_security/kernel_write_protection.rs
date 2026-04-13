//! Kernel .text and .rodata write-protection after init.
//!
//! Phase 6 Plan 04: Flips kernel .text and .rodata page table entries to read-only
//! at the end of the boot sequence, after all init-time code execution is complete
//! (all IDT handlers registered, APIC timer programmed, scheduler initialized,
//! TPM reseeding complete, PCR measurements done) (D-15). The write-protection is
//! applied as a single atomic pass over the kernel page table entries using the
//! Phase 2 page table machinery.
//!
//! A write to a protected page after init generates a fatal kernel halt via the
//! page fault handler -- not a recoverable error (D-16).
//! Section boundary symbols `_text_start`, `_text_end`, `_rodata_start`, `_rodata_end`
//! are exported by the linker script and used to identify the range to protect.

#[cfg(test)]
mod tests {
    /// SC-02: .text/.rodata pages are read-only after init.
    ///
    /// Phase 6 Plan 04 replaces this stub with the real test.
    #[test]
    #[ignore = "Phase 6 Plan 04 implements this test"]
    fn test_kernel_text_pages_are_read_only_after_init() {
        // SC-02: .text/.rodata pages flipped to read-only after init
    }
}
