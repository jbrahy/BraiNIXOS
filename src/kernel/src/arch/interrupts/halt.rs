//! Shared halt helper for kernel fault and panic paths.
//!
//! Provides a single canonical implementation of the cli+hlt loop used by
//! both the panic handler (main.rs) and all CPU exception handlers
//! (interrupt_descriptor_table.rs). Consolidating here prevents the pattern
//! from diverging across call sites.
//!
//! Allowlist: `src/kernel/src/arch/interrupts/` — cli/sti interrupt flag
//! manipulation requires direct CPU instruction access.
#![allow(unsafe_code)]

/// Disable interrupts and halt the processor in an infinite loop.
///
/// Issues `cli` to prevent interrupts from firing during the halt, then `hlt`
/// to suspend the processor. The loop ensures we never return if an NMI or
/// similar wakes the processor.
///
/// Enforces invariant INV-FAULT-003: fault handlers do not return to corrupted
/// state; they halt the processor with interrupts disabled.
///
/// # Safety
/// Caller must be executing in ring 0. This function never returns.
///
/// Verified by: test_panic_handler_disables_interrupts_before_halt;
/// QEMU integration test observes halt after fault injection.
// SAFETY: cli and hlt are privileged instructions available only in ring 0.
// - Precondition: executing in ring 0 (kernel context).
// - Invariant: INV-FAULT-003 (fault handlers halt with interrupts disabled).
// - Evidence: test_panic_handler_disables_interrupts_before_halt.
// Allowlist: src/kernel/src/arch/interrupts/ — cli/hlt halt loop.
pub fn disable_interrupts_and_halt() -> ! {
    loop {
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}
