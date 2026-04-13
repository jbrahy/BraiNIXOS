//! Scheduler subsystem initialization during boot.
//!
//! Wires the APIC timer hardware to the scheduler tick loop.
//! Called from the boot sequence after IPC subsystem initialization.

use crate::arch::timer::initialize_apic_timer;
use crate::boot::logger::BootStepLogger;

/// Phase 5 boot step: initializes APIC timer and scheduler state.
///
/// Starts the local APIC timer in periodic mode (see arch::timer::initialize_apic_timer).
/// After this call, the timer fires IRQ 32 periodically to drive scheduler ticks.
/// The partition table is compile-time constant (PARTITION_TABLE in scheduler::mod).
///
/// Enforces INV-SCHED-001: scheduler clock is active before any threads run.
/// Verified by: boot sequence integration (APIC timer fires after boot).
pub fn initialize_scheduler_subsystem(boot_step_logger: &mut BootStepLogger) {
    initialize_apic_timer();
    boot_step_logger.ok("Scheduler initialized (APIC timer periodic, partition table loaded)");
}
