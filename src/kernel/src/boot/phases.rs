//! Boot phase sequence. Each function logs one cohesive boot step.

use crate::boot::logger::BootStepLogger;

/// Run the full boot sequence. Called from `_start` after serial is ready.
pub fn execute_boot_sequence(boot_step_logger: &mut BootStepLogger) {
    log_kernel_banner(boot_step_logger);
    log_boot_infrastructure_status(boot_step_logger);
    log_upcoming_phases(boot_step_logger);
    log_halt_notice(boot_step_logger);
}

fn log_kernel_banner(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.separator();
    boot_step_logger.line(" BRAINIX MICROKERNEL  v0.1.0");
    boot_step_logger.line(" x86_64-unknown-none | Rust nightly-2025-12-01 | Phase 0");
    boot_step_logger.separator();
}

fn log_boot_infrastructure_status(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Serial console initialized (COM1 | 115200 8N1)");
    boot_step_logger.ok("Kernel entry point reached");
    boot_step_logger.info("Build: Phase 0 stub -- boot logging infrastructure online");
}

fn log_upcoming_phases(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.info("Upcoming phases:");
    log_upcoming_phases_one_through_five(boot_step_logger);
    log_upcoming_phases_six_through_nine(boot_step_logger);
}

fn log_upcoming_phases_one_through_five(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.info("  Phase 1: CPU verification, memory map, interrupt handlers");
    boot_step_logger.info("  Phase 2: Physical allocator, KPTI, W^X enforcement");
    boot_step_logger.info("  Phase 3: Capability manager with Kani formal verification");
    boot_step_logger.info("  Phase 4: Synchronous IPC with Prusti verification");
    boot_step_logger.info("  Phase 5: Preemptive scheduler with CPU budgets");
}

fn log_upcoming_phases_six_through_nine(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.info("  Phase 6: Hardware security, TPM attestation chain");
    boot_step_logger.info("  Phase 7: Userspace foundation (init, spawnd, auditd)");
    boot_step_logger.info("  Phase 8: Per-device isolation with bounded capabilities");
    boot_step_logger.info("  Phase 9: Decomposed network stack (linkd, ipd, transportd)");
}

fn log_halt_notice(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.halt("No userspace ready -- halting processor");
}
