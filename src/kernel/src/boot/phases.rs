//! Boot phase sequence. Each function logs one cohesive boot step.

use crate::arch::interrupts::initialize_interrupt_handling;
use crate::boot::logger::BootStepLogger;

/// Run the full boot sequence. Called from `_start` after serial is ready.
pub fn execute_boot_sequence(boot_step_logger: &mut BootStepLogger) {
    log_kernel_banner(boot_step_logger);
    log_boot_infrastructure_status(boot_step_logger);
    initialize_interrupt_handling(boot_step_logger);
    log_boot_complete(boot_step_logger);
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

fn log_boot_complete(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Brainix: boot complete");
}

fn log_halt_notice(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.halt("No userspace ready -- halting processor");
}
