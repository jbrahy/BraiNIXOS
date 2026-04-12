//! Boot phase sequence. Each function logs one cohesive boot step.

use crate::arch::interrupts::initialize_interrupt_handling;
use crate::arch::paging::kernel_page_table::build_kernel_page_table;
use crate::arch::paging::stack_guard::configure_kernel_stack_guard_page;
use crate::arch::paging::user_page_table::build_user_page_table;
use crate::boot::logger::BootStepLogger;
use crate::boot::multiboot2_info::initialize_memory_subsystem;

/// Run the full boot sequence. Called from `_start` after serial is ready.
pub fn execute_boot_sequence(
    multiboot2_magic_value: u32,
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    log_kernel_banner(boot_step_logger);
    log_boot_infrastructure_status(boot_step_logger);
    initialize_interrupt_handling(boot_step_logger);
    initialize_memory_subsystem(
        multiboot2_magic_value,
        multiboot2_info_address,
        boot_step_logger,
    );
    initialize_page_tables(boot_step_logger);
    log_boot_complete(boot_step_logger);
}

/// Constructs the kernel and user page table hierarchies and verifies guard pages.
///
/// Does NOT load either table into CR3 -- CR3 switching is deferred to Phase 4 (D-08).
fn initialize_page_tables(boot_step_logger: &mut BootStepLogger) {
    build_kernel_page_table(boot_step_logger);
    build_user_page_table(boot_step_logger);
    configure_kernel_stack_guard_page(boot_step_logger);
    boot_step_logger.ok("Page tables constructed (KPTI structure ready)");
}

fn log_kernel_banner(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.separator();
    boot_step_logger.line(" BRAINIX MICROKERNEL  v0.1.0");
    boot_step_logger.line(" x86_64-unknown-none | Rust nightly-2025-12-01 | Phase 2");
    boot_step_logger.separator();
}

fn log_boot_infrastructure_status(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Serial console initialized (COM1 | 115200 8N1)");
    boot_step_logger.ok("Kernel entry point reached");
    boot_step_logger.info("Build: Phase 2 -- GDT/TSS/IDT initialized");
}

fn log_boot_complete(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Brainix: boot complete");
}
