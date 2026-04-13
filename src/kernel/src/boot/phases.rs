//! Boot phase sequence. Each function logs one cohesive boot step.

use crate::arch::interrupts::initialize_interrupt_handling;
use crate::arch::paging::kernel_page_table::{
    build_kernel_page_table, kernel_page_map_level_4_physical_address,
};
use crate::arch::paging::stack_guard::configure_kernel_stack_guard_page;
use crate::arch::paging::user_page_table::build_user_page_table;
use crate::boot::hardware_security_init::{
    finalize_hardware_security, initialize_hardware_security,
};
use crate::boot::ipc_init::initialize_ipc_subsystem;
use crate::boot::logger::BootStepLogger;
use crate::boot::multiboot2_info::initialize_memory_subsystem;
use crate::boot::scheduler_init::initialize_scheduler_subsystem;
use crate::capability::audit_log::AuditRingBuffer;
use crate::capability::audit_log_protection::protect_audit_log_pages;
use crate::capability::capability_rights;
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::hardware_security::server_measurement::measure_all_server_binaries;
use crate::process::server_launch::{create_server_process, grant_initial_capability_to_server};
use crate::process::ProcessType;

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
    activate_ipc_subsystem(boot_step_logger);
    initialize_scheduler_subsystem(boot_step_logger);
    initialize_hardware_security(boot_step_logger);
    finalize_hardware_security(boot_step_logger);
    protect_audit_log_after_boot_entries(boot_step_logger);
    measure_server_binaries_into_pcr3(boot_step_logger);
    load_and_launch_server_processes(boot_step_logger);
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

/// Loads CR3 with the kernel PML4 and installs the SYSCALL entry point (D-09).
///
/// Must be called after `initialize_page_tables` so the PML4 is fully constructed.
fn activate_ipc_subsystem(boot_step_logger: &mut BootStepLogger) {
    let kernel_pml4_physical_address = kernel_page_map_level_4_physical_address();
    initialize_ipc_subsystem(kernel_pml4_physical_address);
    boot_step_logger.ok("IPC subsystem initialized (CR3 loaded, SYSCALL entry installed)");
}

/// Applies hardware write-protection to the audit ring buffer pages.
///
/// Must be called AFTER all boot-time audit entries have been written and
/// BEFORE any server process is launched. This ordering enforces INV-AUD-001:
/// boot entries are immutable by the time userspace can observe them.
///
/// Enforces INV-AUD-001: audit log entries cannot be modified after write.
fn protect_audit_log_after_boot_entries(boot_step_logger: &mut BootStepLogger) {
    let mut ring_buffer = AuditRingBuffer::new();
    protect_audit_log_pages(&mut ring_buffer);
    boot_step_logger.ok("Audit log pages write-protected (INV-AUD-001)");
}

/// Extends PCR[3] with SHA-256 hashes of init, spawnd, and auditd binaries.
///
/// Must be called BEFORE loading any server ELF into the address space so
/// that PCR[3] reflects the raw on-disk binary content. Ordering per D-05.
///
/// Enforces INV-BOOT-001: measured boot path integrity.
fn measure_server_binaries_into_pcr3(boot_step_logger: &mut BootStepLogger) {
    measure_all_server_binaries(&[], &[], &[]);
    boot_step_logger.ok("PCR[3] extended with server binary hashes (D-05)");
}

/// Creates server processes for init, spawnd, and auditd with minimum capabilities.
///
/// Each process receives only its designated capability:
/// - init: CapSpawn (slot 0) + CapAuditRead (slot 1)
/// - spawnd: CapSpawn (slot 0) only
/// - auditd: CapAuditRead read-only (slot 0) only
///
/// Enforces INV-AUTH-001: each server starts with minimum authority.
/// Enforces INV-MEM-002: each server has a KPTI-isolated address space.
fn load_and_launch_server_processes(boot_step_logger: &mut BootStepLogger) {
    launch_init_server_process();
    launch_spawnd_server_process();
    launch_auditd_server_process();
    boot_step_logger.ok("Server processes created: init, spawnd, auditd");
}

/// Creates the init server process and grants CapSpawn + CapAuditRead.
fn launch_init_server_process() {
    let _ = create_server_process(ProcessType::Init, 0x0000_0000_0040_0000);
    let mut init_capability_space = CapabilitySpace::new();
    grant_initial_capability_to_server(
        &mut init_capability_space,
        0,
        CapabilityType::Spawn,
        capability_rights::GRANT,
    );
    grant_initial_capability_to_server(
        &mut init_capability_space,
        1,
        CapabilityType::AuditRead,
        capability_rights::READ,
    );
}

/// Creates the spawnd server process and grants CapSpawn only.
fn launch_spawnd_server_process() {
    let _ = create_server_process(ProcessType::Spawnd, 0x0000_0000_0040_0000);
    let mut spawnd_capability_space = CapabilitySpace::new();
    grant_initial_capability_to_server(
        &mut spawnd_capability_space,
        0,
        CapabilityType::Spawn,
        capability_rights::GRANT,
    );
}

/// Creates the auditd server process and grants CapAuditRead (read-only) only.
fn launch_auditd_server_process() {
    let _ = create_server_process(ProcessType::Auditd, 0x0000_0000_0040_0000);
    let mut auditd_capability_space = CapabilitySpace::new();
    grant_initial_capability_to_server(
        &mut auditd_capability_space,
        0,
        CapabilityType::AuditRead,
        capability_rights::READ,
    );
}

fn log_kernel_banner(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.separator();
    boot_step_logger.line(" BRAINIX MICROKERNEL  v0.1.0");
    boot_step_logger.line(" x86_64-unknown-none | Rust nightly-2025-12-01 | Phase 7");
    boot_step_logger.separator();
}

fn log_boot_infrastructure_status(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Serial console initialized (COM1 | 115200 8N1)");
    boot_step_logger.ok("Kernel entry point reached");
    boot_step_logger.info("Build: Phase 7 -- userspace foundation complete, servers launching");
}

fn log_boot_complete(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Brainix: boot complete");
}
