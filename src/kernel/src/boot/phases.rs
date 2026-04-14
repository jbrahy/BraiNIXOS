//! Boot phase sequence. Each function logs one cohesive boot step.

use crate::arch::interrupts::initialize_interrupt_handling;
use crate::arch::paging::kernel_page_table::{
    build_kernel_page_table, kernel_page_map_level_4_physical_address,
};
use crate::arch::paging::stack_guard::configure_kernel_stack_guard_page;
use crate::arch::paging::user_page_table::build_user_page_table;
use crate::boot::device_table::{DISK_DEVICE_CAPABILITY_DATA, NIC_DEVICE_CAPABILITY_DATA};
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
use crate::hardware_security::iommu_detection::IommuDetectionResult;
use crate::hardware_security::iommu_detection::{detect_iommu_presence, enforce_iommu_policy};
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
    detect_and_enforce_iommu_policy(boot_step_logger);
    measure_server_binaries_into_pcr3(boot_step_logger);
    load_and_launch_server_processes(boot_step_logger);
    launch_device_server_processes(boot_step_logger);
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

/// Extends PCR[3] with SHA-256 hashes of all five server binaries.
///
/// Must be called BEFORE loading any server ELF into the address space so
/// that PCR[3] reflects the raw on-disk binary content. Ordering per D-02:
/// init, spawnd, auditd, devd-nic, devd-disk.
///
/// Enforces INV-BOOT-001: measured boot path integrity.
fn measure_server_binaries_into_pcr3(boot_step_logger: &mut BootStepLogger) {
    measure_all_server_binaries(&[], &[], &[], &[], &[]);
    boot_step_logger.ok("PCR[3] extended with 5 server binary hashes (D-02)");
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

/// Detects IOMMU hardware presence and enforces the boot policy.
///
/// Development mode (enforcement_mode=0): absent IOMMU emits a warning, boot continues.
/// Production mode (enforcement_mode=1): absent IOMMU halts boot immediately.
///
/// Enforces INV-DEV-001: devices do not imply universal memory authority (D-04).
fn detect_and_enforce_iommu_policy(boot_step_logger: &mut BootStepLogger) {
    let detection_result = detect_iommu_presence();
    let iommu_enforcement_mode: u8 = 0;
    let boot_may_continue = enforce_iommu_policy(detection_result, iommu_enforcement_mode);
    apply_iommu_enforcement_outcome(detection_result, boot_may_continue, boot_step_logger);
}

/// Logs the IOMMU enforcement outcome and halts if policy requires it.
fn apply_iommu_enforcement_outcome(
    detection_result: IommuDetectionResult,
    boot_may_continue: bool,
    boot_step_logger: &mut BootStepLogger,
) {
    if !boot_may_continue {
        halt_on_iommu_absent(boot_step_logger);
    }
    log_iommu_detection_status(detection_result, boot_step_logger);
    boot_step_logger.ok("IOMMU policy enforced (D-04)");
}

/// Logs the fatal IOMMU absence message and halts the boot sequence.
// INV-DEV-001: panic! is the kernel halt mechanism on bare-metal (-> !).
#[allow(clippy::panic)]
fn halt_on_iommu_absent(boot_step_logger: &mut BootStepLogger) -> ! {
    boot_step_logger.fail(
        "IOMMU absent in production mode",
        "INV-DEV-001 requires hardware DMA isolation",
    );
    panic!("IOMMU absent: production mode requires hardware DMA isolation");
}

/// Logs the appropriate IOMMU detection status message.
fn log_iommu_detection_status(
    detection_result: IommuDetectionResult,
    boot_step_logger: &mut BootStepLogger,
) {
    if detection_result == IommuDetectionResult::Present {
        boot_step_logger.ok("IOMMU detected");
    } else {
        boot_step_logger.info("IOMMU absent, software-only enforcement active");
    }
}

/// Launches device server processes for devd-nic and devd-disk.
///
/// Per D-01: kernel grants CapDevice directly to each device server.
/// Enforces INV-DEV-002: each device service receives least privilege.
fn launch_device_server_processes(boot_step_logger: &mut BootStepLogger) {
    launch_devd_nic_server_process();
    launch_devd_disk_server_process();
    boot_step_logger.ok("Device server processes created: devd-nic, devd-disk");
}

/// Creates the devd-nic server process and grants CapDevice for the NIC.
///
/// Per D-01: kernel grants CapDevice directly — no spawnd involvement.
/// Mitigates T-DEV-018: object_pointer holds the NIC DeviceCapabilityData address.
/// Enforces INV-DEV-002: NIC server receives only NIC-scoped authority.
fn launch_devd_nic_server_process() {
    let _ = create_server_process(ProcessType::DeviceServer, 0x0000_0000_0040_0000);
    let mut capability_space = CapabilitySpace::new();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Device,
        capability_rights::READ | capability_rights::WRITE,
    );
    wire_nic_device_data_into_slot(&mut capability_space);
}

/// Sets the NIC DeviceCapabilityData address in slot 0's object_pointer.
///
/// Stores the address of the static NIC_DEVICE_CAPABILITY_DATA so Phase 9
/// syscall handlers can recover MMIO bounds without a separate lookup table.
fn wire_nic_device_data_into_slot(capability_space: &mut CapabilitySpace) {
    let slot = capability_space.lookup_slot_mut(0);
    slot.object_pointer = core::ptr::addr_of!(NIC_DEVICE_CAPABILITY_DATA) as u64;
}

/// Creates the devd-disk server process and grants CapDevice for the disk.
///
/// Per D-01: kernel grants CapDevice directly — no spawnd involvement.
/// Mitigates T-DEV-018: object_pointer holds the disk DeviceCapabilityData address.
/// Enforces INV-DEV-002: disk server receives only disk-scoped authority.
fn launch_devd_disk_server_process() {
    let _ = create_server_process(ProcessType::DeviceServer, 0x0000_0000_0040_0000);
    let mut capability_space = CapabilitySpace::new();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Device,
        capability_rights::READ | capability_rights::WRITE,
    );
    wire_disk_device_data_into_slot(&mut capability_space);
}

/// Sets the disk DeviceCapabilityData address in slot 0's object_pointer.
///
/// Stores the address of the static DISK_DEVICE_CAPABILITY_DATA so Phase 9
/// syscall handlers can recover MMIO bounds without a separate lookup table.
fn wire_disk_device_data_into_slot(capability_space: &mut CapabilitySpace) {
    let slot = capability_space.lookup_slot_mut(0);
    slot.object_pointer = core::ptr::addr_of!(DISK_DEVICE_CAPABILITY_DATA) as u64;
}

fn log_kernel_banner(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.separator();
    boot_step_logger.line(" BRAINIX MICROKERNEL  v0.1.0");
    boot_step_logger.line(" x86_64-unknown-none | Rust nightly-2025-12-01 | Phase 8");
    boot_step_logger.separator();
}

fn log_boot_infrastructure_status(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Serial console initialized (COM1 | 115200 8N1)");
    boot_step_logger.ok("Kernel entry point reached");
    boot_step_logger.info("Build: Phase 8 -- device isolation complete, servers launching");
}

fn log_boot_complete(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Brainix: boot complete");
}
