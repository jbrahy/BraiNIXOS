//! Boot phase sequence. Each function logs one cohesive boot step.
//!
//! Falls under `src/kernel/src/boot/phases.rs` allowlist entry in
//! `docs/security/UNSAFE_CODE_POLICY.md`.
#![allow(unsafe_code)]

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
use crate::boot::server_measurement::extract_module_byte_slices_from_boot_information;
use crate::capability::audit_log::AuditRingBuffer;
use crate::capability::audit_log_protection::protect_audit_log_pages;
use crate::capability::capability_rights;
use crate::capability::capability_rights::CapabilityRights;
use crate::capability::capability_space::CapabilitySpace;
use crate::capability::capability_type::CapabilityType;
use crate::hardware_security::iommu_detection::IommuDetectionResult;
use crate::hardware_security::iommu_detection::{detect_iommu_presence, enforce_iommu_policy};
use crate::hardware_security::server_measurement::measure_all_server_binaries;
use crate::ipc::endpoint::ThreadIdentifier;
use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;
use crate::process::server_launch::{create_server_process, grant_initial_capability_to_server};
use crate::process::ProcessType;
use crate::syscall::kernel_ipc_state;

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
    // CR3 swap inside `activate_ipc_subsystem` has retired the bootloader's
    // identity map. The multiboot2 info structure (and module bytes the
    // bootloader copied for PCR[3] measurement) live at physical addresses
    // that are now reachable only through the direct-map region.
    let multiboot2_info_address = DIRECT_MAP_REGION_START.wrapping_add(multiboot2_info_address);
    initialize_scheduler_subsystem(boot_step_logger);
    initialize_hardware_security(boot_step_logger);
    finalize_hardware_security(boot_step_logger);
    protect_audit_log_after_boot_entries(boot_step_logger);
    detect_and_enforce_iommu_policy(boot_step_logger);
    measure_server_binaries_into_pcr3(multiboot2_info_address, boot_step_logger);
    initialize_kernel_ipc_globals(boot_step_logger);
    allocate_network_stack_endpoints(boot_step_logger);
    probe_pci_devices(boot_step_logger);
    load_and_launch_server_processes(boot_step_logger);
    launch_device_server_processes(boot_step_logger);
    launch_network_server_processes(boot_step_logger);
    let shell_thread_index = launch_shell_server_process(multiboot2_info_address, boot_step_logger);
    log_boot_complete(boot_step_logger);
    dispatch_shell_to_userspace(shell_thread_index, boot_step_logger);
}

/// Loads the shell thread's saved entry point, user stack, and user page table,
/// then SYSRETs into ring 3 through the KPTI trampoline. Never returns — this is
/// the end of the boot path; from here the shell runs and drives the console.
#[allow(clippy::unwrap_used)]
fn dispatch_shell_to_userspace(thread_index: usize, boot_step_logger: &mut BootStepLogger) -> ! {
    boot_step_logger.ok("Dispatching shell to userspace (ring 3)");
    // SAFETY: single-core boot; thread_index is the shell created just above and
    // is < MAXIMUM_THREADS. The accessor borrows the kernel thread pool exclusively.
    let shell_thread = unsafe { kernel_ipc_state::kernel_thread_at_mut(thread_index) }.unwrap();
    let entry_point = shell_thread.register_save_area.register_rcx;
    let user_stack_top = shell_thread.register_save_area.register_rsp;
    let user_page_table = shell_thread.user_page_table_physical_address;
    // SAFETY: the shell's user PML4 maps its entry point, stack, and (via
    // map_trampoline_into_user_page_table) the supervisor trampoline pages.
    unsafe {
        crate::arch::syscall_trampoline::enter_userspace(
            thread_index as u32,
            entry_point,
            user_stack_top,
            user_page_table,
        )
    }
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
    crate::arch::syscall_trampoline::record_kernel_trampoline_state();
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

/// Extends PCR[3] with SHA-256 hashes of all eight server binaries.
///
/// Must be called BEFORE loading any server ELF into the address space so
/// that PCR[3] reflects the raw on-disk binary content. Ordering per D-02:
/// init, spawnd, auditd, devd-nic, devd-disk, linkd, ipd, transportd.
///
/// Enforces INV-BOOT-001: measured boot path integrity.
fn measure_server_binaries_into_pcr3(
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) {
    let module_slices = extract_module_byte_slices_from_boot_information(multiboot2_info_address);
    pass_module_slices_to_pcr3_measurement(&module_slices);
    boot_step_logger.ok("PCR[3] extended with 8 server binary hashes (real module bytes)");
}

/// Passes the 8 module byte slices to measure_all_server_binaries.
fn pass_module_slices_to_pcr3_measurement(module_slices: &[&[u8]; 8]) {
    measure_all_server_binaries(
        module_slices[0],
        module_slices[1],
        module_slices[2],
        module_slices[3],
        module_slices[4],
        module_slices[5],
        module_slices[6],
        module_slices[7],
    );
}

/// Initializes kernel IPC state globals: EndpointPool and ProcessTable.
///
/// Must be called before any server launch or IPC dispatch.
/// Enforces INV-IPC-001: IPC infrastructure ready before dispatch.
fn initialize_kernel_ipc_globals(boot_step_logger: &mut BootStepLogger) {
    // SAFETY: Single-core boot. Called exactly once before server launches.
    // Precondition: kernel BSS is zeroed (standard for static mut).
    // Invariant: INV-IPC-001 (endpoint pool ready), INV-AUTH-001 (process table ready).
    // Evidence: integration test in Plan 05.
    unsafe {
        kernel_ipc_state::initialize_kernel_endpoint_pool();
        kernel_ipc_state::initialize_kernel_process_table();
    }
    boot_step_logger.ok("Kernel IPC globals initialized (endpoint pool + process table)");
}

/// Documents the network stack endpoint index assignments (D-04).
///
/// Endpoint 0: devd-nic <-> linkd
/// Endpoint 1: linkd <-> ipd
/// Endpoint 2: ipd <-> transportd
///
/// EndpointPool::new() initializes all 16 endpoints. Indices 0-2 are
/// reserved for the network stack chain. No explicit allocation needed.
/// Enforces D-04: three endpoints for network stack IPC chain.
/// Enumerates PCI bus 0 and logs each virtio device's location, device ID, and
/// BAR0/BAR4 — so the MMIO bases hardcoded in `device_table.rs` can be validated
/// against the real topology before a CapDevice is granted to a device server.
///
/// Discovery only: the kernel never drives the devices (drivers live in
/// userspace devd-nic / devd-disk).
fn probe_pci_devices(boot_step_logger: &mut BootStepLogger) {
    use crate::arch::pci::{
        for_each_device_on_bus_zero, read_base_address_register, VIRTIO_PCI_VENDOR_ID,
    };
    let _ = VIRTIO_PCI_VENDOR_ID;
    for_each_device_on_bus_zero(|location| {
        // Pack vendor:device into one word, and log BAR0 so both the virtio
        // disk and the Intel e1000 NIC (vendor 0x8086) topology are visible.
        let vendor_device = ((location.vendor_id as u64) << 16) | (location.device_id as u64);
        let bus_device_function = ((location.bus as u64) << 16)
            | ((location.device as u64) << 8)
            | (location.function as u64);
        boot_step_logger.info_hex("PCI dev (bus<<16|dev<<8|fn)", bus_device_function);
        boot_step_logger.info_hex("  vendor:device", vendor_device);
        boot_step_logger.info_hex("  BAR0", read_base_address_register(location, 0) as u64);
    });
    boot_step_logger.ok("PCI bus 0 enumerated (device topology logged)");

    match crate::arch::e1000::initialize_nic() {
        Some(nic) => {
            let mac = nic.mac_address();
            let mac_word = ((mac[0] as u64) << 40)
                | ((mac[1] as u64) << 32)
                | ((mac[2] as u64) << 24)
                | ((mac[3] as u64) << 16)
                | ((mac[4] as u64) << 8)
                | (mac[5] as u64);
            boot_step_logger.info_hex("e1000 MMIO base", nic.mmio_base_address());
            boot_step_logger.info_hex("e1000 MAC", mac_word);
            boot_step_logger.ok("e1000 NIC initialized (MMIO mapped, reset, MAC read)");
            if let Some(gateway_mac) = resolve_gateway_via_arp(&nic, mac, boot_step_logger) {
                ping_gateway_via_icmp(&nic, mac, gateway_mac, boot_step_logger);
                query_dns_via_udp(&nic, mac, gateway_mac, boot_step_logger);
            }
            discover_ipv6_router(&nic, mac, boot_step_logger);
        }
        None => boot_step_logger.warn("e1000 NIC not found"),
    }

    // Block device + credential store — always, independent of networking.
    match crate::arch::virtio_blk::initialize_block_device() {
        Some(device) => {
            boot_step_logger.info_hex("virtio-blk io_base", device.io_base_port() as u64);
            boot_step_logger.info_hex("virtio-blk sectors", device.capacity_in_sectors());
            boot_step_logger.ok("virtio-blk device initialized (reset + feature handshake)");
            crate::boot::credential_store::initialize_credential_store(device, boot_step_logger);
            log_credential_store_status(boot_step_logger);
        }
        None => boot_step_logger.warn("virtio-blk device not found"),
    }
}

/// Network constants for the QEMU slirp environment.
const OUR_IPV4: [u8; 4] = [10, 0, 2, 15];
const GATEWAY_IPV4: [u8; 4] = [10, 0, 2, 2];

/// ARP-resolves the slirp gateway (10.0.2.2): sends a broadcast ARP request and
/// polls the RX ring for the reply, proving TX, RX, and ARP. Returns the
/// learned gateway MAC (expected 52:55:0a:00:02:02), or None.
fn resolve_gateway_via_arp(
    nic: &crate::arch::e1000::E1000Device,
    our_mac: [u8; 6],
    boot_step_logger: &mut BootStepLogger,
) -> Option<[u8; 6]> {
    let request = crate::net::build_arp_request(our_mac, OUR_IPV4, GATEWAY_IPV4);
    if !nic.send_frame(&request) {
        boot_step_logger.warn("ARP: gateway request transmit did not complete");
        return None;
    }
    let mut frame = [0u8; 2048];
    for _attempt in 0..10_000_000u64 {
        if let Some(length) = nic.poll_receive(&mut frame) {
            if let Some(gateway_mac) = crate::net::parse_arp_reply(&frame[..length], GATEWAY_IPV4) {
                let mac_word = ((gateway_mac[0] as u64) << 40)
                    | ((gateway_mac[1] as u64) << 32)
                    | ((gateway_mac[2] as u64) << 24)
                    | ((gateway_mac[3] as u64) << 16)
                    | ((gateway_mac[4] as u64) << 8)
                    | (gateway_mac[5] as u64);
                boot_step_logger.info_hex("ARP gateway 10.0.2.2 MAC", mac_word);
                boot_step_logger.ok("Networking: ARP resolved gateway (TX+RX verified)");
                return Some(gateway_mac);
            }
        }
        core::hint::spin_loop();
    }
    boot_step_logger.warn("ARP: no gateway reply received");
    None
}

/// Sends an IPv4 ICMP echo request ("ping") to the gateway and polls for the
/// echo reply — proving the IPv4 + ICMP datapath end-to-end.
fn ping_gateway_via_icmp(
    nic: &crate::arch::e1000::E1000Device,
    our_mac: [u8; 6],
    gateway_mac: [u8; 6],
    boot_step_logger: &mut BootStepLogger,
) {
    const ICMP_IDENTIFIER: u16 = 0x4252;
    const ICMP_SEQUENCE: u16 = 1;
    let mut frame = [0u8; crate::net::ICMP_PING_FRAME_LENGTH];
    let length = crate::net::build_icmp_ping_frame(
        gateway_mac,
        our_mac,
        OUR_IPV4,
        GATEWAY_IPV4,
        ICMP_IDENTIFIER,
        ICMP_SEQUENCE,
        &mut frame,
    );
    if !nic.send_frame(&frame[..length]) {
        boot_step_logger.warn("ICMP: ping transmit did not complete");
        return;
    }
    let mut reply = [0u8; 2048];
    for _attempt in 0..10_000_000u64 {
        if let Some(received) = nic.poll_receive(&mut reply) {
            if crate::net::is_icmp_echo_reply(
                &reply[..received],
                GATEWAY_IPV4,
                ICMP_IDENTIFIER,
                ICMP_SEQUENCE,
            ) {
                boot_step_logger.ok("Networking: ICMP echo reply from gateway (IPv4 ping works)");
                return;
            }
        }
        core::hint::spin_loop();
    }
    boot_step_logger.warn("ICMP: no echo reply from gateway");
}

/// Sends a DNS A-query for example.com to slirp's DNS server (10.0.2.3:53) over
/// UDP and polls for the response — proving the UDP datapath end-to-end.
fn query_dns_via_udp(
    nic: &crate::arch::e1000::E1000Device,
    our_mac: [u8; 6],
    gateway_mac: [u8; 6],
    boot_step_logger: &mut BootStepLogger,
) {
    const DNS_SERVER_IPV4: [u8; 4] = [10, 0, 2, 3];
    const EPHEMERAL_PORT: u16 = 0xC000;
    const DNS_PORT: u16 = 53;
    // example.com in DNS label form.
    let question_name: &[u8] = b"\x07example\x03com\x00";
    let mut query = [0u8; 64];
    let query_length = crate::net::udp::build_dns_query(0xB2A1, question_name, &mut query);

    let mut frame = [0u8; 256];
    let frame_length = crate::net::build_udp_ipv4_frame(
        gateway_mac,
        our_mac,
        OUR_IPV4,
        DNS_SERVER_IPV4,
        EPHEMERAL_PORT,
        DNS_PORT,
        &query[..query_length],
        &mut frame,
    );
    if !nic.send_frame(&frame[..frame_length]) {
        boot_step_logger.warn("UDP/DNS: query transmit did not complete");
        return;
    }
    let mut reply = [0u8; 2048];
    for _attempt in 0..10_000_000u64 {
        if let Some(received) = nic.poll_receive(&mut reply) {
            if crate::net::is_udp_response(
                &reply[..received],
                DNS_SERVER_IPV4,
                DNS_PORT,
                EPHEMERAL_PORT,
            ) {
                boot_step_logger.ok("Networking: DNS response received over UDP (UDP works)");
                return;
            }
        }
        core::hint::spin_loop();
    }
    boot_step_logger.warn("UDP/DNS: no response from DNS server");
}

/// Sends an IPv6 Router Solicitation and polls for a Router Advertisement,
/// proving the IPv6 + ICMPv6/NDP datapath end-to-end.
fn discover_ipv6_router(
    nic: &crate::arch::e1000::E1000Device,
    our_mac: [u8; 6],
    boot_step_logger: &mut BootStepLogger,
) {
    let mut frame = [0u8; 128];
    let length = crate::net::ipv6::build_router_solicitation_frame(our_mac, &mut frame);
    if !nic.send_frame(&frame[..length]) {
        boot_step_logger.warn("IPv6: router solicitation transmit did not complete");
        return;
    }
    let mut reply = [0u8; 2048];
    for _attempt in 0..10_000_000u64 {
        if let Some(received) = nic.poll_receive(&mut reply) {
            if crate::net::ipv6::is_router_advertisement(&reply[..received]) {
                boot_step_logger.ok("Networking: IPv6 router advertisement received (IPv6/NDP works)");
                return;
            }
        }
        core::hint::spin_loop();
    }
    boot_step_logger.warn("IPv6: no router advertisement received");
}

/// Sanity-logs the loaded credential store: confirms the default password
/// verifies for root and whether root still owes a forced change. (Diagnostic;
/// reveals nothing secret — the default password is public.)
fn log_credential_store_status(boot_step_logger: &mut BootStepLogger) {
    match crate::boot::credential_store::verify_login(b"root", b"brainxos") {
        Some((_user, must_change)) if must_change => {
            boot_step_logger.ok("Credential check: root/brainxos valid, change required")
        }
        Some((_user, _)) => {
            boot_step_logger.ok("Credential check: root/brainxos valid, already changed")
        }
        None => boot_step_logger.info("Credential check: root default password no longer valid"),
    }
}

fn allocate_network_stack_endpoints(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Network stack endpoints reserved (indices 0=nic<->linkd, 1=linkd<->ipd, 2=ipd<->transportd)");
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
///
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
// Boot-time, infallible by construction: canonical entry point and the thread
// pool has capacity for every boot server. A failure here is an unrecoverable
// boot fault, so `unwrap` (panic = abort) is the correct response.
#[allow(clippy::unwrap_used)]
fn launch_init_server_process() {
    let (handle, mut capability_space) =
        create_server_process(ProcessType::Init, 0x0000_0000_0040_0000).unwrap();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Spawn,
        capability_rights::GRANT,
    );
    grant_init_audit_read_capability(&mut capability_space);
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
}

/// Grants CapAuditRead (read-only) into init's slot 1.
fn grant_init_audit_read_capability(capability_space: &mut CapabilitySpace) {
    grant_initial_capability_to_server(
        capability_space,
        1,
        CapabilityType::AuditRead,
        capability_rights::READ,
    );
}

/// Creates the spawnd server process and grants CapSpawn only.
///
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_spawnd_server_process() {
    let (handle, mut capability_space) =
        create_server_process(ProcessType::Spawnd, 0x0000_0000_0040_0000).unwrap();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Spawn,
        capability_rights::GRANT,
    );
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
}

/// Creates the auditd server process and grants CapAuditRead (read-only) only.
///
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_auditd_server_process() {
    let (handle, mut capability_space) =
        create_server_process(ProcessType::Auditd, 0x0000_0000_0040_0000).unwrap();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::AuditRead,
        capability_rights::READ,
    );
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
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
///
/// ORDERING CONSTRAINT: devd-nic must be launched before devd-disk.
/// Both share entry point 0x0000_0000_0040_0000 and ProcessType::DeviceServer.
/// Thread identity is distinguished only by the monotonic NEXT_THREAD_POOL_SLOT_INDEX
/// counter. Reordering these calls silently swaps their thread identifiers and
/// capability grants. This constraint will be eliminated when distinct
/// ProcessType::DeviceServerNic and ProcessType::DeviceServerDisk variants
/// are introduced in a future phase.
fn launch_device_server_processes(boot_step_logger: &mut BootStepLogger) {
    // ORDERING CONSTRAINT: devd-nic MUST be launched before devd-disk.
    // Both use ProcessType::DeviceServer and the same entry point. Thread identity is
    // assigned by NEXT_THREAD_POOL_SLOT_INDEX. Reordering silently swaps capability grants.
    // This constraint is eliminated when distinct ProcessType::DeviceServerNic/Disk variants
    // are introduced in a future phase.
    launch_devd_nic_server_process();
    launch_devd_disk_server_process();
    boot_step_logger.ok("Device server processes created: devd-nic, devd-disk");
}

/// Creates the devd-nic server process and grants CapDevice for the NIC plus Endpoint WRITE.
///
/// Per D-01: kernel grants CapDevice directly — no spawnd involvement.
/// Slot 0: CapDevice READ|WRITE (NIC hardware access).
/// Slot 1: CapEndpoint WRITE (send to linkd, endpoint index 0 per D-04).
/// Mitigates T-DEV-018: object_pointer holds the NIC DeviceCapabilityData address.
/// Enforces INV-DEV-002: NIC server receives only NIC-scoped authority.
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
///
/// Entry point 0x0000_0000_0040_0000 is a boot-phase placeholder shared with devd-disk.
/// The two servers are distinguished solely by the object_pointer written into slot 0
/// (NIC_DEVICE_CAPABILITY_DATA vs DISK_DEVICE_CAPABILITY_DATA). The ProcessTable key
/// is the thread_identifier, which is unique because NEXT_THREAD_POOL_SLOT_INDEX
/// increments between calls. ORDERING CONSTRAINT: devd-nic must be launched before
/// devd-disk (launch_device_server_processes enforces this order). If this order
/// changes, the slot assignments swap silently — this is a known structural gap
/// to be resolved when distinct ProcessType variants are introduced in a future phase.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_devd_nic_server_process() {
    let (handle, mut capability_space) =
        create_server_process(ProcessType::DeviceServer, 0x0000_0000_0040_0000).unwrap();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Device,
        capability_rights::READ | capability_rights::WRITE,
    );
    wire_nic_device_data_into_slot(&mut capability_space);
    grant_endpoint_capability_with_index(&mut capability_space, 1, capability_rights::WRITE, 0);
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
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
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
///
/// Entry point 0x0000_0000_0040_0000 is a boot-phase placeholder shared with devd-nic.
/// The two servers are distinguished solely by the object_pointer written into slot 0
/// (DISK_DEVICE_CAPABILITY_DATA vs NIC_DEVICE_CAPABILITY_DATA). The ProcessTable key
/// is the thread_identifier, which is unique because NEXT_THREAD_POOL_SLOT_INDEX
/// increments between calls. ORDERING CONSTRAINT: devd-disk must be launched after
/// devd-nic (launch_device_server_processes enforces this order). If this order
/// changes, the slot assignments swap silently — this is a known structural gap
/// to be resolved when distinct ProcessType variants are introduced in a future phase.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_devd_disk_server_process() {
    let (handle, mut capability_space) =
        create_server_process(ProcessType::DeviceServer, 0x0000_0000_0040_0000).unwrap();
    grant_initial_capability_to_server(
        &mut capability_space,
        0,
        CapabilityType::Device,
        capability_rights::READ | capability_rights::WRITE,
    );
    wire_disk_device_data_into_slot(&mut capability_space);
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
}

/// Sets the disk DeviceCapabilityData address in slot 0's object_pointer.
///
/// Stores the address of the static DISK_DEVICE_CAPABILITY_DATA so Phase 9
/// syscall handlers can recover MMIO bounds without a separate lookup table.
fn wire_disk_device_data_into_slot(capability_space: &mut CapabilitySpace) {
    let slot = capability_space.lookup_slot_mut(0);
    slot.object_pointer = core::ptr::addr_of!(DISK_DEVICE_CAPABILITY_DATA) as u64;
}

/// Launches network server processes for linkd, ipd, and transportd.
///
/// Per D-03: kernel grants minimum capabilities directly at boot.
/// Enforces INV-AUTH-001: each network server starts with minimum authority.
/// Enforces INV-MEM-002: each server has a KPTI-isolated address space.
fn launch_network_server_processes(boot_step_logger: &mut BootStepLogger) {
    launch_linkd_server_process();
    launch_ipd_server_process();
    launch_transportd_server_process();
    boot_step_logger.ok("Network servers created: linkd, ipd, transportd");
}

/// Creates the linkd server process and grants 3 capabilities per D-03.
///
/// Slot 0: CapEndpoint READ (receive from devd-nic, endpoint index 0 per D-04).
/// Slot 1: CapEndpoint WRITE (send to ipd, endpoint index 1 per D-04).
/// Slot 2: CapFrame READ|WRITE (shared packet buffer page).
///
/// Enforces INV-DEV-002: linkd receives only its assigned authority.
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_linkd_server_process() {
    let (handle, mut linkd_capability_space) =
        create_server_process(ProcessType::NetworkServer, 0x0000_0000_0040_0000).unwrap();
    grant_endpoint_capability_with_index(
        &mut linkd_capability_space,
        0,
        capability_rights::READ,
        0,
    );
    grant_linkd_outbound_and_frame_capabilities(&mut linkd_capability_space);
    insert_capability_space_into_global_process_table(
        handle.thread_identifier,
        linkd_capability_space,
    );
}

/// Grants linkd's slot 1 (send to ipd, endpoint 1) and slot 2 (CapFrame) capabilities.
fn grant_linkd_outbound_and_frame_capabilities(linkd_capability_space: &mut CapabilitySpace) {
    grant_endpoint_capability_with_index(linkd_capability_space, 1, capability_rights::WRITE, 1);
    grant_initial_capability_to_server(
        linkd_capability_space,
        2,
        CapabilityType::Frame,
        capability_rights::READ | capability_rights::WRITE,
    );
}

/// Creates the ipd server process and grants 2 capabilities per D-03.
///
/// Slot 0: CapEndpoint READ (receive from linkd, endpoint index 1 per D-04).
/// Slot 1: CapEndpoint WRITE (send to transportd, endpoint index 2 per D-04).
///
/// Enforces INV-DEV-002: ipd receives only its assigned authority.
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_ipd_server_process() {
    let (handle, mut ipd_capability_space) =
        create_server_process(ProcessType::NetworkServer, 0x0000_0000_0040_0000).unwrap();
    grant_endpoint_capability_with_index(&mut ipd_capability_space, 0, capability_rights::READ, 1);
    grant_ipd_outbound_capability(&mut ipd_capability_space);
    insert_capability_space_into_global_process_table(
        handle.thread_identifier,
        ipd_capability_space,
    );
}

/// Grants ipd's slot 1 (send to transportd, endpoint index 2) capability.
fn grant_ipd_outbound_capability(ipd_capability_space: &mut CapabilitySpace) {
    grant_endpoint_capability_with_index(ipd_capability_space, 1, capability_rights::WRITE, 2);
}

/// Creates the transportd server process and grants ONLY 1 capability per D-03.
///
/// Slot 0: CapEndpoint READ (receive from ipd, endpoint index 2 per D-04) — and nothing else.
/// NO CapDevice, NO CapIrq, NO endpoint to devd-nic, NO endpoint to devd-disk.
///
/// Enforces D-04: two-layer containment — transportd cannot reach devd-nic.
/// Enforces INV-DEV-002: transportd receives minimum possible authority.
/// Enforces T-10-02-01: CSpace inserted into ProcessTable after capability grant.
#[allow(clippy::unwrap_used)] // boot-time, infallible by construction (see launch_init_server_process)
fn launch_transportd_server_process() {
    let (handle, mut transportd_capability_space) =
        create_server_process(ProcessType::NetworkServer, 0x0000_0000_0040_0000).unwrap();
    grant_endpoint_capability_with_index(
        &mut transportd_capability_space,
        0,
        capability_rights::READ,
        2,
    );
    insert_capability_space_into_global_process_table(
        handle.thread_identifier,
        transportd_capability_space,
    );
}

/// Grants an Endpoint capability and sets object_pointer to the endpoint pool index.
///
/// Enforces D-04: CSlot.object_pointer holds the endpoint_index for dispatch lookup.
fn grant_endpoint_capability_with_index(
    capability_space: &mut CapabilitySpace,
    slot_index: u8,
    rights: CapabilityRights,
    endpoint_index: u64,
) {
    grant_initial_capability_to_server(
        capability_space,
        slot_index,
        CapabilityType::Endpoint,
        rights,
    );
    let slot = capability_space.lookup_slot_mut(slot_index);
    slot.object_pointer = endpoint_index;
}

/// Inserts a capability space into the global kernel process table.
///
/// Boot-time panics on insert failure: MAXIMUM_THREADS=32 > 8 servers ensures
/// this cannot fail in practice. Panicking here is safer than silently dropping a CSpace.
///
/// Enforces T-10-02-01: every server launch ends with CSpace in the ProcessTable.
/// Enforces INV-AUTH-001: no authority exists without explicit table registration.
#[allow(clippy::unwrap_used)]
fn insert_capability_space_into_global_process_table(
    thread_identifier: ThreadIdentifier,
    capability_space: CapabilitySpace,
) {
    // SAFETY: Single-core boot. initialize_kernel_process_table called before this.
    // Precondition: KERNEL_PROCESS_TABLE initialized via initialize_kernel_ipc_globals.
    // Invariant: INV-AUTH-001 (CSpace registered for thread).
    // Evidence: integration_server_holds_live_cspace_after_boot.
    let process_table = unsafe { kernel_ipc_state::kernel_process_table_mut() };
    process_table
        .insert_entry(thread_identifier, capability_space)
        .unwrap();
}

/// Launches the shell server by ELF-loading the multiboot2 `shell`
/// module into a fresh user address space and registering it in the
/// global process table. Halts the kernel with PCR[5] extended on any
/// loader error.
///
/// Enforces invariant INV-BOOT-001 (measured boot integrity) by routing
/// the source module's hash into the failure record.
///
/// The shell thread is created in the `Ready` state; it does not yet run
/// because the boot sequence halts after `log_boot_complete` with no
/// scheduler dispatch to userspace (see `main.rs`). Executing the shell's
/// first instruction on the serial console is a separate scheduler task.
fn launch_shell_server_process(
    multiboot2_info_address: u64,
    boot_step_logger: &mut BootStepLogger,
) -> usize {
    let module_inputs = prepare_shell_module_inputs(multiboot2_info_address);
    let handle_and_cspace = create_shell_process_or_halt(&module_inputs, boot_step_logger);
    let shell_thread_index = handle_and_cspace.0.thread_index;
    register_shell_process_in_table(handle_and_cspace);
    boot_step_logger.ok("Shell process created and registered (Ready)");
    shell_thread_index
}

struct ShellModuleInputs {
    module_bytes: &'static [u8],
    module_hash: [u8; 32],
}

fn prepare_shell_module_inputs(multiboot2_info_address: u64) -> ShellModuleInputs {
    let module_slices = extract_module_byte_slices_from_boot_information(multiboot2_info_address);
    let shell_bytes = pick_shell_module_byte_slice(&module_slices);
    let shell_hash = compute_module_sha256(shell_bytes);
    ShellModuleInputs {
        module_bytes: shell_bytes,
        module_hash: shell_hash,
    }
}

/// Module index 1 is the shell per docker/test.sh grub.cfg generation
/// (kernel = index 0, shell = index 1).
fn pick_shell_module_byte_slice(module_slices: &[&'static [u8]; 8]) -> &'static [u8] {
    module_slices[1]
}

fn compute_module_sha256(module_bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(module_bytes);
    hasher.finalize().into()
}

fn create_shell_process_or_halt(
    inputs: &ShellModuleInputs,
    boot_step_logger: &mut BootStepLogger,
) -> (
    crate::process::server_launch::ServerProcessHandle,
    crate::capability::capability_space::CapabilitySpace,
) {
    match crate::process::server_launch::create_server_process_from_elf(
        ProcessType::Shell,
        inputs.module_bytes,
    ) {
        Ok(pair) => pair,
        Err(error) => halt_on_userspace_elf_load_failure(
            ProcessType::Shell,
            error,
            &inputs.module_hash,
            boot_step_logger,
        ),
    }
}

fn halt_on_userspace_elf_load_failure(
    process_type: ProcessType,
    error: crate::process::elf_loader::ElfLoadError,
    module_hash: &[u8; 32],
    boot_step_logger: &mut BootStepLogger,
) -> ! {
    boot_step_logger.line("[FAIL] Userspace ELF load failed");
    let failure_record = crate::process::elf_load_failure::compute_load_failure_record_hash(
        process_type,
        error,
        module_hash,
    );
    let _ = crate::hardware_security::tpm::commands::extend_platform_configuration_register(
        crate::process::elf_load_failure::USERSPACE_ELF_LOAD_FAILURE_PCR_INDEX,
        &failure_record,
    );
    crate::arch::interrupts::halt::disable_interrupts_and_halt()
}

fn register_shell_process_in_table(
    handle_and_cspace: (
        crate::process::server_launch::ServerProcessHandle,
        crate::capability::capability_space::CapabilitySpace,
    ),
) {
    let (handle, capability_space) = handle_and_cspace;
    insert_capability_space_into_global_process_table(handle.thread_identifier, capability_space);
}

fn log_kernel_banner(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.separator();
    boot_step_logger.line(" BraiNIX MICROKERNEL  v0.1.0");
    boot_step_logger.line(" x86_64-unknown-none | Rust nightly-2025-12-01 | Phase 12");
    boot_step_logger.separator();
}

fn log_boot_infrastructure_status(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("Serial console initialized (COM1 | 115200 8N1)");
    boot_step_logger.ok("Kernel entry point reached");
    boot_step_logger.info("Build: Phase 12 -- Attestation chain measurement wiring");
}

fn log_boot_complete(boot_step_logger: &mut BootStepLogger) {
    boot_step_logger.ok("BraiNIX: boot complete");
}
