//! IPC subsystem initialization during kernel boot (D-09).
//!
//! CR3 load activates the KPTI page tables built in Phase 2.
//! SYSCALL entry installation wires the IPC fast path.
//!
//! Falls under src/kernel/src/boot/ unsafe allowlist entry in
//! docs/security/UNSAFE_CODE_POLICY.md (writing to CR3, reading/writing CR0/CR4).
#![allow(unsafe_code)]

use crate::arch::syscall_entry::install_syscall_entry_point;

/// Initializes the IPC subsystem: loads CR3 and installs the SYSCALL handler.
///
/// Called from the boot sequence after Phase 2 page tables are built.
/// Must be called before the first context switch (D-09).
///
/// # Safety
///
/// `kernel_pml4_physical_address` must be the physical address of the kernel
/// PML4 built by Phase 2. Loading CR3 flushes the TLB and activates KPTI.
///
/// - Precondition: Phase 2 page tables are fully constructed and valid.
/// - Invariant: INV-MEM-001 (kernel not mapped in user page tables — by construction
///   in Phase 2), INV-MEM-002 (KPTI active after CR3 load).
/// - Evidence: test_kernel_virtual_address_is_absent_from_user_page_table (Phase 2).
pub fn initialize_ipc_subsystem(kernel_pml4_physical_address: u64) {
    load_cr3_to_activate_kpti_page_tables(kernel_pml4_physical_address);
    install_syscall_entry_point();
}

/// Writes the kernel PML4 physical address to CR3, activating KPTI page tables.
///
/// # Safety
///
/// `kernel_pml4_physical_address` must be the Phase 2 kernel PML4.
/// Writing CR3 flushes the TLB. The user PML4 is structurally empty (KPTI by
/// construction — the kernel is never mapped in user page tables in Phase 2).
fn load_cr3_to_activate_kpti_page_tables(kernel_pml4_physical_address: u64) {
    // SAFETY: Physical address is the kernel PML4 built in Phase 2 (D-09).
    // - Precondition: kernel_pml4_physical_address is a valid 4096-byte aligned PML4.
    // - Invariant: INV-MEM-001 (kernel absent from user PT), INV-MEM-002 (KPTI active).
    // - Evidence: test_kernel_virtual_address_is_absent_from_user_page_table (Phase 2).
    unsafe {
        core::arch::asm!(
            "mov cr3, {}",
            in(reg) kernel_pml4_physical_address,
            options(nostack, preserves_flags),
        );
    }
}
