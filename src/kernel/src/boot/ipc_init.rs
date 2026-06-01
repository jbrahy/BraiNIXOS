//! IPC subsystem initialization during kernel boot (D-09).
//!
//! CR3 load activates the KPTI page tables built in Phase 2.
//! SYSCALL entry installation wires the IPC fast path.
//!
//! Falls under src/kernel/src/boot/ unsafe allowlist entry in
//! docs/security/UNSAFE_CODE_POLICY.md (writing to CR3, reading/writing CR0/CR4).
#![allow(unsafe_code)]

use crate::arch::syscall_entry::install_syscall_entry_point;
use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;

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
    switch_stack_to_direct_map_view_and_load_cr3(kernel_pml4_physical_address);
    install_syscall_entry_point();
}

/// Atomically rebases the stack pointer onto the direct-map region and
/// loads the kernel PML4 into CR3.
///
/// The bootloader's identity map made the boot stack reachable at its
/// physical address (e.g. 0x808000). The kernel's KPTI page tables do
/// not include that identity map; once CR3 is loaded, the only
/// virtual-address path to the boot stack's physical memory is through
/// the direct-map region (DIRECT_MAP_REGION_START + phys).
///
/// The two writes — adjusting RSP and loading CR3 — must occur in the
/// same inline-asm block so that no `push`/`pop`/`call`/`ret` runs
/// between them. `mov rsp, …` does not access memory; the next memory
/// access via the stack happens after `mov cr3, …` and resolves
/// through the new direct-map mapping to the same physical bytes the
/// boot stack already holds.
///
/// After this returns, the caller's saved return address (originally
/// pushed at the bootloader's physical stack address) is read back via
/// the direct-map virtual address that points to the same physical
/// memory, so unwinding works normally.
///
/// # Safety
///
/// - `kernel_pml4_physical_address` must be the Phase 2 kernel PML4 and
///   that PML4 must map both the current RIP (kernel binary region) and
///   the direct-map region used as the new stack view.
/// - Must be called while still on the bootloader's identity-mapped
///   stack (otherwise the rebase computation lands in the wrong place).
fn switch_stack_to_direct_map_view_and_load_cr3(kernel_pml4_physical_address: u64) {
    // SAFETY: See function doc-comment. The asm block performs only
    // register-to-register operations until the final CR3 write; no stack
    // access occurs between the rebase and the page-table swap.
    // - Precondition: caller's stack lives in identity-mapped low memory.
    // - Invariant: INV-MEM-001 (kernel absent from user PT), INV-MEM-002 (KPTI active).
    // - Evidence: live boot verified via docker/test.sh inside dev container.
    unsafe {
        core::arch::asm!(
            "movabs rcx, {direct_map}",
            "add rsp, rcx",
            "mov cr3, {pml4}",
            direct_map = const DIRECT_MAP_REGION_START,
            pml4 = in(reg) kernel_pml4_physical_address,
            out("rcx") _,
        );
    }
}
