//! KPTI syscall trampoline support.
//!
//! On a `syscall` from ring 3 the CPU jumps to the kernel entry point with the
//! USER page table still loaded in CR3 and the USER stack still in RSP. Because
//! BraiNIX does not map the kernel into user page tables (INV-MEM-001), the
//! entry point's code page and a small scratch page must be present
//! (supervisor-only) in every user page table so the first instructions can
//! run. Those instructions swap CR3 to the kernel page table and switch to the
//! ring-0 stack; the exit path swaps back. This two-page supervisor mapping is
//! the single, named exception to "the kernel is not mapped in user page
//! tables" — it exposes no general kernel memory and is unreachable from ring 3
//! (U/S = 0). It is the standard KPTI trampoline.
//!
//! The asm in `syscall_entry.rs` indexes `SYSCALL_TRAMPOLINE_SCRATCH` by byte
//! offset, so the field order below is load-bearing.
//!
//! Allowlist: src/kernel/src/arch/ — assembly stubs and CPU control structures.
#![allow(unsafe_code)]

use x86_64::structures::paging::{PageTable, PageTableFlags};

use crate::arch::interrupts::task_state_segment::syscall_kernel_stack_top;
use crate::arch::paging::kernel_page_table::{
    kernel_page_map_level_4_physical_address, map_single_page_in_root,
};
use crate::arch::paging::page_table_walk_helpers::compute_physical_address_of_bss_page;

/// Trampoline scratch shared between the kernel and the trampoline while it runs
/// under the user page table. Slot order MUST match the byte offsets used by the
/// asm in `syscall_entry.rs`:
///
///   [0] kernel CR3 (phys of the kernel PML4)   — offset 0
///   [1] kernel RSP0 (top of the ring-0 stack)  — offset 8
///   [2] user CR3 (phys of the current PML4)     — offset 16
///   [3] saved user RSP                          — offset 24
///   [4] scratch register save (rax)             — offset 32
#[no_mangle]
pub static mut SYSCALL_TRAMPOLINE_SCRATCH: [u64; 5] = [0; 5];

extern "C" {
    /// The syscall entry stub; its code page is exposed into user page tables.
    fn syscall_entry_point();
}

/// Records the kernel CR3 and ring-0 stack top the trampoline switches to on
/// entry from ring 3. Call once, after the kernel page table is active.
pub fn record_kernel_trampoline_state() {
    let kernel_cr3 = kernel_page_map_level_4_physical_address();
    let kernel_stack_top = syscall_kernel_stack_top();
    // SAFETY: single-core boot; the scratch is a static written only here and on
    // dispatch. addr_of_mut! avoids a reference to the static mut.
    unsafe {
        let scratch = core::ptr::addr_of_mut!(SYSCALL_TRAMPOLINE_SCRATCH);
        (*scratch)[0] = kernel_cr3;
        (*scratch)[1] = kernel_stack_top;
    }
}

/// Records the user CR3 the trampoline restores when returning to ring 3 — the
/// page table of the process the kernel is about to run or is serving.
pub fn set_active_user_page_table(user_page_table_physical_address: u64) {
    // SAFETY: single-core; see `record_kernel_trampoline_state`.
    unsafe {
        let scratch = core::ptr::addr_of_mut!(SYSCALL_TRAMPOLINE_SCRATCH);
        (*scratch)[2] = user_page_table_physical_address;
    }
}

#[allow(clippy::arithmetic_side_effects)]
fn align_down_to_page(virtual_address: u64) -> u64 {
    virtual_address & !0xFFF
}

fn scratch_page_virtual_base() -> u64 {
    align_down_to_page(core::ptr::addr_of!(SYSCALL_TRAMPOLINE_SCRATCH) as u64)
}

fn trampoline_code_virtual_base() -> u64 {
    align_down_to_page(syscall_entry_point as *const () as u64)
}

/// Maps the trampoline code page(s) and the scratch page into a user PML4 as
/// supervisor-only entries (read-execute for code, read-write/no-execute for
/// scratch) at the same kernel virtual addresses they occupy in the kernel page
/// table, so the trampoline executes seamlessly across the CR3 swap.
///
/// # Safety
/// Single-core boot; caller holds exclusive access to `user_page_map_level_4`.
#[allow(clippy::arithmetic_side_effects)]
pub unsafe fn map_trampoline_into_user_page_table(user_page_map_level_4: &mut PageTable) {
    let code_flags = PageTableFlags::PRESENT;
    let scratch_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    let code_base = trampoline_code_virtual_base();
    map_kernel_page_into_user(user_page_map_level_4, code_base, code_flags);
    map_kernel_page_into_user(user_page_map_level_4, code_base + 0x1000, code_flags);
    map_kernel_page_into_user(user_page_map_level_4, scratch_page_virtual_base(), scratch_flags);
}

unsafe fn map_kernel_page_into_user(
    user_page_map_level_4: &mut PageTable,
    virtual_address: u64,
    flags: PageTableFlags,
) {
    let physical_address = compute_physical_address_of_bss_page(virtual_address);
    let _ = map_single_page_in_root(user_page_map_level_4, virtual_address, physical_address, flags);
}

extern "C" {
    /// Defined in `syscall_entry.rs`: swaps to `user_cr3`, loads `user_rsp`,
    /// and `sysretq`s to `entry` in ring 3. Never returns.
    fn enter_userspace_trampoline(entry: u64, user_rsp: u64, user_cr3: u64) -> !;
}

/// Enters ring 3 for the first time. Marks `thread_identifier` as current,
/// records its page table for the trampoline's return path, then SYSRETs into
/// `entry` on `user_rsp` under `user_cr3`. Never returns.
///
/// # Safety
/// `user_cr3` must be a valid user PML4 that maps `entry`, `user_rsp`, and the
/// trampoline pages (via `map_trampoline_into_user_page_table`). Single-core.
pub unsafe fn enter_userspace(
    thread_identifier: u32,
    entry: u64,
    user_rsp: u64,
    user_cr3: u64,
) -> ! {
    crate::scheduler::context_switch::set_current_thread_identifier(thread_identifier);
    set_active_user_page_table(user_cr3);
    enter_userspace_trampoline(entry, user_rsp, user_cr3)
}
