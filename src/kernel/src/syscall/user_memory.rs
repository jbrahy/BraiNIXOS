//! Bounded copy-from-user: read a small buffer from the calling process's
//! address space into the kernel.
//!
//! Syscall arguments that don't fit in registers (credential strings today,
//! network buffers later) are passed by user virtual address + length. The
//! kernel must read them through the *caller's* page table, not its own, and
//! must never trust the length: every byte is bounds-checked against the
//! destination and translated page-by-page through the active user PML4 (the
//! CR3 the trampoline recorded), then read via the direct map.
//!
//! Allowlist: `src/kernel/src/syscall/` — translating and dereferencing a
//! user-controlled pointer has no safe interface.
#![allow(unsafe_code)]

use crate::arch::paging::kernel_page_table::resolve_mapped_physical_address;
use crate::arch::paging::page_table_walk_helpers::retrieve_page_table_by_physical_address;
use crate::arch::syscall_trampoline::active_user_page_table;
use crate::memory::virtual_address_layout::DIRECT_MAP_REGION_START;
use x86_64::PhysAddr;

/// Copies `length` bytes from user virtual address `user_virtual_address` into
/// `destination`, translating through the calling process's page table.
///
/// Returns the number of bytes copied, or `None` if `length` exceeds the
/// destination, the active user page table is unset, or any page in the range
/// is not mapped in user space (a bad/hostile pointer fails closed).
pub fn copy_from_user(
    user_virtual_address: u64,
    length: usize,
    destination: &mut [u8],
) -> Option<usize> {
    if length > destination.len() {
        return None;
    }
    let user_page_table_physical = active_user_page_table();
    if user_page_table_physical == 0 {
        return None;
    }
    // SAFETY: the active user CR3 was recorded by the trampoline for the current
    // (single-core, non-preemptible) process; the PML4 lives in BSS-backed
    // bootstrap page-table storage.
    let page_table =
        unsafe { retrieve_page_table_by_physical_address(PhysAddr::new(user_page_table_physical)) };
    // Iterate the destination directly rather than indexing it by a loop
    // counter: the slot and its offset then cannot disagree, and a short
    // destination truncates the copy instead of panicking mid-way through
    // reading user memory.
    for (offset, slot) in destination.iter_mut().enumerate().take(length) {
        let source_virtual = user_virtual_address.wrapping_add(offset as u64);
        *slot = read_one_user_byte(page_table, source_virtual)?;
    }
    Some(length)
}

/// Translates one user virtual address through `page_table` and reads the byte
/// via the direct map. Returns `None` if the address is not mapped.
fn read_one_user_byte(
    page_table: &mut x86_64::structures::paging::PageTable,
    user_virtual_address: u64,
) -> Option<u8> {
    // SAFETY: resolve walks the supplied user PML4 read-only; on success the
    // frame is mapped, so the direct-map read is valid.
    unsafe {
        let frame_physical =
            resolve_mapped_physical_address(page_table, user_virtual_address).ok()?;
        let byte_physical = frame_physical | (user_virtual_address & 0xFFF);
        let direct_pointer = DIRECT_MAP_REGION_START.wrapping_add(byte_physical) as *const u8;
        Some(core::ptr::read_volatile(direct_pointer))
    }
}
