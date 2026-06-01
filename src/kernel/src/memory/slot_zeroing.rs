//! Volatile capability slot zeroing for secure revocation.
//!
//! Placed in the memory module because src/kernel/src/memory/ is on the unsafe
//! allowlist in UNSAFE_CODE_POLICY.md. No unsafe code appears in the capability
//! module itself.
//!
//! Enforces INV-AUTH-004: revocation is final — write_volatile prevents compiler elision.
//! Enforces INV-OBJ-002: revoked slots cannot carry stale authority.

#![allow(unsafe_code)]

use crate::capability::capability_slot::CapabilitySlot;

/// Zeroes a capability slot via mutable reference using write_volatile.
///
/// The safe wrapper derives the raw pointer from the mutable reference, which
/// guarantees non-null and exclusive ownership. Callers in the capability module
/// do not need an unsafe block.
///
/// Enforces INV-AUTH-004 (revocation is final) and INV-OBJ-002 (no stale authority).
pub fn zero_capability_slot_via_reference(slot_reference: &mut CapabilitySlot) {
    let slot_pointer = core::ptr::addr_of_mut!(*slot_reference);
    let null_sentinel = CapabilitySlot::null();
    // SAFETY: slot_pointer is derived from a &mut reference: non-null, aligned,
    // and exclusively owned for the duration of this call.
    unsafe { zero_capability_slot_with_volatile_write(slot_pointer, null_sentinel) };
}

/// Zeroes a capability slot using write_volatile to prevent compiler elision.
///
/// Enforces INV-AUTH-004 (revocation is final) and INV-OBJ-002 (no stale authority).
///
/// # Safety
///
/// The caller must ensure slot_pointer is non-null, properly aligned, and exclusively
/// owned. On single-core BraiNIX, exclusive ownership is guaranteed by the caller
/// holding `&mut CapabilitySpace`.
pub unsafe fn zero_capability_slot_with_volatile_write(
    slot_pointer: *mut CapabilitySlot,
    null_sentinel: CapabilitySlot,
) {
    core::ptr::write_volatile(slot_pointer, null_sentinel);
}
