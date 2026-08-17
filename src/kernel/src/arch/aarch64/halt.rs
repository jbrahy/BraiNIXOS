//! Parking the core on aarch64.
//!
//! The x86-64 sibling is `arch::interrupts::halt`, which issues `cli; hlt`.
//! Neither instruction exists here, which is why that module carried a bare
//! `asm!("cli")` into the aarch64 build for months and only went unnoticed
//! because a library build is not a link.

//! `wfe` and `mrs` are inline assembly, which is unsafe by definition. Same
//! per-module allowlist convention as the x86-64 siblings.
#![allow(unsafe_code)]

/// Park the core forever.
///
/// `wfe` rather than a spin: a tight loop on a core that will never be woken
/// burns power and, on a machine drawing from a shared thermal budget, can
/// affect whatever else is running. `wfe` is unprivileged and has no memory
/// effects, so it is safe at any exception level the kernel can be entered at.
pub fn park() -> ! {
    loop {
        // SAFETY: `wfe` has no memory operands and no side effects beyond
        // suspending until an event. It cannot fault at EL1 or EL2.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) }
    }
}

/// The current exception level, from `CurrentEL`.
///
/// Worth reporting at boot rather than assuming: m1n1 hands control at **EL2**
/// (observed on the target, `Running in EL2` in its own banner), while a kernel
/// entered directly from iBoot may not be. Code that assumes EL1 and finds EL2
/// fails at the first system-register write, which presents as a hang.
pub fn current_exception_level() -> u8 {
    let value: u64;
    // SAFETY: reading `CurrentEL` is unprivileged at EL1 and above and has no
    // side effects.
    unsafe { core::arch::asm!("mrs {}, CurrentEL", out(reg) value, options(nomem, nostack)) }
    // Bits [3:2] hold the level; the rest are RES0.
    ((value >> 2) & 0b11) as u8
}
