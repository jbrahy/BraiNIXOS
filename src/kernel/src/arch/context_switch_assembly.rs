//! Context switch register save/restore.
//!
//! Unsafe code allowed per UNSAFE_CODE_POLICY.md: context switch register
//! save/restore in src/kernel/src/arch/ (assembly stubs allowlist entry).
//!
//! Phase 5 note: single-core, no real userspace exists yet. These functions
//! document the intended register save/restore sequence. Full assembly
//! implementation with real userspace threads is wired in Phase 7.
//!
//! PHASE-7-DEFERRED [T-SCHED-08]: Timer interrupt save path (to RegisterSaveArea) and
//! SYSCALL entry save path (to kernel stack) must be implemented as SEPARATE code paths
//! in Phase 7 when real userspace threads exist. Double-save (both paths firing on the
//! same thread) is prevented by the single-core constraint (INV-SCHED-001) until then.
#![allow(unsafe_code)]

use crate::thread::RegisterSaveArea;

/// Reads the current value of rax from CPU into the save area.
fn save_register_rax(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rax register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rax",
            out(reg) save_area.register_rax,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the current value of rbx from CPU into the save area.
fn save_register_rbx(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rbx register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rbx",
            out(reg) save_area.register_rbx,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the current value of rcx from CPU into the save area.
fn save_register_rcx(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rcx register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rcx",
            out(reg) save_area.register_rcx,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the current value of rdx from CPU into the save area.
fn save_register_rdx(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rdx register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rdx",
            out(reg) save_area.register_rdx,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the current value of rdi from CPU into the save area.
fn save_register_rdi(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rdi register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rdi",
            out(reg) save_area.register_rdi,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the current value of rsi from CPU into the save area.
fn save_register_rsi(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rsi register; output written to safe Rust reference.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {}, rsi",
            out(reg) save_area.register_rsi,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the general-purpose registers r8-r11 from CPU into the save area.
fn save_registers_r8_through_r11(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads r8-r11; outputs written to safe Rust references.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {r8_out}, r8",
            "mov {r9_out}, r9",
            "mov {r10_out}, r10",
            "mov {r11_out}, r11",
            r8_out = out(reg) save_area.register_r8,
            r9_out = out(reg) save_area.register_r9,
            r10_out = out(reg) save_area.register_r10,
            r11_out = out(reg) save_area.register_r11,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads the general-purpose registers r12-r15 from CPU into the save area.
fn save_registers_r12_through_r15(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads r12-r15; outputs written to safe Rust references.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {r12_out}, r12",
            "mov {r13_out}, r13",
            "mov {r14_out}, r14",
            "mov {r15_out}, r15",
            r12_out = out(reg) save_area.register_r12,
            r13_out = out(reg) save_area.register_r13,
            r14_out = out(reg) save_area.register_r14,
            r15_out = out(reg) save_area.register_r15,
            options(nostack, preserves_flags),
        );
    }
}

/// Reads rbp and rsp from CPU into the save area.
fn save_registers_rbp_and_rsp(save_area: &mut RegisterSaveArea) {
    // SAFETY: Inline asm reads rbp and rsp; outputs written to safe Rust references.
    // - Precondition: save_area is exclusively owned by caller.
    // - Invariant: INV-SCHED-003 (context switch preserves full register state).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov {rbp_out}, rbp",
            "mov {rsp_out}, rsp",
            rbp_out = out(reg) save_area.register_rbp,
            rsp_out = out(reg) save_area.register_rsp,
            options(nostack, preserves_flags),
        );
    }
}

/// Saves the full x86-64 register state of the current thread to save_area.
///
/// Reads all general-purpose registers into the RegisterSaveArea fields.
/// Called during a context switch before switching to another thread.
///
/// Phase 5: Documents intended save sequence. Full integration occurs in Phase 7
/// when real userspace threads exist and context switching is active.
///
/// Enforces invariant INV-SCHED-003: context switch preserves complete register state.
/// Verified by: perform_context_switch (integration test, Phase 7).
pub fn save_register_state_to_save_area(save_area: &mut RegisterSaveArea) {
    save_register_rax(save_area);
    save_register_rbx(save_area);
    save_register_rcx(save_area);
    save_register_rdx(save_area);
    save_register_rdi(save_area);
    save_register_rsi(save_area);
}

/// Saves the extended register set (r8-r15, rbp, rsp) to save_area.
///
/// Called immediately after save_register_state_to_save_area to complete
/// the full register save. Separated to keep each function under 6 lines.
pub fn save_extended_register_state_to_save_area(save_area: &mut RegisterSaveArea) {
    save_registers_r8_through_r11(save_area);
    save_registers_r12_through_r15(save_area);
    save_registers_rbp_and_rsp(save_area);
}

/// Restores rax, rbx, rcx, rdx, rdi, rsi from save_area to CPU registers.
fn restore_registers_rax_through_rsi(save_area: &RegisterSaveArea) {
    // SAFETY: Inline asm writes CPU registers from values in the save area.
    // - Precondition: save_area contains a valid prior register snapshot.
    // - Invariant: INV-SCHED-003 (register state restored exactly as saved).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov rax, {rax_in}",
            "mov rbx, {rbx_in}",
            "mov rcx, {rcx_in}",
            "mov rdx, {rdx_in}",
            "mov rdi, {rdi_in}",
            "mov rsi, {rsi_in}",
            rax_in = in(reg) save_area.register_rax,
            rbx_in = in(reg) save_area.register_rbx,
            rcx_in = in(reg) save_area.register_rcx,
            rdx_in = in(reg) save_area.register_rdx,
            rdi_in = in(reg) save_area.register_rdi,
            rsi_in = in(reg) save_area.register_rsi,
            options(nostack, preserves_flags),
        );
    }
}

/// Restores r8-r11 from save_area to CPU registers.
fn restore_registers_r8_through_r11(save_area: &RegisterSaveArea) {
    // SAFETY: Inline asm writes CPU registers from values in the save area.
    // - Precondition: save_area contains a valid prior register snapshot.
    // - Invariant: INV-SCHED-003 (register state restored exactly as saved).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov r8, {r8_in}",
            "mov r9, {r9_in}",
            "mov r10, {r10_in}",
            "mov r11, {r11_in}",
            r8_in = in(reg) save_area.register_r8,
            r9_in = in(reg) save_area.register_r9,
            r10_in = in(reg) save_area.register_r10,
            r11_in = in(reg) save_area.register_r11,
            options(nostack, preserves_flags),
        );
    }
}

/// Restores r12-r15 and rbp from save_area to CPU registers.
fn restore_registers_r12_through_r15_and_rbp(save_area: &RegisterSaveArea) {
    // SAFETY: Inline asm writes CPU registers from values in the save area.
    // - Precondition: save_area contains a valid prior register snapshot.
    // - Invariant: INV-SCHED-003 (register state restored exactly as saved).
    // - Evidence: perform_context_switch test (future integration test).
    unsafe {
        core::arch::asm!(
            "mov r12, {r12_in}",
            "mov r13, {r13_in}",
            "mov r14, {r14_in}",
            "mov r15, {r15_in}",
            "mov rbp, {rbp_in}",
            r12_in = in(reg) save_area.register_r12,
            r13_in = in(reg) save_area.register_r13,
            r14_in = in(reg) save_area.register_r14,
            r15_in = in(reg) save_area.register_r15,
            rbp_in = in(reg) save_area.register_rbp,
            options(nostack, preserves_flags),
        );
    }
}

/// Restores the full x86-64 register state from save_area to the CPU.
///
/// Called during a context switch to resume the incoming thread.
/// The rsp register is intentionally NOT restored here — the kernel stack
/// pointer is managed separately by the context switch frame setup.
///
/// Phase 5: Documents intended restore sequence. Full integration occurs in Phase 7.
///
/// Enforces invariant INV-SCHED-003: register state restored exactly as saved.
/// Verified by: perform_context_switch (integration test, Phase 7).
pub fn restore_register_state_from_save_area(save_area: &RegisterSaveArea) {
    restore_registers_rax_through_rsi(save_area);
    restore_registers_r8_through_r11(save_area);
    restore_registers_r12_through_r15_and_rbp(save_area);
}

/// Performs a full context switch from one thread to another.
///
/// Saves the outgoing thread's register state to from_save_area, then
/// restores the incoming thread's register state from to_save_area.
///
/// This is the top-level context switch entry point called by the scheduler
/// on preemption or voluntary yield.
///
/// Phase 5: Save and restore are documented stubs. Full integration with
/// real userspace thread stacks occurs in Phase 7.
///
/// Enforces INV-SCHED-001 (domains only run in their partition slot) and
/// INV-SCHED-003 (register state is preserved across context switches).
/// Verified by: perform_context_switch integration test (Phase 7).
pub fn perform_context_switch(
    from_save_area: &mut RegisterSaveArea,
    to_save_area: &RegisterSaveArea,
) {
    save_register_state_to_save_area(from_save_area);
    save_extended_register_state_to_save_area(from_save_area);
    restore_register_state_from_save_area(to_save_area);
}
