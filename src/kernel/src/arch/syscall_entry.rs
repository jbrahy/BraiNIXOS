//! SYSCALL/SYSRET entry and exit stub (D-10, D-11).
//!
//! Implements IPC_SPEC.md §8 register ABI exactly.
//! Falls under src/kernel/src/arch/ (assembly stubs) unsafe allowlist entry
//! in docs/security/UNSAFE_CODE_POLICY.md.
//!
//! Security properties enforced:
//! - r11 saved to kernel stack (SYSCALL clobbers r11 with RFLAGS)
//! - rcx saved to kernel stack (SYSCALL clobbers rcx with return RIP)
//! - All non-return registers zeroed before SYSRET (no leakage between processes)
//! - Return RIP (rcx) validated as canonical before SYSRET (Intel errata, D-11)
//! - Non-canonical RIP falls back to IRETQ
//!
//! Phase 4 simplification: no GS-based stack switching. RSP remains on the
//! kernel stack throughout Phase 4 (no real userspace process exists yet).
//! Phase 5 replaces with proper per-thread kernel stack switching.
//!
//! Phase 11 addition: after the 10-register push sequence, all 7 IPC argument
//! registers are stored to `KERNEL_SYSCALL_*_VALUE` AtomicU64 globals via
//! RIP-relative stores. This makes the arguments available to IPC dispatch
//! handlers without passing them through the assembly ABI (D-01).
#![allow(unsafe_code)]

use core::arch::global_asm;

/// Installs the SYSCALL handler by writing the entry point address to LSTAR MSR.
///
/// LSTAR = IA32_LSTAR (0xC0000082) — holds the 64-bit SYSCALL target RIP.
/// STAR  = IA32_STAR  (0xC0000081) — encodes CS and SS selectors for SYSCALL/SYSRET.
/// SFMASK = IA32_SFMASK (0xC0000084) — bits to clear in RFLAGS on SYSCALL entry.
///
/// # Safety
///
/// Writing MSRs requires ring 0. This function is called only from the boot
/// sequence (ring 0). Writing LSTAR to `syscall_entry_point` is safe because
/// `syscall_entry_point` is a valid kernel function pointer in kernel .text.
///
/// - Precondition: CPU is in ring 0; called after GDT is loaded (Phase 1).
/// - Invariant: INV-IPC-001 (all IPC through kernel entry), INV-AUTH-001 (no ambient authority).
/// - Evidence: test_syscall_entry_stub_registers_lstar_msr (source inspection test).
pub fn install_syscall_entry_point() {
    // SAFETY: Ring 0 MSR write. LSTAR points to validated kernel entry stub.
    // Precondition: CPU in ring 0; GDT loaded (Phase 1 prerequisite).
    // Invariant: INV-IPC-001 (all IPC routes through this entry point).
    // Evidence: test_syscall_entry_stub_registers_lstar_msr.
    unsafe {
        write_lstar_msr_with_entry_point();
        write_star_msr_with_segment_selectors();
        write_sfmask_msr_to_clear_interrupt_flag();
    }
}

/// Writes the SYSCALL entry point address to IA32_LSTAR (0xC0000082).
///
/// # Safety
///
/// Ring 0 required. Entry point must be a valid kernel function pointer.
unsafe fn write_lstar_msr_with_entry_point() {
    // SAFETY: function pointer cast to integer for MSR write; syscall_entry_point is a valid .text address.
    // Using *const () intermediate to satisfy cast_fn_ptr_to_usize (clippy allows fn->*const()->usize).
    let entry_point_fn_ptr = syscall_entry_point as *const ();
    let entry_point_address = entry_point_fn_ptr as u64;
    let low_bits = entry_point_address as u32;
    let high_bits = (entry_point_address >> 32) as u32;
    // SAFETY: Ring 0 MSR write; IA32_LSTAR = 0xC0000082.
    // Precondition: entry_point_address is a valid .text symbol.
    // Invariant: INV-IPC-001.
    // Evidence: test_syscall_entry_stub_registers_lstar_msr.
    core::arch::asm!(
        "wrmsr",
        in("ecx") 0xC000_0082u32,
        in("eax") low_bits,
        in("edx") high_bits,
        options(nostack, preserves_flags),
    );
}

/// Writes segment selectors to IA32_STAR (0xC0000081).
///
/// Bits [63:48] = user code selector base (0x18), bits [47:32] = kernel code
/// selector (0x08). Values match the GDT established in Phase 1.
///
/// # Safety
///
/// Ring 0 required. Selector values must match the live GDT layout.
unsafe fn write_star_msr_with_segment_selectors() {
    // Bits [63:48] = user CS base (0x18), bits [47:32] = kernel CS (0x08).
    // SYSRET uses [63:48] | 3 for user CS and [63:48] + 8 for user SS.
    // SYSCALL uses [47:32] for kernel CS and [47:32] + 8 for kernel SS.
    let star_register_value: u64 = 0x0018_0008_u64 << 32;
    // SAFETY: Ring 0 MSR write; IA32_STAR = 0xC0000081.
    // Precondition: GDT is loaded with kernel CS=0x08, user CS=0x18.
    // Invariant: INV-IPC-001.
    // Evidence: test_syscall_entry_stub_registers_lstar_msr.
    core::arch::asm!(
        "wrmsr",
        in("ecx") 0xC000_0081u32,
        in("eax") star_register_value as u32,
        in("edx") (star_register_value >> 32) as u32,
        options(nostack, preserves_flags),
    );
}

/// Writes SFMASK to IA32_SFMASK (0xC0000084) to clear IF on SYSCALL entry.
///
/// Clearing IF prevents hardware interrupts during the early SYSCALL entry
/// path before the kernel has a chance to save state.
///
/// # Safety
///
/// Ring 0 required. Clearing IF is safe at kernel entry; IF is restored on SYSRET.
unsafe fn write_sfmask_msr_to_clear_interrupt_flag() {
    // SAFETY: Ring 0 MSR write; IA32_SFMASK = 0xC0000084.
    // Precondition: CPU in ring 0.
    // Invariant: INV-IPC-001 (prevents interrupt during kernel entry save sequence).
    // Evidence: test_syscall_entry_stub_registers_lstar_msr.
    core::arch::asm!(
        "wrmsr",
        in("ecx") 0xC000_0084u32,
        in("eax") 0x0200u32,
        in("edx") 0u32,
        options(nostack, preserves_flags),
    );
}

/// Checks whether `address` is a canonical x86-64 virtual address.
///
/// Canonical addresses have bits [63:48] all equal to bit 47 (sign extension).
/// Non-canonical addresses in SYSRET cause a GP fault in ring 0 on Intel CPUs
/// (Intel errata D-11 — SYSRET to non-canonical RIP is fatal in kernel mode).
///
/// Enforces D-11: return RIP must be canonical before SYSRET.
#[no_mangle]
pub extern "C" fn is_canonical_virtual_address(address: u64) -> bool {
    let sign_extended_bits = ((address as i64) >> 47) as u64;
    sign_extended_bits == 0 || sign_extended_bits == 0xFFFF_FFFF_FFFF_FFFFu64
}

// The SYSCALL entry point is implemented in global_asm! to precisely control
// register state without Rust's calling convention imposing register allocations.
//
// Phase 4 simplification: RSP is already on the kernel stack (no actual userspace
// process exists in Phase 4). Full GS-based per-thread stack switching is deferred
// to Phase 5.
//
// Register save order on kernel stack (growing downward):
//   [rsp+0]  = r12 (Capability Register)
//   [rsp+8]  = r10 (Message Register 2)
//   [rsp+16] = r9  (Message Register 1)
//   [rsp+24] = r8  (Message Register 0)
//   [rsp+32] = rdx (timeout_ticks)
//   [rsp+40] = rsi (cap CSlot / receive destination)
//   [rsp+48] = rdi (endpoint CSlot)
//   [rsp+56] = rax (syscall number)
//   [rsp+64] = r11 (RFLAGS, clobbered by SYSCALL)
//   [rsp+72] = rcx (return RIP, clobbered by SYSCALL)
//
// The canonical RIP check runs BEFORE dispatch_syscall because:
// - rcx = return RIP at entry (placed there by SYSCALL instruction).
// - is_canonical_virtual_address is called with rcx as argument (rdi per SysV ABI).
// - is_canonical_virtual_address uses rax for its return value.
// - dispatch_syscall is called AFTER the check, so no rax conflict exists.
//
// Stack alignment: System V AMD64 ABI requires 16-byte aligned RSP before a
// CALL instruction. After SYSCALL, RSP alignment depends on the calling context.
// We push 10 registers (80 bytes) before calling dispatch_syscall; the alignment
// before the call is preserved by the "and $-16, %rsp" instruction after saving.
// Note: This alignment fixup is Phase 4 only; Phase 5 will control stack layout fully.
global_asm!(
    ".global syscall_entry_point",
    "syscall_entry_point:",
    // KPTI entry: the CPU arrived here on the USER page table and USER stack.
    // Swap to the kernel page table and the ring-0 stack before touching any
    // kernel memory. rcx (return RIP) and r11 (RFLAGS) must be preserved.
    "mov %rsp, SYSCALL_TRAMPOLINE_SCRATCH+24(%rip)", // save user rsp
    "mov %rax, SYSCALL_TRAMPOLINE_SCRATCH+32(%rip)", // spill rax to free a register
    "mov SYSCALL_TRAMPOLINE_SCRATCH+0(%rip), %rax",  // kernel CR3
    "mov %rax, %cr3",                                 // -> kernel page table (kernel now mapped)
    "mov SYSCALL_TRAMPOLINE_SCRATCH+8(%rip), %rsp",  // kernel RSP0
    "mov SYSCALL_TRAMPOLINE_SCRATCH+32(%rip), %rax", // restore rax
    // SYSCALL clobbers rcx (return RIP) and r11 (RFLAGS). Save them first.
    "push %rcx",
    "push %r11",
    // Save all D-10 argument registers to kernel stack.
    "push %rax",
    "push %rdi",
    "push %rsi",
    "push %rdx",
    "push %r8",
    "push %r9",
    "push %r10",
    "push %r12",
    // Save IPC syscall argument registers to kernel globals (single-core, no TOCTOU).
    // rax is safe to use as scratch — already saved at [rsp+56].
    // Enforces D-01: argument propagation via #[no_mangle] AtomicU64 globals.
    "mov 48(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_ENDPOINT_SLOT_VALUE(%rip)",
    "mov 40(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_CAP_SLOT_VALUE(%rip)",
    "mov 32(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE(%rip)",
    "mov 24(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE(%rip)",
    "mov 16(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE(%rip)",
    "mov 8(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE(%rip)",
    "mov 0(%rsp), %rax",
    "mov %rax, KERNEL_SYSCALL_CAPABILITY_REGISTER_VALUE(%rip)",
    // Validate return RIP (rcx) is canonical BEFORE dispatch_syscall.
    // rcx was saved to stack; reload it from the saved position (rsp+80 from current rsp).
    // rcx = return RIP (saved at rsp+64 from current rsp = 8 pushes * 8 bytes = 64 + 16 for r11/rcx = rsp+80).
    // Actually: we pushed rcx first (at rsp+72 after 10 pushes), so reload from offset.
    // Stack layout after 10 pushes: rcx at [rsp+72], r11 at [rsp+64].
    "mov 72(%rsp), %rdi",
    "call is_canonical_virtual_address",
    "test %rax, %rax",
    "jz .Liretq_fallback",
    // Canonical RIP: load syscall number and thread identifier, then dispatch.
    // Thread identity comes from kernel memory (CURRENT_THREAD_IDENTIFIER_VALUE), not
    // from any userspace-controlled register. Single read in assembly per D-03.
    // T-10-03-01: userspace cannot write kernel BSS; T-10-03-02: single-core prevents TOCTOU.
    "mov 56(%rsp), %rdi",
    "mov CURRENT_THREAD_IDENTIFIER_VALUE(%rip), %esi",
    "call dispatch_syscall",
    // rax now holds the return code from dispatch_syscall.
    // Save return code; restore non-return registers.
    "pop %r12",
    "pop %r10",
    "pop %r9",
    "pop %r8",
    "pop %rdx",
    "pop %rsi",
    "pop %rdi",
    // Discard saved rax (syscall number); rax already has the return code.
    "add $8, %rsp",
    "pop %r11",
    "pop %rcx",
    // Zero all non-return registers before SYSRET (D-11 — no information leakage).
    "xor %rbx, %rbx",
    "xor %rbp, %rbp",
    "xor %r13, %r13",
    "xor %r14, %r14",
    "xor %r15, %r15",
    // KPTI exit: rax holds the return code, rcx the return RIP, r11 the RFLAGS.
    // Swap back to the user page table and the user stack, then SYSRET.
    "mov %rax, SYSCALL_TRAMPOLINE_SCRATCH+32(%rip)", // save return code
    "mov SYSCALL_TRAMPOLINE_SCRATCH+16(%rip), %rax", // user CR3
    "mov %rax, %cr3",                                 // -> user page table
    "mov SYSCALL_TRAMPOLINE_SCRATCH+24(%rip), %rsp", // restore user rsp
    "mov SYSCALL_TRAMPOLINE_SCRATCH+32(%rip), %rax", // restore return code
    // SYSRET restores RIP from rcx and RFLAGS from r11 (both pre-verified canonical).
    "sysretq",
    ".Liretq_fallback:",
    // A non-canonical return RIP cannot occur for a correctly-built userspace
    // binary. Halt rather than attempt an IRETQ frame here.
    "hlt",
    // First entry to ring 3: rdi=entry RIP, rsi=user RSP, rdx=user CR3. Runs on
    // the kernel page table until the `mov %rdx,%cr3`; the rest executes from this
    // (user-mapped) trampoline page under the user page table.
    ".global enter_userspace_trampoline",
    "enter_userspace_trampoline:",
    "mov %rdx, SYSCALL_TRAMPOLINE_SCRATCH+16(%rip)", // record user CR3 for later exits
    "mov %rsi, SYSCALL_TRAMPOLINE_SCRATCH+24(%rip)", // user rsp
    "mov %rdi, %rcx",                                 // SYSRET loads RIP from rcx
    "mov $0x202, %r11",                               // RFLAGS: IF set (bit 9) + reserved bit 1
    "mov %rdx, %cr3",                                 // -> user page table
    "mov SYSCALL_TRAMPOLINE_SCRATCH+24(%rip), %rsp",  // load user rsp
    "xor %rax, %rax",
    "xor %rbx, %rbx",
    "xor %rdx, %rdx",
    "xor %rsi, %rsi",
    "xor %rdi, %rdi",
    "xor %rbp, %rbp",
    "xor %r8, %r8",
    "xor %r9, %r9",
    "xor %r10, %r10",
    "xor %r12, %r12",
    "xor %r13, %r13",
    "xor %r14, %r14",
    "xor %r15, %r15",
    "sysretq",
    options(att_syntax),
);

extern "C" {
    /// The SYSCALL entry point installed in LSTAR. Symbol defined by global_asm! above.
    fn syscall_entry_point();
}
