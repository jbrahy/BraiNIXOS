//! Task State Segment (TSS) with dedicated double-fault IST stack.
//!
//! Allowlist: `src/kernel/src/arch/interrupts/` — TSS setup requires writing to
//! CPU control structures that have no safe Rust interface.
#![allow(unsafe_code)]

use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

const DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX: u16 = 0;
const DOUBLE_FAULT_STACK_SIZE_IN_BYTES: usize = 4096;

static mut DOUBLE_FAULT_INTERRUPT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE_IN_BYTES] =
    [0; DOUBLE_FAULT_STACK_SIZE_IN_BYTES];

/// Size of the ring-0 stack the CPU switches to on a privilege change from
/// ring 3 (syscall trampoline / interrupt). 16 KiB is ample for the kernel's
/// short, bounded syscall handlers.
const SYSCALL_KERNEL_STACK_SIZE_IN_BYTES: usize = 16 * 1024;

/// Page-aligned ring-0 stack loaded into TSS.RSP0. The CPU loads RSP0 on every
/// ring 3 -> ring 0 transition; the KPTI trampoline also reads this value from
/// its scratch page to switch stacks before it has the kernel page table.
#[repr(align(4096))]
struct SyscallKernelStack([u8; SYSCALL_KERNEL_STACK_SIZE_IN_BYTES]);

static mut SYSCALL_KERNEL_STACK: SyscallKernelStack =
    SyscallKernelStack([0; SYSCALL_KERNEL_STACK_SIZE_IN_BYTES]);

static mut TASK_STATE_SEGMENT: TaskStateSegment = TaskStateSegment::new();

/// Initialize the TSS with a dedicated double-fault IST[0] stack.
///
/// Enforces invariant INV-FAULT-001: double-fault handler runs on a separate
/// stack so a stack-overflow-induced double fault does not silently triple fault.
///
/// Verified by: test_double_fault_uses_separate_ist_stack
///
/// # Safety
/// Caller must ensure this function is called exactly once during boot,
/// before the GDT is loaded. The returned reference is valid for 'static
/// because TASK_STATE_SEGMENT is a static.
// SAFETY: TASK_STATE_SEGMENT is a static that is only mutated here during
// single-threaded boot initialization. Single-core constraint (no SMP)
// guarantees no concurrent access.
// - Precondition: called once during boot before GDT load.
// - Invariant: INV-FAULT-001 (double-fault on separate IST stack).
// - Evidence: test_double_fault_uses_separate_ist_stack.
// Allowlist: src/kernel/src/arch/interrupts/ — TSS IST stack pointer write.
pub fn initialize_task_state_segment() -> &'static TaskStateSegment {
    let stack_top = compute_double_fault_stack_top();
    // SAFETY: TASK_STATE_SEGMENT is a static mutated once during single-threaded
    // boot initialization. addr_of_mut! avoids creating a Rust reference to the
    // static mut, preventing UB from the shared-reference-to-mutable-static lint.
    // - Precondition: called once during boot before GDT load.
    // - Invariant: INV-FAULT-001 (double-fault on separate IST stack).
    // - Evidence: test_double_fault_uses_separate_ist_stack.
    // Allowlist: src/kernel/src/arch/interrupts/ — TSS IST stack pointer write.
    unsafe {
        let task_state_segment_pointer = core::ptr::addr_of_mut!(TASK_STATE_SEGMENT);
        let interrupt_stack_table_entry = core::ptr::addr_of_mut!(
            (*task_state_segment_pointer).interrupt_stack_table
                [DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX as usize]
        );
        interrupt_stack_table_entry.write(stack_top);
        let privilege_stack_table_entry =
            core::ptr::addr_of_mut!((*task_state_segment_pointer).privilege_stack_table[0]);
        privilege_stack_table_entry.write(compute_syscall_kernel_stack_top());
        &*core::ptr::addr_of!(TASK_STATE_SEGMENT)
    }
}

/// Returns the top of the ring-0 syscall stack (the value placed in TSS.RSP0).
///
/// The KPTI syscall trampoline reads this to switch to a kernel stack on entry
/// from ring 3 before it loads the kernel page table.
pub fn syscall_kernel_stack_top() -> u64 {
    compute_syscall_kernel_stack_top().as_u64()
}

fn compute_syscall_kernel_stack_top() -> VirtAddr {
    // SAFETY: addr_of! takes the array address without forming a reference;
    // add(1) is the valid one-past-the-end pointer (the stack grows down from it).
    // - Precondition: SYSCALL_KERNEL_STACK is a 'static with known size.
    // - Invariant: ring-0 entries land on a mapped, aligned kernel stack.
    // - Evidence: live boot reaches userspace via the trampoline.
    // Allowlist: src/kernel/src/arch/interrupts/ — ring-0 stack pointer setup.
    let stack_pointer = core::ptr::addr_of!(SYSCALL_KERNEL_STACK);
    let stack_top_pointer = unsafe { stack_pointer.add(1) };
    VirtAddr::from_ptr(stack_top_pointer as *const u8)
}

fn compute_double_fault_stack_top() -> VirtAddr {
    // SAFETY: addr_of! obtains the address of the array without creating a reference.
    // ptr::add(1) advances by one array length — a valid one-past-the-end pointer
    // per Rust's pointer provenance rules (the array is 'static, so the pointer is valid).
    // from_ptr casts it to VirtAddr without dereferencing.
    // - Precondition: DOUBLE_FAULT_INTERRUPT_STACK is a static with known size.
    // - Invariant: INV-FAULT-001 (separate stack for double-fault handler).
    // - Evidence: test_double_fault_uses_separate_ist_stack.
    // Allowlist: src/kernel/src/arch/interrupts/ — IST stack pointer setup.
    let stack_array_pointer = core::ptr::addr_of!(DOUBLE_FAULT_INTERRUPT_STACK);
    let stack_top_pointer = unsafe { stack_array_pointer.add(1) };
    VirtAddr::from_ptr(stack_top_pointer as *const u8)
}

/// Returns the IST array index used for the double-fault handler.
///
/// The x86_64 crate uses 0-based indexing internally; hardware IST is 1-based.
/// The crate handles the +1 offset — callers use index 0 everywhere.
pub fn double_fault_interrupt_stack_table_index() -> u16 {
    DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX
}
