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
        &*core::ptr::addr_of!(TASK_STATE_SEGMENT)
    }
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
