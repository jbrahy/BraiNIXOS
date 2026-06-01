//! Interrupt handling subsystem: GDT, TSS, and IDT initialization.
//!
//! Allowlist: `src/kernel/src/arch/interrupts/` — IST setup, IDT loading, and
//! GDT loading require direct CPU control structure manipulation.
#![allow(unsafe_code)]

pub mod global_descriptor_table;
pub mod halt;
pub mod interrupt_descriptor_table;
pub mod task_state_segment;

use crate::boot::logger::BootStepLogger;

/// Initialize interrupt handling: build TSS, load GDT, load IDT.
///
/// Must be called during boot before any interrupt can occur.
/// Enforces invariant INV-BOOT-002: GDT, TSS, and IDT are all initialized
/// in the correct order before interrupts are enabled.
///
/// Verified by: test_interrupt_handling_initializes_without_fault
pub fn initialize_interrupt_handling(boot_step_logger: &mut BootStepLogger) {
    let task_state_segment_reference = task_state_segment::initialize_task_state_segment();
    global_descriptor_table::load_global_descriptor_table(task_state_segment_reference);
    let double_fault_index = task_state_segment::double_fault_interrupt_stack_table_index();
    interrupt_descriptor_table::load_interrupt_descriptor_table(double_fault_index);
    boot_step_logger.ok("Interrupt handling initialized (GDT + TSS + IDT)");
}
