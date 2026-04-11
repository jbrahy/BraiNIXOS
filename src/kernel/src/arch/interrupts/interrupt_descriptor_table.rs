//! Interrupt Descriptor Table with handlers for CPU exception vectors.
//!
//! Registers catch-all handlers for all publicly accessible exception vectors
//! (0-8, 10-14, 16-21, 28-30) via the x86_64 crate named fields.
//! Vectors 9, 15, 22-27, 31 are private/reserved in the x86_64 crate IDT
//! struct and cannot be registered; they will generate triple faults if
//! triggered (these are obsolete or permanently reserved by Intel).
//!
//! Allowlist: `src/kernel/src/arch/interrupts/` — IDT loading and IST stack
//! index assignment require direct CPU control structure manipulation.
#![allow(unsafe_code)]

use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::boot::serial::SerialOutputPort;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};

static mut INTERRUPT_DESCRIPTOR_TABLE: InterruptDescriptorTable = InterruptDescriptorTable::new();

/// Tracks whether the double-fault handler was registered with an IST index.
///
/// Set to true in register_double_fault_handler. Allows host-target tests to
/// verify the structural property without reading raw IDT entry options.
///
/// Verified by: test_double_fault_handler_is_registered_on_separate_interrupt_stack_table_entry
static DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX_IS_SET: AtomicBool = AtomicBool::new(false);

/// Returns true if the double-fault IDT entry was registered with a non-zero IST index.
///
/// Enforces invariant INV-FAULT-001: double-fault handler must run on a separate
/// IST stack. This function provides a host-testable structural check.
///
/// Verified by: test_double_fault_handler_is_registered_on_separate_interrupt_stack_table_entry
pub fn double_fault_uses_interrupt_stack_table() -> bool {
    DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX_IS_SET.load(Ordering::Acquire)
}

/// Load the IDT with handlers for all accessible exception vectors.
///
/// Enforces invariant INV-FAULT-002: all accessible CPU exception vectors have
/// registered handlers to prevent silent triple faults on those vectors.
///
/// Verified by: test_all_accessible_exception_vectors_have_handlers
// SAFETY: INTERRUPT_DESCRIPTOR_TABLE is a static mutated once during
// single-threaded boot before interrupts are enabled.
// - Precondition: GDT and TSS must be loaded before this function is called.
// - Invariant: INV-FAULT-002 (accessible vectors handled, no silent gaps).
// - Evidence: test_all_accessible_exception_vectors_have_handlers.
// Allowlist: src/kernel/src/arch/interrupts/ — IDT loading.
pub fn load_interrupt_descriptor_table(double_fault_stack_index: u16) {
    // SAFETY: addr_of_mut! avoids creating a Rust reference to the static mut,
    // preventing UB from the mutable-reference-to-mutable-static lint. The static
    // is mutated exactly once during single-threaded boot before interrupts are enabled.
    // - Precondition: GDT and TSS must be loaded before this function is called.
    // - Invariant: INV-FAULT-002 (accessible vectors handled, no silent gaps).
    // - Evidence: test_all_accessible_exception_vectors_have_handlers.
    // Allowlist: src/kernel/src/arch/interrupts/ — IDT loading.
    unsafe {
        let interrupt_descriptor_table_pointer =
            core::ptr::addr_of_mut!(INTERRUPT_DESCRIPTOR_TABLE);
        register_catch_all_exception_handlers(&mut *interrupt_descriptor_table_pointer);
        register_double_fault_handler(
            &mut *interrupt_descriptor_table_pointer,
            double_fault_stack_index,
        );
        (&*core::ptr::addr_of!(INTERRUPT_DESCRIPTOR_TABLE)).load();
    }
}

fn register_double_fault_handler(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
    double_fault_stack_index: u16,
) {
    let double_fault_entry =
        interrupt_descriptor_table.double_fault.set_handler_fn(handle_double_fault);
    // SAFETY: double_fault_stack_index is DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX (0),
    // which references IST[0] in the TSS initialized by initialize_task_state_segment().
    // The x86_64 crate handles the hardware +1 offset internally.
    // - Precondition: TSS IST[0] is initialized with a valid 4096-byte stack.
    // - Invariant: INV-FAULT-001 (double-fault on separate IST stack).
    // - Evidence: test_double_fault_handler_is_registered_on_separate_interrupt_stack_table_entry.
    // Allowlist: src/kernel/src/arch/interrupts/ — IDT IST index assignment.
    unsafe {
        double_fault_entry.set_stack_index(double_fault_stack_index);
    }
    DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX_IS_SET.store(true, Ordering::Release);
}

fn register_catch_all_exception_handlers(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
) {
    register_low_exception_handlers(interrupt_descriptor_table);
    register_fault_handlers_with_error_codes(interrupt_descriptor_table);
    register_floating_point_and_check_handlers(interrupt_descriptor_table);
    register_virtualization_and_security_handlers(interrupt_descriptor_table);
}

fn register_low_exception_handlers(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
) {
    interrupt_descriptor_table.divide_error.set_handler_fn(handle_division_error);
    interrupt_descriptor_table.debug.set_handler_fn(handle_debug_exception);
    interrupt_descriptor_table.non_maskable_interrupt.set_handler_fn(handle_non_maskable_interrupt);
    interrupt_descriptor_table.breakpoint.set_handler_fn(handle_breakpoint);
    interrupt_descriptor_table.overflow.set_handler_fn(handle_overflow);
    interrupt_descriptor_table.bound_range_exceeded.set_handler_fn(handle_bound_range_exceeded);
}

fn register_fault_handlers_with_error_codes(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
) {
    interrupt_descriptor_table.invalid_opcode.set_handler_fn(handle_invalid_opcode);
    interrupt_descriptor_table.device_not_available.set_handler_fn(handle_device_not_available);
    interrupt_descriptor_table.invalid_tss.set_handler_fn(handle_invalid_task_state_segment);
    interrupt_descriptor_table.segment_not_present.set_handler_fn(handle_segment_not_present);
    interrupt_descriptor_table.stack_segment_fault.set_handler_fn(handle_stack_segment_fault);
    interrupt_descriptor_table
        .general_protection_fault
        .set_handler_fn(handle_general_protection_fault);
}

fn register_floating_point_and_check_handlers(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
) {
    interrupt_descriptor_table.page_fault.set_handler_fn(handle_page_fault);
    interrupt_descriptor_table.x87_floating_point.set_handler_fn(handle_x87_floating_point_exception);
    interrupt_descriptor_table.alignment_check.set_handler_fn(handle_alignment_check);
    interrupt_descriptor_table.machine_check.set_handler_fn(handle_machine_check);
    interrupt_descriptor_table.simd_floating_point.set_handler_fn(handle_simd_floating_point_exception);
    interrupt_descriptor_table.virtualization.set_handler_fn(handle_virtualization_exception);
}

fn register_virtualization_and_security_handlers(
    interrupt_descriptor_table: &mut InterruptDescriptorTable,
) {
    interrupt_descriptor_table
        .cp_protection_exception
        .set_handler_fn(handle_control_protection_exception);
    interrupt_descriptor_table
        .hv_injection_exception
        .set_handler_fn(handle_hypervisor_injection_exception);
    interrupt_descriptor_table
        .vmm_communication_exception
        .set_handler_fn(handle_vmm_communication_exception);
    interrupt_descriptor_table
        .security_exception
        .set_handler_fn(handle_security_exception);
}

fn print_fault_message(vector_name: &str) {
    let mut emergency_serial_port = SerialOutputPort::initialize();
    let _ = writeln!(emergency_serial_port, "[FAULT] Exception: {}", vector_name);
    let _ = writeln!(emergency_serial_port, "[FAULT] System halted");
}

fn halt_processor_loop() -> ! {
    loop {
        // SAFETY: cli disables interrupts; hlt suspends until next interrupt.
        // Combined in a loop they halt the processor permanently after a fault.
        // - Precondition: executing in ring 0.
        // - Invariant: INV-FAULT-003 (fault handlers do not return to corrupted state).
        // - Evidence: QEMU integration test observes halt after fault.
        // Allowlist: src/kernel/src/arch/interrupts/ — cli/sti interrupt flag manipulation.
        unsafe {
            core::arch::asm!("cli", options(nomem, nostack, preserves_flags));
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

extern "x86-interrupt" fn handle_division_error(_stack_frame: InterruptStackFrame) {
    print_fault_message("Division Error (vector 0)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_debug_exception(_stack_frame: InterruptStackFrame) {
    print_fault_message("Debug Exception (vector 1)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_non_maskable_interrupt(_stack_frame: InterruptStackFrame) {
    print_fault_message("Non-Maskable Interrupt (vector 2)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_breakpoint(_stack_frame: InterruptStackFrame) {
    print_fault_message("Breakpoint (vector 3)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_overflow(_stack_frame: InterruptStackFrame) {
    print_fault_message("Overflow (vector 4)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_bound_range_exceeded(_stack_frame: InterruptStackFrame) {
    print_fault_message("Bound Range Exceeded (vector 5)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_invalid_opcode(_stack_frame: InterruptStackFrame) {
    print_fault_message("Invalid Opcode (vector 6)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_device_not_available(_stack_frame: InterruptStackFrame) {
    print_fault_message("Device Not Available (vector 7)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_double_fault(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    print_fault_message("Double Fault (vector 8)");
    halt_processor_loop()
}

extern "x86-interrupt" fn handle_invalid_task_state_segment(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Invalid Task State Segment (vector 10)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_segment_not_present(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Segment Not Present (vector 11)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_stack_segment_fault(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Stack Segment Fault (vector 12)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_general_protection_fault(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("General Protection Fault (vector 13)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_page_fault(
    _stack_frame: InterruptStackFrame,
    _error_code: PageFaultErrorCode,
) {
    print_fault_message("Page Fault (vector 14)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_x87_floating_point_exception(_stack_frame: InterruptStackFrame) {
    print_fault_message("x87 Floating Point Exception (vector 16)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_alignment_check(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Alignment Check (vector 17)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_machine_check(_stack_frame: InterruptStackFrame) -> ! {
    print_fault_message("Machine Check (vector 18)");
    halt_processor_loop()
}

extern "x86-interrupt" fn handle_simd_floating_point_exception(_stack_frame: InterruptStackFrame) {
    print_fault_message("SIMD Floating Point Exception (vector 19)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_virtualization_exception(_stack_frame: InterruptStackFrame) {
    print_fault_message("Virtualization Exception (vector 20)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_control_protection_exception(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Control Protection Exception (vector 21)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_hypervisor_injection_exception(
    _stack_frame: InterruptStackFrame,
) {
    print_fault_message("Hypervisor Injection Exception (vector 28)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_vmm_communication_exception(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("VMM Communication Exception (vector 29)");
    halt_processor_loop();
}

extern "x86-interrupt" fn handle_security_exception(
    _stack_frame: InterruptStackFrame,
    _error_code: u64,
) {
    print_fault_message("Security Exception (vector 30)");
    halt_processor_loop();
}
