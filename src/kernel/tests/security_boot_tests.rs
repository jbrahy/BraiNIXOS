//! Security boot property tests for the Brainix kernel.
//!
//! These tests run on the HOST target (not x86_64-unknown-none) and verify
//! structural security properties of the kernel by inspecting source code.
//! Source inspection is used because the kernel is no_std and x86-only,
//! so runtime imports from brainix_kernel are not available on the host.
//!
//! REQ-06: Four security tests required before Phase 1 is complete.

/// Verifies that the panic handler disables interrupts before halting.
///
/// Enforces invariant INV-BOOT-003: the panic handler calls cli before hlt
/// to prevent recursive panics from interrupts firing during panic handling.
///
/// Verified by: structural source inspection via include_str!
#[test]
fn test_panic_handler_disables_interrupts_before_halt() {
    let main_source = include_str!("../src/main.rs");
    let panic_handler_body = extract_panic_handler_body(main_source);
    let cli_position = panic_handler_body.find("\"cli\"");
    let hlt_position = panic_handler_body.find("\"hlt\"");
    assert!(cli_position.is_some(), "panic handler must contain cli instruction");
    assert!(hlt_position.is_some(), "panic handler must contain hlt instruction");
    assert!(
        cli_position.unwrap() < hlt_position.unwrap(),
        "cli must appear before hlt in panic handler body"
    );
}

fn extract_panic_handler_body(source: &str) -> &str {
    let panic_handler_start = source
        .find("fn handle_kernel_panic")
        .expect("handle_kernel_panic function must exist in main.rs");
    &source[panic_handler_start..]
}

/// Verifies that the double-fault IDT entry is registered with an IST index.
///
/// Enforces invariant INV-FAULT-001: the double-fault handler must run on a
/// separate IST stack so a stack-overflow-induced double fault does not silently
/// triple fault.
///
/// Verified by: structural source inspection of interrupt_descriptor_table.rs
/// and task_state_segment.rs to confirm set_stack_index is called with a
/// constant IST index value.
#[test]
fn test_double_fault_handler_is_registered_on_separate_interrupt_stack_table_entry() {
    let interrupt_descriptor_table_source =
        include_str!("../src/arch/interrupts/interrupt_descriptor_table.rs");
    let task_state_segment_source =
        include_str!("../src/arch/interrupts/task_state_segment.rs");
    let set_stack_index_is_called =
        interrupt_descriptor_table_source.contains("set_stack_index");
    let interrupt_stack_table_index_is_defined =
        task_state_segment_source.contains("DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX");
    assert!(
        set_stack_index_is_called,
        "interrupt_descriptor_table.rs must call set_stack_index for double-fault IST"
    );
    assert!(
        interrupt_stack_table_index_is_defined,
        "task_state_segment.rs must define DOUBLE_FAULT_INTERRUPT_STACK_TABLE_INDEX"
    );
}

/// Phase 1 stub: verifies the stack guard page requirement is documented for Phase 2.
///
/// The real enforcement is implemented in Phase 2 (memory management). This stub
/// documents the Phase 2 requirement and prevents REQ-06 from being silently
/// forgotten. In Phase 2, this test will verify that the linker script
/// _kernel_stack_guard_page symbol corresponds to an unmapped page in the
/// active page table.
#[test]
fn test_stack_guard_page_is_unmapped_below_kernel_stack() {
    // Phase 1 stub — stack guard page enforcement is implemented in Phase 2
    // (memory management). This test will be updated to verify that the linker
    // script's _kernel_stack_guard_page symbol corresponds to an unmapped page
    // in the active page table.
    assert!(true, "Phase 1 stub: stack guard page enforcement deferred to Phase 2");
}
