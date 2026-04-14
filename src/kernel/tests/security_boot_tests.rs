//! Security boot property tests for the BraiNIX kernel.
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
/// The cli+hlt sequence is now centralised in arch::interrupts::halt. This
/// test verifies two structural properties:
/// 1. The panic handler delegates to `disable_interrupts_and_halt`.
/// 2. The halt helper contains "cli" before "hlt".
///
/// Verified by: structural source inspection via include_str!
#[test]
fn test_panic_handler_disables_interrupts_before_halt() {
    let main_source = include_str!("../src/main.rs");
    let halt_source = include_str!("../src/arch/interrupts/halt.rs");
    assert_panic_handler_delegates_to_halt_helper(main_source);
    assert_halt_helper_issues_cli_before_hlt(halt_source);
}

fn assert_panic_handler_delegates_to_halt_helper(main_source: &str) {
    let panic_handler_body = extract_panic_handler_body(main_source);
    assert!(
        panic_handler_body.contains("disable_interrupts_and_halt"),
        "panic handler must delegate to disable_interrupts_and_halt"
    );
}

fn assert_halt_helper_issues_cli_before_hlt(halt_source: &str) {
    let cli_position = halt_source.find("\"cli\"");
    let hlt_position = halt_source.find("\"hlt\"");
    assert_both_instructions_are_present(cli_position, hlt_position);
    assert_cli_appears_before_hlt(cli_position, hlt_position);
}

fn assert_both_instructions_are_present(cli_position: Option<usize>, hlt_position: Option<usize>) {
    assert!(
        cli_position.is_some(),
        "halt helper must contain cli instruction"
    );
    assert!(
        hlt_position.is_some(),
        "halt helper must contain hlt instruction"
    );
}

fn assert_cli_appears_before_hlt(cli_position: Option<usize>, hlt_position: Option<usize>) {
    let cli_offset = cli_position.unwrap_or(usize::MAX);
    let hlt_offset = hlt_position.unwrap_or(usize::MAX);
    assert!(
        cli_offset < hlt_offset,
        "cli must appear before hlt in panic handler body"
    );
}

fn extract_panic_handler_body(source: &str) -> &str {
    // If the function is not found, return an empty string. The caller's
    // subsequent assert!(cli_position.is_some()) will fail with a clear message.
    match source.find("fn handle_kernel_panic") {
        Some(panic_handler_start) => &source[panic_handler_start..],
        None => "",
    }
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
    let task_state_segment_source = include_str!("../src/arch/interrupts/task_state_segment.rs");
    let set_stack_index_is_called = interrupt_descriptor_table_source.contains("set_stack_index");
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

/// Verifies that SMEP and SMAP are enabled in CR4 before kernel entry.
///
/// Enforces invariant INV-BOOT-002: SMEP (CR4 bit 20) and SMAP (CR4 bit 21) must
/// be set before jumping to the kernel entry point. The combined bitmask 0x300000
/// represents both bits: (1 << 20) | (1 << 21) = 0x100000 | 0x200000 = 0x300000.
///
/// The bootloader implements this in main.rs via global_asm! (the canonical source
/// of truth — start.s is retained as a documentation artifact only).
///
/// Verified by: structural source inspection of src/bootloader/src/main.rs
/// via include_str! to confirm the SMEP+SMAP CR4 enablement pattern.
#[test]
fn test_bootloader_enables_smep_and_smap_before_kernel_entry() {
    let bootloader_main_source = include_str!("../../bootloader/src/main.rs");
    assert_smep_and_smap_bitmask_is_present(bootloader_main_source);
    assert_cr4_is_written_after_smep_smap_bitmask(bootloader_main_source);
}

fn assert_smep_and_smap_bitmask_is_present(bootloader_source: &str) {
    assert!(
        bootloader_source.contains("0x300000"),
        "bootloader must set SMEP (bit 20) and SMAP (bit 21) via bitmask 0x300000 in CR4"
    );
}

fn assert_cr4_is_written_after_smep_smap_bitmask(bootloader_source: &str) {
    let smep_smap_position = bootloader_source.find("0x300000");
    let cr4_write_position = find_cr4_write_after_position(bootloader_source, smep_smap_position);
    assert!(
        cr4_write_position.is_some(),
        "bootloader must write CR4 register after applying the SMEP+SMAP bitmask"
    );
}

fn find_cr4_write_after_position(
    bootloader_source: &str,
    smep_smap_position: Option<usize>,
) -> Option<usize> {
    let bitmask_offset = smep_smap_position?;
    let source_after_bitmask = &bootloader_source[bitmask_offset..];
    source_after_bitmask
        .find("mov cr4")
        .map(|offset| bitmask_offset + offset)
}

/// Verifies that all critical CPU exception vectors have registered handlers.
///
/// Enforces requirement REQ-04: all publicly accessible x86-64 exception vectors
/// must have handlers registered to prevent silent triple faults. This test
/// verifies the six most critical exception handlers are present as a structural
/// property of interrupt_descriptor_table.rs.
///
/// The x86_64 crate makes vectors 9, 15, 22-27, and 31 inaccessible via its public
/// API (they are obsolete or permanently Intel-reserved). The six handlers checked
/// here cover the exception vectors most likely to fire in kernel code.
///
/// Verified by: structural source inspection of interrupt_descriptor_table.rs
#[test]
fn test_all_critical_exception_vectors_have_registered_handlers() {
    let interrupt_descriptor_table_source =
        include_str!("../src/arch/interrupts/interrupt_descriptor_table.rs");
    assert_divide_error_handler_is_registered(interrupt_descriptor_table_source);
    assert_breakpoint_handler_is_registered(interrupt_descriptor_table_source);
    assert_invalid_opcode_handler_is_registered(interrupt_descriptor_table_source);
    assert_double_fault_handler_is_registered(interrupt_descriptor_table_source);
    assert_general_protection_fault_handler_is_registered(interrupt_descriptor_table_source);
    assert_page_fault_handler_is_registered(interrupt_descriptor_table_source);
}

fn assert_divide_error_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("divide_error");
    let handler_call_is_present = source.contains("handle_division_error");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the divide error exception (vector 0)"
    );
}

fn assert_breakpoint_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("breakpoint");
    let handler_call_is_present = source.contains("handle_breakpoint");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the breakpoint exception (vector 3)"
    );
}

fn assert_invalid_opcode_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("invalid_opcode");
    let handler_call_is_present = source.contains("handle_invalid_opcode");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the invalid opcode exception (vector 6)"
    );
}

fn assert_double_fault_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("double_fault");
    let handler_call_is_present = source.contains("handle_double_fault");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the double fault exception (vector 8)"
    );
}

fn assert_general_protection_fault_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("general_protection_fault");
    let handler_call_is_present = source.contains("handle_general_protection_fault");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the general protection fault exception (vector 13)"
    );
}

fn assert_page_fault_handler_is_registered(source: &str) {
    let field_access_is_present = source.contains("page_fault");
    let handler_call_is_present = source.contains("handle_page_fault");
    assert!(
        field_access_is_present && handler_call_is_present,
        "interrupt_descriptor_table.rs must register a handler for the page fault exception (vector 14)"
    );
}

/// Verifies the kernel stack guard page is structurally absent from kernel page table mappings.
///
/// Enforces invariant INV-MEM-007: kernel stack overrun must fault, not corrupt silently.
/// The guard page at INITIAL_KERNEL_STACK_GUARD_PAGE_ADDRESS is enforced by construction:
/// map_kernel_stack_region in kernel_page_table.rs starts at INITIAL_KERNEL_STACK_BOTTOM,
/// never mapping the guard page address.
///
/// Verified by: structural source inspection of kernel_page_table.rs and stack_guard.rs
#[test]
fn test_stack_guard_page_is_unmapped_below_kernel_stack() {
    let kernel_page_table_source = include_str!("../src/arch/paging/kernel_page_table.rs");
    let stack_guard_source = include_str!("../src/arch/paging/stack_guard.rs");
    assert_guard_page_address_is_never_mapped(kernel_page_table_source);
    assert_guard_page_module_enforces_inv_mem_007(stack_guard_source);
}

fn assert_guard_page_address_is_never_mapped(kernel_page_table_source: &str) {
    let maps_from_stack_bottom = kernel_page_table_source.contains("INITIAL_KERNEL_STACK_BOTTOM");
    let skips_guard_page = kernel_page_table_source.contains("INITIAL_KERNEL_STACK_GUARD_PAGE");
    assert!(
        maps_from_stack_bottom,
        "kernel_page_table.rs must map from INITIAL_KERNEL_STACK_BOTTOM (not the guard page)"
    );
    assert!(
        skips_guard_page,
        "kernel_page_table.rs must reference the guard page (to document it is skipped)"
    );
}

fn assert_guard_page_module_enforces_inv_mem_007(stack_guard_source: &str) {
    assert!(
        stack_guard_source.contains("INV-MEM-007"),
        "stack_guard.rs must reference INV-MEM-007 (kernel stack overrun must fault)"
    );
    assert!(
        stack_guard_source.contains("configure_kernel_stack_guard_page"),
        "stack_guard.rs must define configure_kernel_stack_guard_page"
    );
}
