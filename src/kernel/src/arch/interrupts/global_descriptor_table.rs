//! Global Descriptor Table with kernel code segment and TSS selector.
//!
//! Allowlist: `src/kernel/src/arch/interrupts/` — GDT loading requires direct
//! CPU control structure manipulation that has no safe Rust interface.
#![allow(unsafe_code)]

use x86_64::instructions::segmentation::{Segment, CS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;

static mut GLOBAL_DESCRIPTOR_TABLE: GlobalDescriptorTable = GlobalDescriptorTable::new();
static mut KERNEL_CODE_SEGMENT_SELECTOR: SegmentSelector = SegmentSelector(0);
static mut TASK_STATE_SEGMENT_SELECTOR: SegmentSelector = SegmentSelector(0);

/// Load the GDT with a kernel code segment and TSS selector, then reload CS and TSS.
///
/// Enforces invariant INV-BOOT-002: GDT is loaded with valid kernel segments
/// before the IDT is loaded or interrupts are enabled.
///
/// Verified by: test_gdt_loaded_with_kernel_segments
// SAFETY: GLOBAL_DESCRIPTOR_TABLE is a static mutated once during single-threaded
// boot. Single-core constraint guarantees no concurrent access.
// - Precondition: called once during boot, after TSS is initialized.
// - Invariant: INV-BOOT-002 (GDT loaded before IDT).
// - Evidence: test_gdt_loaded_with_kernel_segments.
// Allowlist: src/kernel/src/arch/interrupts/ — GDT and TSS loading.
pub fn load_global_descriptor_table(task_state_segment: &'static TaskStateSegment) {
    populate_global_descriptor_table(task_state_segment);
    apply_global_descriptor_table();
}

fn populate_global_descriptor_table(task_state_segment: &'static TaskStateSegment) {
    // SAFETY: addr_of_mut! avoids creating a Rust reference to the static mut,
    // preventing UB from the shared-reference-to-mutable-static lint. The static
    // is mutated exactly once during single-threaded boot initialization.
    // - Precondition: called before GDT.load() in apply_global_descriptor_table.
    // - Invariant: INV-BOOT-002 (GDT loaded before IDT).
    // - Evidence: test_gdt_loaded_with_kernel_segments.
    // Allowlist: src/kernel/src/arch/interrupts/ — GDT segment descriptor setup.
    unsafe {
        let kernel_code_selector =
            (*core::ptr::addr_of_mut!(GLOBAL_DESCRIPTOR_TABLE))
                .append(Descriptor::kernel_code_segment());
        core::ptr::addr_of_mut!(KERNEL_CODE_SEGMENT_SELECTOR).write(kernel_code_selector);
        let task_state_segment_selector =
            (*core::ptr::addr_of_mut!(GLOBAL_DESCRIPTOR_TABLE))
                .append(Descriptor::tss_segment(task_state_segment));
        core::ptr::addr_of_mut!(TASK_STATE_SEGMENT_SELECTOR).write(task_state_segment_selector);
    }
}

fn apply_global_descriptor_table() {
    // SAFETY: addr_of! obtains a &'static reference to the GDT without going
    // through a mutable-static reference. CS::set_reg and load_tss read the
    // selectors written by populate_global_descriptor_table.
    // - Precondition: populate_global_descriptor_table has been called.
    // - Invariant: INV-BOOT-002 (GDT loaded before IDT).
    // - Evidence: test_gdt_loaded_with_kernel_segments.
    // Allowlist: src/kernel/src/arch/interrupts/ — GDT and TSS loading.
    unsafe {
        let global_descriptor_table_reference = &*core::ptr::addr_of!(GLOBAL_DESCRIPTOR_TABLE);
        global_descriptor_table_reference.load();
        CS::set_reg(core::ptr::addr_of!(KERNEL_CODE_SEGMENT_SELECTOR).read());
        load_tss(core::ptr::addr_of!(TASK_STATE_SEGMENT_SELECTOR).read());
    }
}
