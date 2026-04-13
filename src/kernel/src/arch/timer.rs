//! Local APIC timer programming for scheduler tick generation.
//!
//! Unsafe code allowed per UNSAFE_CODE_POLICY.md: APIC timer programming
//! in src/kernel/src/arch/ (assembly stubs allowlist entry).
#![allow(unsafe_code)]

/// Base physical address of the local APIC memory-mapped register block.
const LOCAL_APIC_BASE_ADDRESS: u64 = 0xFEE0_0000;

/// Offset from APIC base to the Timer Local Vector Table entry register.
const APIC_TIMER_LOCAL_VECTOR_TABLE_OFFSET: u64 = 0x320;

/// Offset from APIC base to the Timer Initial Count register.
const APIC_TIMER_INITIAL_COUNT_OFFSET: u64 = 0x380;

/// Offset from APIC base to the Timer Divide Configuration register.
const APIC_TIMER_DIVIDE_CONFIGURATION_OFFSET: u64 = 0x3E0;

/// Offset from APIC base to the End-Of-Interrupt register.
const APIC_TIMER_END_OF_INTERRUPT_OFFSET: u64 = 0x0B0;

/// Interrupt vector number assigned to the APIC timer (IRQ 32, first user vector).
const APIC_TIMER_INTERRUPT_VECTOR: u32 = 0x20;

/// LVT bit mask to select periodic timer delivery mode.
const APIC_TIMER_PERIODIC_MODE_FLAG: u32 = 0x0002_0000;

/// Timer divide-by-16 value for the divide configuration register.
const APIC_TIMER_DIVIDE_BY_16: u32 = 0x03;

/// Initial count value for the APIC timer (calibrated for QEMU).
const APIC_TIMER_INITIAL_COUNT_VALUE: u32 = 10_000;

/// Configures the divide register to divide by 16.
///
/// Must be called before writing the initial count so the timer
/// frequency is deterministic.
fn write_apic_timer_divide_configuration() {
    let register_address = LOCAL_APIC_BASE_ADDRESS + APIC_TIMER_DIVIDE_CONFIGURATION_OFFSET;
    // SAFETY: MMIO write to the APIC divide configuration register.
    // - Precondition: APIC is present and base address is identity-mapped.
    // - Invariant: INV-SCHED-001 (timer fires at defined periodic rate).
    // - Evidence: initialize_apic_timer integration with boot sequence.
    unsafe {
        core::ptr::write_volatile(register_address as *mut u32, APIC_TIMER_DIVIDE_BY_16);
    }
}

/// Programs the LVT timer register to deliver IRQ at vector 0x20 in periodic mode.
fn write_apic_timer_local_vector_table_entry() {
    let register_address = LOCAL_APIC_BASE_ADDRESS + APIC_TIMER_LOCAL_VECTOR_TABLE_OFFSET;
    let lvt_value = APIC_TIMER_PERIODIC_MODE_FLAG | APIC_TIMER_INTERRUPT_VECTOR;
    // SAFETY: MMIO write to the APIC LVT timer register.
    // - Precondition: APIC is present and base address is identity-mapped.
    // - Invariant: INV-SCHED-001 (scheduler tick fires periodically at fixed vector).
    // - Evidence: initialize_apic_timer integration with boot sequence.
    unsafe {
        core::ptr::write_volatile(register_address as *mut u32, lvt_value);
    }
}

/// Writes the initial count to start the APIC countdown timer.
///
/// Writing the initial count starts the timer immediately.
fn write_apic_timer_initial_count() {
    let register_address = LOCAL_APIC_BASE_ADDRESS + APIC_TIMER_INITIAL_COUNT_OFFSET;
    // SAFETY: MMIO write to the APIC initial count register.
    // - Precondition: Divide configuration and LVT are already written.
    // - Invariant: INV-SCHED-001 (timer starts firing after this write).
    // - Evidence: initialize_apic_timer integration with boot sequence.
    unsafe {
        core::ptr::write_volatile(register_address as *mut u32, APIC_TIMER_INITIAL_COUNT_VALUE);
    }
}

/// Starts the APIC timer in periodic mode. Called during boot. Enforces INV-SCHED-001.
///
/// Programs the local APIC to fire IRQ 32 (vector 0x20) at a fixed periodic rate
/// determined by APIC_TIMER_INITIAL_COUNT_VALUE divided by APIC_TIMER_DIVIDE_BY_16.
///
/// Must be called from the boot sequence in ring 0 after the APIC MMIO region
/// is identity-mapped (Phase 2 page tables are loaded before this call in Phase 5).
///
/// Enforces invariant INV-SCHED-001: every security domain receives CPU time only
/// within its assigned partition slot, driven by this hardware timer.
///
/// Verified by: boot sequence integration (timer interrupt handler calls process_scheduler_tick).
pub fn initialize_apic_timer() {
    write_apic_timer_divide_configuration();
    write_apic_timer_local_vector_table_entry();
    write_apic_timer_initial_count();
}

/// Writes to the APIC End-Of-Interrupt register to acknowledge a timer interrupt.
///
/// Must be called at the end of every APIC timer interrupt handler. Failing to
/// send EOI prevents further interrupts from the local APIC.
///
/// Enforces INV-SCHED-001: timer interrupts continue firing after each handler
/// completes, ensuring the scheduler tick is never silently dropped.
///
/// Verified by: timer interrupt handler in arch/interrupts/ (future plan).
pub fn acknowledge_apic_timer_interrupt() {
    let register_address = LOCAL_APIC_BASE_ADDRESS + APIC_TIMER_END_OF_INTERRUPT_OFFSET;
    // SAFETY: EOI write to APIC MMIO; no side effects beyond acknowledging interrupt.
    // - Precondition: Called from within an APIC interrupt handler.
    // - Invariant: INV-SCHED-001 (subsequent timer interrupts are not masked).
    // - Evidence: timer interrupt handler integration (future plan).
    unsafe {
        core::ptr::write_volatile(register_address as *mut u32, 0);
    }
}
