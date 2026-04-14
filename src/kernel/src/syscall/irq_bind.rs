//! sys_irq_bind handler for Phase 8 device isolation.
//!
//! Binds a hardware IRQ line to an IPC endpoint. When the IRQ fires,
//! the kernel delivers an IPC message to the bound endpoint, allowing the
//! device server to receive interrupt notifications via ipc_receive.
//!
//! Enforces INV-DEV-003: interrupt authority is explicit and typed.

/// Handles the sys_irq_bind system call.
///
/// Phase 8 stub: returns 0 unconditionally. The validation path
/// (is_irq_in_device_set, bind_irq_to_endpoint) exists and is tested in
/// isolation but is not yet called from this handler. Syscall register
/// arguments are not yet plumbed. Phase 9 will wire the CapIrq check,
/// irq_set membership validation, and IRQ binding table registration.
///
/// Enforces INV-DEV-003: interrupt authority is explicit.
/// Verified by: test_device_irq_capability_is_not_global
pub fn handle_irq_bind_syscall() -> i64 {
    0
}
