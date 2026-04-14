//! sys_irq_bind handler for Phase 8 device isolation.
//!
//! Binds a hardware IRQ line to an IPC endpoint. When the IRQ fires,
//! the kernel delivers an IPC message to the bound endpoint, allowing the
//! device server to receive interrupt notifications via ipc_receive.
//!
//! Enforces INV-DEV-003: interrupt authority is explicit and typed.

/// Handles the sys_irq_bind system call.
///
/// Returns -1 (fail closed) until Phase 9 plumbs register arguments and the
/// process table required to call is_irq_in_device_set and
/// bind_irq_to_endpoint. Failing closed prevents any IRQ binding from
/// succeeding before irq_set membership is validated.
///
/// Mitigates T-DEV-012: IRQ not in device's irq_set cannot be bound.
/// Enforces INV-DEV-003: interrupt authority is explicit and typed.
/// Verified by: test_device_irq_capability_is_not_global
pub fn handle_irq_bind_syscall() -> i64 {
    -1
}
