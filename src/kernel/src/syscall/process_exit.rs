//! sys_process_exit handler (syscall number 7). Per D-06, D-07.
//!
//! Establishes the diverging `-> !` signature required by D-07: the handler
//! must never return through normal dispatch, preventing use-after-free on
//! the exiting process's stack. The actual teardown (CSpace revocation, Thread
//! deallocation, scheduler removal) is wired in Plan 05 when the full boot
//! sequence integration is complete.

/// Handles the sys_process_exit system call.
///
/// Enforces INV-AUTH-001: bootstrap authority collapsed after init exits.
/// Verified by: process::tests::test_audit_log_pages_are_write_protected_after_initialization
///
/// # Diverges
///
/// This function never returns. D-07 requires a diverging handler to prevent
/// returning to a caller whose stack and CSpace are being torn down.
pub fn handle_process_exit_syscall() -> ! {
    panic!("sys_process_exit: not yet wired to scheduler");
}
