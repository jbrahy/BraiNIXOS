//! BraiNIX userspace shell binary entry stub.
//!
//! This binary is loaded by the kernel's ELF loader at
//! SERVER_CODE_BASE_VIRTUAL_ADDRESS (0x0000_0000_0040_0000) per libsyscall's
//! server VA layout. `_start` is the ELF entry point; it calls into
//! `brainix_shell::shell_main`, which runs the interactive REPL.
//!
//! Unsafe is permitted in this file per `docs/security/UNSAFE_CODE_POLICY.md`
//! (the `#[no_mangle] unsafe extern "C"` attribute on `_start` falls under the
//! `userland/shell/0.01/src/main.rs` allowlist entry). No other unsafe blocks
//! or operations exist in this file; the panic handler is purely safe.
#![no_std]
#![no_main]
#![allow(unsafe_code)]

use core::panic::PanicInfo;

use brainix_libsyscall::syscall_process_exit;

/// ELF entry point. Linked at SERVER_CODE_BASE_VIRTUAL_ADDRESS.
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    brainix_shell::shell_main()
}

/// Panic handler: exits the shell process via syscall_process_exit.
///
/// The kernel sees the exit and reclaims the process's thread slot + CSpace
/// per Phase 10's process-teardown logic. Future work may add audit-log
/// entries describing panic location; today the process just exits quietly.
#[panic_handler]
fn on_shell_panic(_info: &PanicInfo) -> ! {
    syscall_process_exit()
}
