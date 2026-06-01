//! Authentication syscalls: login verification and password change.
//!
//! Verification happens in the kernel against the persistent credential store,
//! so a compromised shell cannot bypass login or read credentials. The shell
//! passes the username and password by user virtual address + length; the
//! kernel reads them with bounded `copy_from_user`.
//!
//! ABI (message registers, per the syscall entry stub):
//!   r8  (MSG0) = username user-VA
//!   r9  (MSG1) = (username_len << 32) | password_len
//!   r10 (MSG2) = password user-VA
//!
//! sys_auth_login returns: 0 = accepted, 1 = accepted-but-must-change-password,
//! -1 = rejected. sys_auth_set_password returns 0 on success, -1 on failure.
//!
//! Allowlist: `src/kernel/src/syscall/` — reads user memory via copy_from_user.

use core::sync::atomic::Ordering;

use crate::auth::UserIdentity;
use crate::boot::credential_store::{change_password, verify_login};
use crate::syscall::kernel_syscall_registers::{
    KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE,
    KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE,
};
use crate::syscall::user_memory::copy_from_user;

/// Maximum accepted credential length (matches the shell's line limit).
const MAXIMUM_CREDENTIAL_LENGTH: usize = 63;

const RESULT_REJECTED: i64 = -1;
const RESULT_ACCEPTED: i64 = 0;
const RESULT_ACCEPTED_MUST_CHANGE: i64 = 1;
const RESULT_FAILURE: i64 = -1;
const RESULT_SUCCESS: i64 = 0;

/// Handles sys_auth_login: verifies the username/password from user memory.
pub fn handle_auth_login_syscall() -> i64 {
    let (username, username_length, password, password_length) =
        match read_credential_arguments() {
            Some(arguments) => arguments,
            None => return RESULT_REJECTED,
        };
    match verify_login(
        &username[..username_length],
        &password[..password_length],
    ) {
        Some((_user, true)) => RESULT_ACCEPTED_MUST_CHANGE,
        Some((_user, false)) => RESULT_ACCEPTED,
        None => RESULT_REJECTED,
    }
}

/// Handles sys_auth_set_password: rotates the password for the named user.
pub fn handle_auth_set_password_syscall() -> i64 {
    let (username, username_length, new_password, new_password_length) =
        match read_credential_arguments() {
            Some(arguments) => arguments,
            None => return RESULT_FAILURE,
        };
    let user = match UserIdentity::from_login_name(&username[..username_length]) {
        Some(user) => user,
        None => return RESULT_FAILURE,
    };
    if change_password(user, &new_password[..new_password_length]) {
        RESULT_SUCCESS
    } else {
        RESULT_FAILURE
    }
}

/// Reads the username and password byte buffers from user memory per the ABI.
/// Returns (username, username_len, password, password_len), all bounded.
fn read_credential_arguments() -> Option<([u8; 64], usize, [u8; 64], usize)> {
    let username_virtual = KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.load(Ordering::Relaxed);
    let packed_lengths = KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE.load(Ordering::Relaxed);
    let password_virtual = KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE.load(Ordering::Relaxed);

    let username_length = (packed_lengths >> 32) as usize;
    let password_length = (packed_lengths & 0xFFFF_FFFF) as usize;
    if username_length > MAXIMUM_CREDENTIAL_LENGTH || password_length > MAXIMUM_CREDENTIAL_LENGTH {
        return None;
    }

    let mut username = [0u8; 64];
    let mut password = [0u8; 64];
    copy_from_user(username_virtual, username_length, &mut username)?;
    copy_from_user(password_virtual, password_length, &mut password)?;
    Some((username, username_length, password, password_length))
}
