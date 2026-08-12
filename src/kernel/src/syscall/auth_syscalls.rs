//! Authentication syscalls: login verification and password change.
//!
//! Verification happens in the kernel against the persistent credential store,
//! so a compromised shell cannot bypass login or read credentials. The shell
//! passes the username and password by user virtual address + length; the
//! kernel reads them with bounded `copy_from_user`.
//!
//! sys_auth_login ABI (message registers, per the syscall entry stub):
//!   r8  (MSG0) = username user-VA
//!   r9  (MSG1) = (username_len << 32) | password_len
//!   r10 (MSG2) = password user-VA
//! Returns: 0 = accepted, 1 = accepted-but-must-change, -1 = rejected.
//!
//! sys_auth_set_password ABI (requires proof of authority — the CURRENT
//! password — so a process cannot rotate another user's, or its own, password
//! without knowing it; prevents privilege escalation):
//!   r8  (MSG0) = username user-VA
//!   r9  (MSG1) = current-password user-VA
//!   r10 (MSG2) = new-password user-VA
//!   rdx (TIMEOUT slot) = (username_len << 16) | (current_len << 8) | new_len
//! Returns 0 on success, -1 if the current password is wrong or on any failure.
//!
//! Allowlist: `src/kernel/src/syscall/` — reads user memory via copy_from_user.

use core::sync::atomic::Ordering;

use crate::boot::credential_store::{change_password, verify_login};
use crate::syscall::kernel_syscall_registers::{
    KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE, KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE,
    KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE, KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE,
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
    let (username, username_length, password, password_length) = match read_credential_arguments() {
        Some(arguments) => arguments,
        None => return RESULT_REJECTED,
    };
    match verify_login(&username[..username_length], &password[..password_length]) {
        Some((_user, true)) => RESULT_ACCEPTED_MUST_CHANGE,
        Some((_user, false)) => RESULT_ACCEPTED,
        None => RESULT_REJECTED,
    }
}

/// Handles sys_auth_set_password: rotates the password for the named user, but
/// ONLY after proving authority by verifying the supplied CURRENT password.
/// This prevents any process from rewriting a credential it cannot already
/// authenticate as (privilege escalation).
pub fn handle_auth_set_password_syscall() -> i64 {
    let arguments = match read_password_change_arguments() {
        Some(arguments) => arguments,
        None => return RESULT_FAILURE,
    };
    let username = &arguments.username[..arguments.username_length];
    let current_password = &arguments.current_password[..arguments.current_password_length];
    let new_password = &arguments.new_password[..arguments.new_password_length];

    // Proof of authority: the caller must know the current password. verify_login
    // both checks it and resolves which user is being changed — so the caller can
    // only ever rotate the exact account it just authenticated.
    let user = match verify_login(username, current_password) {
        Some((user, _must_change)) => user,
        None => return RESULT_FAILURE,
    };
    if change_password(user, new_password) {
        RESULT_SUCCESS
    } else {
        RESULT_FAILURE
    }
}

/// Username/current/new buffers and their lengths for a password change.
struct PasswordChangeArguments {
    username: [u8; 64],
    username_length: usize,
    current_password: [u8; 64],
    current_password_length: usize,
    new_password: [u8; 64],
    new_password_length: usize,
}

/// Reads the three credential buffers for sys_auth_set_password per the ABI.
fn read_password_change_arguments() -> Option<PasswordChangeArguments> {
    let username_virtual = KERNEL_SYSCALL_MESSAGE_REGISTER_ZERO_VALUE.load(Ordering::Relaxed);
    let current_virtual = KERNEL_SYSCALL_MESSAGE_REGISTER_ONE_VALUE.load(Ordering::Relaxed);
    let new_virtual = KERNEL_SYSCALL_MESSAGE_REGISTER_TWO_VALUE.load(Ordering::Relaxed);
    let packed_lengths = KERNEL_SYSCALL_TIMEOUT_TICKS_VALUE.load(Ordering::Relaxed);

    let username_length = ((packed_lengths >> 16) & 0xFF) as usize;
    let current_password_length = ((packed_lengths >> 8) & 0xFF) as usize;
    let new_password_length = (packed_lengths & 0xFF) as usize;
    if username_length > MAXIMUM_CREDENTIAL_LENGTH
        || current_password_length > MAXIMUM_CREDENTIAL_LENGTH
        || new_password_length > MAXIMUM_CREDENTIAL_LENGTH
    {
        return None;
    }

    let mut username = [0u8; 64];
    let mut current_password = [0u8; 64];
    let mut new_password = [0u8; 64];
    copy_from_user(username_virtual, username_length, &mut username)?;
    copy_from_user(
        current_virtual,
        current_password_length,
        &mut current_password,
    )?;
    copy_from_user(new_virtual, new_password_length, &mut new_password)?;
    Some(PasswordChangeArguments {
        username,
        username_length,
        current_password,
        current_password_length,
        new_password,
        new_password_length,
    })
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
