//! Pre-REPL login gate: authenticate a user before the shell starts, and
//! force a password change when the account still carries its initial
//! password.
//!
//! The shell performs **no** credential checking itself — it only collects
//! input and renders prompts. Verification and password changes are delegated
//! to a [`CredentialAuthority`], which in the running system is backed by
//! kernel syscalls (the authentication TCB). Tests inject a mock authority.
//! This keeps authority for "act as this user" inside the kernel, not in the
//! untrusted shell process (INV-AUTH-001).
//!
//! The flow is line-oriented: the caller assembles each line (terminated by
//! Enter) and calls [`LoginFlow::submit_line`]. Password lines are never
//! echoed.

use crate::display::{write_byte_slice, write_carriage_return_line_feed, ByteSink};

/// Maximum accepted length of a username or password line. Longer input is
/// rejected rather than truncated, so a too-long password can never alias a
/// shorter accepted one.
pub const MAXIMUM_CREDENTIAL_LINE_LENGTH: usize = 63;

/// Result of checking a username/password pair against the authority.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CredentialCheck {
    /// The username/password pair is not valid.
    Rejected,
    /// Valid, but the password must be changed before the account is usable.
    AcceptedMustChange,
    /// Valid and ready to use.
    Accepted,
}

/// The authority that actually verifies and rotates credentials. Backed by
/// kernel syscalls in the shell binary; mocked in tests.
pub trait CredentialAuthority {
    /// Checks `password` for `username`.
    fn check_password(&self, username: &[u8], password: &[u8]) -> CredentialCheck;
    /// Sets a new password for `username`, clearing the force-change flag.
    /// Returns false if the authority refuses (e.g. unknown user).
    fn set_password(&mut self, username: &[u8], new_password: &[u8]) -> bool;
}

/// Which line the flow is currently waiting for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum LoginStage {
    AwaitingUsername,
    AwaitingPassword,
    AwaitingNewPassword,
    AwaitingNewPasswordConfirmation,
}

/// Outcome of submitting one line to the flow.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum LoginProgress {
    /// More input is needed; the next prompt has been written.
    NeedMoreInput,
    /// Authentication complete; the shell REPL may start.
    Authenticated,
}

/// A fixed-capacity line buffer used to hold a username or a candidate new
/// password between successive submitted lines (no heap in `no_std`).
#[derive(Copy, Clone)]
struct StoredLine {
    bytes: [u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
    length: usize,
}

impl StoredLine {
    fn new() -> Self {
        Self {
            bytes: [0u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
            length: 0,
        }
    }

    fn store(&mut self, source: &[u8]) {
        self.length = source.len().min(MAXIMUM_CREDENTIAL_LINE_LENGTH);
        self.bytes[..self.length].copy_from_slice(&source[..self.length]);
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

/// The login state machine. Holds the stage, the username being authenticated,
/// and the first new-password entry awaiting confirmation.
pub struct LoginFlow {
    stage: LoginStage,
    username: StoredLine,
    pending_new_password: StoredLine,
}

impl LoginFlow {
    /// Creates a flow waiting for a username and writes the first prompt.
    pub fn start<S: ByteSink>(sink: &mut S) -> Self {
        write_byte_slice(sink, USERNAME_PROMPT);
        Self {
            stage: LoginStage::AwaitingUsername,
            username: StoredLine::new(),
            pending_new_password: StoredLine::new(),
        }
    }

    /// Submits one completed input line. Returns whether login is complete.
    pub fn submit_line<S: ByteSink, A: CredentialAuthority>(
        &mut self,
        line: &[u8],
        authority: &mut A,
        sink: &mut S,
    ) -> LoginProgress {
        match self.stage {
            LoginStage::AwaitingUsername => self.handle_username(line, sink),
            LoginStage::AwaitingPassword => self.handle_password(line, authority, sink),
            LoginStage::AwaitingNewPassword => self.handle_new_password(line, sink),
            LoginStage::AwaitingNewPasswordConfirmation => {
                self.handle_new_password_confirmation(line, authority, sink)
            }
        }
    }

    fn handle_username<S: ByteSink>(&mut self, line: &[u8], sink: &mut S) -> LoginProgress {
        if line.is_empty() || line.len() > MAXIMUM_CREDENTIAL_LINE_LENGTH {
            return self.restart_at_username(sink);
        }
        self.username.store(line);
        self.stage = LoginStage::AwaitingPassword;
        write_byte_slice(sink, PASSWORD_PROMPT);
        LoginProgress::NeedMoreInput
    }

    fn handle_password<S: ByteSink, A: CredentialAuthority>(
        &mut self,
        line: &[u8],
        authority: &mut A,
        sink: &mut S,
    ) -> LoginProgress {
        write_carriage_return_line_feed(sink);
        match authority.check_password(self.username.as_slice(), line) {
            CredentialCheck::Accepted => self.finish_authenticated(sink),
            CredentialCheck::AcceptedMustChange => self.begin_forced_change(sink),
            CredentialCheck::Rejected => self.reject_and_restart(sink),
        }
    }

    fn handle_new_password<S: ByteSink>(&mut self, line: &[u8], sink: &mut S) -> LoginProgress {
        write_carriage_return_line_feed(sink);
        if line.is_empty() || line.len() > MAXIMUM_CREDENTIAL_LINE_LENGTH {
            write_byte_slice(sink, NEW_PASSWORD_PROMPT);
            return LoginProgress::NeedMoreInput;
        }
        self.pending_new_password.store(line);
        self.stage = LoginStage::AwaitingNewPasswordConfirmation;
        write_byte_slice(sink, CONFIRM_NEW_PASSWORD_PROMPT);
        LoginProgress::NeedMoreInput
    }

    fn handle_new_password_confirmation<S: ByteSink, A: CredentialAuthority>(
        &mut self,
        line: &[u8],
        authority: &mut A,
        sink: &mut S,
    ) -> LoginProgress {
        write_carriage_return_line_feed(sink);
        if line != self.pending_new_password.as_slice() {
            write_byte_slice(sink, PASSWORD_MISMATCH_MESSAGE);
            self.stage = LoginStage::AwaitingNewPassword;
            write_byte_slice(sink, NEW_PASSWORD_PROMPT);
            return LoginProgress::NeedMoreInput;
        }
        authority.set_password(self.username.as_slice(), line);
        self.finish_authenticated(sink)
    }

    fn begin_forced_change<S: ByteSink>(&mut self, sink: &mut S) -> LoginProgress {
        write_byte_slice(sink, MUST_CHANGE_MESSAGE);
        self.stage = LoginStage::AwaitingNewPassword;
        write_byte_slice(sink, NEW_PASSWORD_PROMPT);
        LoginProgress::NeedMoreInput
    }

    fn finish_authenticated<S: ByteSink>(&mut self, sink: &mut S) -> LoginProgress {
        write_byte_slice(sink, WELCOME_PREFIX);
        write_byte_slice(sink, self.username.as_slice());
        write_carriage_return_line_feed(sink);
        LoginProgress::Authenticated
    }

    fn reject_and_restart<S: ByteSink>(&mut self, sink: &mut S) -> LoginProgress {
        write_byte_slice(sink, LOGIN_INCORRECT_MESSAGE);
        self.restart_at_username(sink)
    }

    fn restart_at_username<S: ByteSink>(&mut self, sink: &mut S) -> LoginProgress {
        self.stage = LoginStage::AwaitingUsername;
        self.username = StoredLine::new();
        self.pending_new_password = StoredLine::new();
        write_byte_slice(sink, USERNAME_PROMPT);
        LoginProgress::NeedMoreInput
    }

    /// True while the flow is collecting a password (so the caller can suppress
    /// echo). Username entry echoes normally; all password entry does not.
    pub fn is_collecting_secret(&self) -> bool {
        !matches!(self.stage, LoginStage::AwaitingUsername)
    }
}

const USERNAME_PROMPT: &[u8] = b"login: ";
const PASSWORD_PROMPT: &[u8] = b"password: ";
const NEW_PASSWORD_PROMPT: &[u8] = b"new password: ";
const CONFIRM_NEW_PASSWORD_PROMPT: &[u8] = b"retype new password: ";
const MUST_CHANGE_MESSAGE: &[u8] = b"password change required\r\n";
const PASSWORD_MISMATCH_MESSAGE: &[u8] = b"passwords do not match\r\n";
const LOGIN_INCORRECT_MESSAGE: &[u8] = b"login incorrect\r\n";
const WELCOME_PREFIX: &[u8] = b"welcome, ";

#[cfg(test)]
mod tests {
    use super::{
        CredentialAuthority, CredentialCheck, LoginFlow, LoginProgress,
        MAXIMUM_CREDENTIAL_LINE_LENGTH,
    };
    use crate::display::ByteSink;

    /// Mock authority: "root"/"jbrahy" accept "brainxos" with must-change set;
    /// after set_password the new password is accepted without must-change.
    struct MockAuthority {
        root_password: [u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
        root_password_length: usize,
        root_must_change: bool,
    }

    impl MockAuthority {
        fn new() -> Self {
            let mut authority = Self {
                root_password: [0u8; MAXIMUM_CREDENTIAL_LINE_LENGTH],
                root_password_length: 0,
                root_must_change: true,
            };
            authority.store_root_password(b"brainxos");
            authority
        }

        fn store_root_password(&mut self, password: &[u8]) {
            self.root_password_length = password.len();
            self.root_password[..password.len()].copy_from_slice(password);
        }

        fn root_password_slice(&self) -> &[u8] {
            &self.root_password[..self.root_password_length]
        }
    }

    impl CredentialAuthority for MockAuthority {
        fn check_password(&self, username: &[u8], password: &[u8]) -> CredentialCheck {
            if username != b"root" || password != self.root_password_slice() {
                return CredentialCheck::Rejected;
            }
            if self.root_must_change {
                CredentialCheck::AcceptedMustChange
            } else {
                CredentialCheck::Accepted
            }
        }

        fn set_password(&mut self, username: &[u8], new_password: &[u8]) -> bool {
            if username != b"root" {
                return false;
            }
            self.store_root_password(new_password);
            self.root_must_change = false;
            true
        }
    }

    struct CapturingByteSink {
        captured: [u8; 512],
        length: usize,
    }

    impl CapturingByteSink {
        fn new() -> Self {
            Self {
                captured: [0u8; 512],
                length: 0,
            }
        }

        fn contains(&self, needle: &[u8]) -> bool {
            self.captured[..self.length]
                .windows(needle.len())
                .any(|window| window == needle)
        }
    }

    impl ByteSink for CapturingByteSink {
        fn write_byte(&mut self, value: u8) {
            if self.length < self.captured.len() {
                self.captured[self.length] = value;
                self.length += 1;
            }
        }
    }

    #[test]
    fn test_forced_change_then_login_succeeds() {
        let mut authority = MockAuthority::new();
        let mut sink = CapturingByteSink::new();
        let mut flow = LoginFlow::start(&mut sink);
        assert_eq!(
            flow.submit_line(b"root", &mut authority, &mut sink),
            LoginProgress::NeedMoreInput
        );
        assert_eq!(
            flow.submit_line(b"brainxos", &mut authority, &mut sink),
            LoginProgress::NeedMoreInput
        );
        assert!(sink.contains(b"password change required"));
        assert_eq!(
            flow.submit_line(b"newsecret", &mut authority, &mut sink),
            LoginProgress::NeedMoreInput
        );
        assert_eq!(
            flow.submit_line(b"newsecret", &mut authority, &mut sink),
            LoginProgress::Authenticated
        );
        assert!(sink.contains(b"welcome, root"));
        assert!(!authority.root_must_change);
    }

    #[test]
    fn test_wrong_password_is_rejected_and_restarts() {
        let mut authority = MockAuthority::new();
        let mut sink = CapturingByteSink::new();
        let mut flow = LoginFlow::start(&mut sink);
        flow.submit_line(b"root", &mut authority, &mut sink);
        let progress = flow.submit_line(b"wrong", &mut authority, &mut sink);
        assert_eq!(progress, LoginProgress::NeedMoreInput);
        assert!(sink.contains(b"login incorrect"));
    }

    #[test]
    fn test_unknown_user_is_rejected() {
        let mut authority = MockAuthority::new();
        let mut sink = CapturingByteSink::new();
        let mut flow = LoginFlow::start(&mut sink);
        flow.submit_line(b"admin", &mut authority, &mut sink);
        let progress = flow.submit_line(b"brainxos", &mut authority, &mut sink);
        assert_eq!(progress, LoginProgress::NeedMoreInput);
        assert!(sink.contains(b"login incorrect"));
    }

    #[test]
    fn test_mismatched_confirmation_reprompts() {
        let mut authority = MockAuthority::new();
        let mut sink = CapturingByteSink::new();
        let mut flow = LoginFlow::start(&mut sink);
        flow.submit_line(b"root", &mut authority, &mut sink);
        flow.submit_line(b"brainxos", &mut authority, &mut sink);
        flow.submit_line(b"newsecret", &mut authority, &mut sink);
        let progress = flow.submit_line(b"different", &mut authority, &mut sink);
        assert_eq!(progress, LoginProgress::NeedMoreInput);
        assert!(sink.contains(b"passwords do not match"));
        assert!(authority.root_must_change);
    }

    #[test]
    fn test_password_entry_is_marked_secret() {
        let mut sink = CapturingByteSink::new();
        let mut authority = MockAuthority::new();
        let mut flow = LoginFlow::start(&mut sink);
        assert!(!flow.is_collecting_secret());
        flow.submit_line(b"root", &mut authority, &mut sink);
        assert!(flow.is_collecting_secret());
    }
}
