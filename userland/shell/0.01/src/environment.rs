//! Mutable shell session state shared across builtin invocations.
//!
//! A REPL needs a little state that outlives any single command: who is
//! logged in (for `whoami` and the prompt), the current working directory
//! (for `pwd` / `cd`), and whether a builtin has requested the process
//! exit. [`ShellEnvironment`] holds exactly that and nothing more.
//!
//! There is no filesystem syscall in userland yet, so `cd` is a purely
//! in-memory path edit — it never validates that the target exists. The
//! path arithmetic still matches an interactive shell's feel: absolute
//! targets replace the path, `..` pops a component, a bare `cd` (or `~`)
//! returns home (`/`), and a relative target is appended.
//!
//! Fixed buffers, no allocation, no unsafe, no panics.

/// Maximum stored length of the logged-in username.
pub const USERNAME_CAPACITY: usize = 63;

/// Maximum stored length of the working-directory path.
pub const WORKING_DIRECTORY_CAPACITY: usize = 128;

/// ASCII forward slash — the path separator and the root directory.
const SLASH_BYTE: u8 = b'/';

/// The home / root directory the shell starts in and returns to.
const ROOT_DIRECTORY: &[u8] = b"/";

/// Session state carried between commands by the REPL.
pub struct ShellEnvironment {
    username_bytes: [u8; USERNAME_CAPACITY],
    username_length: usize,
    working_directory_bytes: [u8; WORKING_DIRECTORY_CAPACITY],
    working_directory_length: usize,
    exit_requested: bool,
}

impl ShellEnvironment {
    /// A fresh session: no username, working directory `/`, not exiting.
    pub fn new() -> Self {
        let mut environment = Self {
            username_bytes: [0; USERNAME_CAPACITY],
            username_length: 0,
            working_directory_bytes: [0; WORKING_DIRECTORY_CAPACITY],
            working_directory_length: 0,
            exit_requested: false,
        };
        environment.set_working_directory_to(ROOT_DIRECTORY);
        environment
    }

    /// Records the authenticated username (truncated to capacity).
    pub fn set_username(&mut self, username: &[u8]) {
        let copy_length = username.len().min(USERNAME_CAPACITY);
        self.username_bytes[..copy_length].copy_from_slice(&username[..copy_length]);
        self.username_length = copy_length;
    }

    /// Borrows the logged-in username (empty before login completes).
    pub fn username(&self) -> &[u8] {
        &self.username_bytes[..self.username_length]
    }

    /// Borrows the current working-directory path (always non-empty).
    pub fn working_directory(&self) -> &[u8] {
        &self.working_directory_bytes[..self.working_directory_length]
    }

    /// Returns true once a builtin (e.g. `exit`) has asked to terminate.
    pub fn exit_requested(&self) -> bool {
        self.exit_requested
    }

    /// Marks the session for termination; the REPL exits after the command.
    pub fn request_exit(&mut self) {
        self.exit_requested = true;
    }

    /// Applies a `cd` argument to the working directory (in-memory only).
    pub fn change_directory(&mut self, argument: &[u8]) {
        match classify_change_directory_argument(argument) {
            ChangeDirectoryAction::GoHome => self.set_working_directory_to(ROOT_DIRECTORY),
            ChangeDirectoryAction::StayPut => {}
            ChangeDirectoryAction::GoUp => self.pop_last_component(),
            ChangeDirectoryAction::SetAbsolute => self.set_working_directory_to(argument),
            ChangeDirectoryAction::AppendRelative => self.append_component(argument),
        }
    }

    fn set_working_directory_to(&mut self, path: &[u8]) {
        let trimmed = trim_trailing_slash(path);
        let source = if trimmed.is_empty() {
            ROOT_DIRECTORY
        } else {
            trimmed
        };
        let copy_length = source.len().min(WORKING_DIRECTORY_CAPACITY);
        self.working_directory_bytes[..copy_length].copy_from_slice(&source[..copy_length]);
        self.working_directory_length = copy_length;
    }

    fn pop_last_component(&mut self) {
        let last_slash = self.index_of_last_slash();
        match last_slash {
            Some(0) | None => self.set_working_directory_to(ROOT_DIRECTORY),
            Some(index) => self.working_directory_length = index,
        }
    }

    fn index_of_last_slash(&self) -> Option<usize> {
        self.working_directory()
            .iter()
            .rposition(|byte| *byte == SLASH_BYTE)
    }

    fn append_component(&mut self, component: &[u8]) {
        if self.working_directory_length > 1 {
            self.push_path_byte(SLASH_BYTE);
        }
        for byte in component {
            self.push_path_byte(*byte);
        }
    }

    fn push_path_byte(&mut self, byte: u8) {
        if self.working_directory_length >= WORKING_DIRECTORY_CAPACITY {
            return;
        }
        self.working_directory_bytes[self.working_directory_length] = byte;
        self.working_directory_length = self.working_directory_length.saturating_add(1);
    }
}

impl Default for ShellEnvironment {
    fn default() -> Self {
        Self::new()
    }
}

/// The `cd` argument kinds, classified before the path edit is applied.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum ChangeDirectoryAction {
    GoHome,
    StayPut,
    GoUp,
    SetAbsolute,
    AppendRelative,
}

fn classify_change_directory_argument(argument: &[u8]) -> ChangeDirectoryAction {
    match argument {
        b"" | b"~" => ChangeDirectoryAction::GoHome,
        b"." => ChangeDirectoryAction::StayPut,
        b".." => ChangeDirectoryAction::GoUp,
        _ if argument.first() == Some(&SLASH_BYTE) => ChangeDirectoryAction::SetAbsolute,
        _ => ChangeDirectoryAction::AppendRelative,
    }
}

fn trim_trailing_slash(path: &[u8]) -> &[u8] {
    if path.len() > 1 && path.last() == Some(&SLASH_BYTE) {
        return &path[..path.len().saturating_sub(1)];
    }
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_environment_starts_at_root() {
        let environment = ShellEnvironment::new();
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn new_environment_has_no_username() {
        let environment = ShellEnvironment::new();
        assert_eq!(environment.username(), b"");
    }

    #[test]
    fn new_environment_is_not_exiting() {
        let environment = ShellEnvironment::new();
        assert!(!environment.exit_requested());
    }

    #[test]
    fn set_username_is_readable() {
        let mut environment = ShellEnvironment::new();
        environment.set_username(b"root");
        assert_eq!(environment.username(), b"root");
    }

    #[test]
    fn set_username_truncates_to_capacity() {
        let mut environment = ShellEnvironment::new();
        let oversized = [b'x'; USERNAME_CAPACITY + 10];
        environment.set_username(&oversized);
        assert_eq!(environment.username().len(), USERNAME_CAPACITY);
    }

    #[test]
    fn request_exit_sets_the_flag() {
        let mut environment = ShellEnvironment::new();
        environment.request_exit();
        assert!(environment.exit_requested());
    }

    #[test]
    fn cd_absolute_path_replaces_working_directory() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/etc");
        assert_eq!(environment.working_directory(), b"/etc");
    }

    #[test]
    fn cd_absolute_path_trims_trailing_slash() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/etc/");
        assert_eq!(environment.working_directory(), b"/etc");
    }

    #[test]
    fn cd_with_no_argument_returns_home() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/etc");
        environment.change_directory(b"");
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn cd_tilde_returns_home() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/etc");
        environment.change_directory(b"~");
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn cd_dot_leaves_working_directory_unchanged() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/var/log");
        environment.change_directory(b".");
        assert_eq!(environment.working_directory(), b"/var/log");
    }

    #[test]
    fn cd_dotdot_pops_one_component() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/var/log");
        environment.change_directory(b"..");
        assert_eq!(environment.working_directory(), b"/var");
    }

    #[test]
    fn cd_dotdot_at_root_stays_at_root() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"..");
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn cd_dotdot_from_first_level_returns_to_root() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/etc");
        environment.change_directory(b"..");
        assert_eq!(environment.working_directory(), b"/");
    }

    #[test]
    fn cd_relative_from_root_appends_without_double_slash() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"home");
        assert_eq!(environment.working_directory(), b"/home");
    }

    #[test]
    fn cd_relative_from_subdirectory_appends_with_separator() {
        let mut environment = ShellEnvironment::new();
        environment.change_directory(b"/home");
        environment.change_directory(b"jbrahy");
        assert_eq!(environment.working_directory(), b"/home/jbrahy");
    }
}
