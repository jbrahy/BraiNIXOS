//! zsh-flavored prompt rendering.
//!
//! zsh's defining visual is its prompt sigil: `%` for an ordinary user and
//! `#` for root (zsh's `%#`). This module renders a prompt in that spirit —
//! `<user>@brainix <cwd> %` (or `… #` for root) — so the console reads as a
//! zsh session and reflects the current working directory that `cd` updates.
//!
//! Pure and host-testable: output goes through a [`ByteSink`]. No
//! allocation, no unsafe; the renderer stays within the shell's
//! six-executable-line budget.

use crate::display::{write_byte_slice, ByteSink};

/// Host label shown between the username and the working directory.
const HOST_LABEL: &[u8] = b"@brainix ";

/// The root account, which gets the `#` sigil instead of `%`.
const ROOT_USERNAME: &[u8] = b"root";

/// Sigil written for the root account.
const ROOT_SIGIL_BYTE: u8 = b'#';

/// Sigil written for every non-root account (zsh's default `%`).
const USER_SIGIL_BYTE: u8 = b'%';

/// ASCII space.
const SPACE_BYTE: u8 = 0x20;

/// Writes `<username>@brainix <working_directory> <sigil> ` to `sink`.
///
/// The trailing sigil is `#` for `root` and `%` for any other user, after
/// which a single space separates the prompt from typed input.
pub fn render_prompt<S: ByteSink>(sink: &mut S, username: &[u8], working_directory: &[u8]) {
    write_byte_slice(sink, username);
    write_byte_slice(sink, HOST_LABEL);
    write_byte_slice(sink, working_directory);
    sink.write_byte(SPACE_BYTE);
    sink.write_byte(prompt_sigil_for(username));
    sink.write_byte(SPACE_BYTE);
}

fn prompt_sigil_for(username: &[u8]) -> u8 {
    if username == ROOT_USERNAME {
        return ROOT_SIGIL_BYTE;
    }
    USER_SIGIL_BYTE
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CapturingByteSink {
        captured: [u8; 256],
        length: usize,
    }

    impl CapturingByteSink {
        fn new() -> Self {
            Self {
                captured: [0u8; 256],
                length: 0,
            }
        }

        fn as_slice(&self) -> &[u8] {
            &self.captured[..self.length]
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

    fn render(username: &[u8], working_directory: &[u8]) -> CapturingByteSink {
        let mut sink = CapturingByteSink::new();
        render_prompt(&mut sink, username, working_directory);
        sink
    }

    #[test]
    fn non_root_user_gets_percent_sigil() {
        let sink = render(b"jbrahy", b"/");
        assert_eq!(sink.as_slice(), b"jbrahy@brainix / % ");
    }

    #[test]
    fn root_user_gets_hash_sigil() {
        let sink = render(b"root", b"/");
        assert_eq!(sink.as_slice(), b"root@brainix / # ");
    }

    #[test]
    fn prompt_includes_the_working_directory() {
        let sink = render(b"jbrahy", b"/var/log");
        assert_eq!(sink.as_slice(), b"jbrahy@brainix /var/log % ");
    }
}
