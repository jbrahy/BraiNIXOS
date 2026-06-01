//! SSH protocol version (identification string) exchange — RFC 4253 §4.2.
//!
//! Each side sends `SSH-protoversion-softwareversion ... CR LF`. We require the
//! peer to speak SSH 2.0.

/// The server's identification string (CR LF terminated), sent on connect.
pub const SERVER_IDENTIFICATION: &[u8] = b"SSH-2.0-BraiNIX_0.1\r\n";

/// The server identification without the trailing CR LF — the form hashed into
/// the SSH exchange hash (V_S).
pub fn server_identification_without_crlf() -> &'static [u8] {
    b"SSH-2.0-BraiNIX_0.1"
}

/// True if `client_identification` (CR/LF already stripped) announces SSH 2.0.
pub fn client_version_is_supported(client_identification: &[u8]) -> bool {
    client_identification.starts_with(b"SSH-2.0-")
}

#[cfg(test)]
mod tests {
    use super::{client_version_is_supported, SERVER_IDENTIFICATION};

    #[test]
    fn test_server_identification_format() {
        assert!(SERVER_IDENTIFICATION.starts_with(b"SSH-2.0-"));
        assert!(SERVER_IDENTIFICATION.ends_with(b"\r\n"));
    }

    #[test]
    fn test_version_support() {
        assert!(client_version_is_supported(b"SSH-2.0-OpenSSH_9.6"));
        assert!(!client_version_is_supported(b"SSH-1.99-x"));
        assert!(!client_version_is_supported(b"garbage"));
    }
}
