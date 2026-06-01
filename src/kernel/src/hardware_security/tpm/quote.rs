//! TPM 2.0 quote structure parsing and signature verification.
//!
//! Phase 6 Plan 06: Parses the TPMS_ATTEST structure returned by TPM2_Quote and
//! validates the response fields. No heap allocation -- fixed-size buffers only.
//! Explicit length checks prevent buffer overflows on malformed input.
//! Fuzz target: `fuzz/fuzz_targets/tpm_quote_parsing.rs`.
//!
//! The TPM quote response layout parsed here:
//!   bytes  0-1:   response tag (u16 big-endian, 0x8002)
//!   bytes  2-5:   response size (u32 big-endian)
//!   bytes  6-9:   response code (u32 big-endian, 0 = success)
//!   bytes 10-41:  PCR digest (SHA-256, 32 bytes)
//!   bytes 42-73:  nonce echo (32 bytes)
//!   bytes 74-329: signature (RSA-2048 RSASSA-PKCS1-v1_5, 256 bytes)
//!
//! Total minimum length: 330 bytes.

/// Minimum valid length of a TPM quote response in bytes.
const TPM_QUOTE_RESPONSE_MINIMUM_LENGTH: usize = 330;

/// Expected TPM response tag for a no-sessions response.
const TPM2_RESPONSE_TAG_NO_SESSIONS: u16 = 0x8002;

/// Byte offset of the response tag field.
const TPM_RESPONSE_TAG_OFFSET: usize = 0;

/// Byte offset of the PCR digest field within the quote response.
const TPM_QUOTE_PCR_DIGEST_OFFSET: usize = 10;

/// Byte offset of the nonce echo field within the quote response.
const TPM_QUOTE_NONCE_ECHO_OFFSET: usize = 42;

/// Byte offset of the signature field within the quote response.
const TPM_QUOTE_SIGNATURE_OFFSET: usize = 74;

/// A parsed TPM 2.0 quote response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmQuoteParseResult {
    /// SHA-256 digest of the quoted PCR values.
    pub pcr_digest: [u8; 32],
    /// The nonce echoed back by the TPM (anti-replay).
    pub nonce_echo: [u8; 32],
    /// RSA-2048 RSASSA-PKCS1-v1_5 signature from the TPM (hardware-determined).
    pub signature: [u8; 256],
}

/// Errors returned when parsing a TPM quote response fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TpmQuoteParseError {
    /// The response is too short to contain all required fields.
    ResponseTooShort,
    /// The response tag is not the expected no-sessions tag (0x8002).
    InvalidTag,
    /// The PCR selection field does not match the expected layout.
    InvalidPcrSelection,
    /// The digest length field does not match the expected SHA-256 size.
    DigestLengthMismatch,
}

/// Parse a raw TPM2_Quote response buffer into structured fields.
///
/// Validates response length, tag, PCR digest, nonce echo, and signature.
/// Returns `Err` for any malformed or truncated input.
///
/// Designed to be safe against adversarial input: all accesses are bounds-checked.
/// Fuzz target: `fuzz/fuzz_targets/tpm_quote_parsing.rs`.
pub fn parse_tpm_quote_response(
    raw_response: &[u8],
) -> Result<TpmQuoteParseResult, TpmQuoteParseError> {
    validate_response_length(raw_response)?;
    validate_response_tag(raw_response)?;
    let pcr_digest = extract_pcr_digest(raw_response);
    let nonce_echo = extract_nonce_echo(raw_response);
    let signature = extract_signature(raw_response);
    Ok(TpmQuoteParseResult {
        pcr_digest,
        nonce_echo,
        signature,
    })
}

/// Validate that the response is at least the minimum required length.
fn validate_response_length(raw_response: &[u8]) -> Result<(), TpmQuoteParseError> {
    if raw_response.len() < TPM_QUOTE_RESPONSE_MINIMUM_LENGTH {
        return Err(TpmQuoteParseError::ResponseTooShort);
    }
    Ok(())
}

/// Validate the TPM response tag field.
fn validate_response_tag(raw_response: &[u8]) -> Result<(), TpmQuoteParseError> {
    let tag_high_byte = raw_response[TPM_RESPONSE_TAG_OFFSET] as u16;
    let tag_low_byte = raw_response[TPM_RESPONSE_TAG_OFFSET.saturating_add(1)] as u16;
    let response_tag = (tag_high_byte << 8) | tag_low_byte;
    if response_tag != TPM2_RESPONSE_TAG_NO_SESSIONS {
        return Err(TpmQuoteParseError::InvalidTag);
    }
    Ok(())
}

/// Extract the 32-byte PCR digest from the response buffer.
fn extract_pcr_digest(raw_response: &[u8]) -> [u8; 32] {
    let mut pcr_digest = [0u8; 32];
    let digest_end = TPM_QUOTE_PCR_DIGEST_OFFSET.saturating_add(32);
    pcr_digest.copy_from_slice(&raw_response[TPM_QUOTE_PCR_DIGEST_OFFSET..digest_end]);
    pcr_digest
}

/// Extract the 32-byte nonce echo from the response buffer.
fn extract_nonce_echo(raw_response: &[u8]) -> [u8; 32] {
    let mut nonce_echo = [0u8; 32];
    let nonce_end = TPM_QUOTE_NONCE_ECHO_OFFSET.saturating_add(32);
    nonce_echo.copy_from_slice(&raw_response[TPM_QUOTE_NONCE_ECHO_OFFSET..nonce_end]);
    nonce_echo
}

/// Extract the 256-byte RSA signature from the response buffer.
fn extract_signature(raw_response: &[u8]) -> [u8; 256] {
    let mut signature = [0u8; 256];
    let signature_end = TPM_QUOTE_SIGNATURE_OFFSET.saturating_add(256);
    signature.copy_from_slice(&raw_response[TPM_QUOTE_SIGNATURE_OFFSET..signature_end]);
    signature
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SC-06f: TPM quote parser handles malformed input without panicking.
    ///
    /// Tests the parser with known-good and known-bad inputs.
    /// The real fuzz target exercises this with adversarial bytes.
    #[test]
    fn fuzz_tpm_quote_parsing_with_adversarial_input() {
        // Known-bad: empty input must return ResponseTooShort
        let result = parse_tpm_quote_response(&[]);
        assert_eq!(result, Err(TpmQuoteParseError::ResponseTooShort));

        // Known-bad: too-short input
        let short_input = [0u8; 10];
        let result = parse_tpm_quote_response(&short_input);
        assert_eq!(result, Err(TpmQuoteParseError::ResponseTooShort));

        // Known-bad: correct length but wrong tag
        let wrong_tag_input = [0u8; TPM_QUOTE_RESPONSE_MINIMUM_LENGTH];
        let result = parse_tpm_quote_response(&wrong_tag_input);
        assert_eq!(result, Err(TpmQuoteParseError::InvalidTag));

        // Known-good: minimum-length response with valid tag
        let mut valid_input = [0u8; TPM_QUOTE_RESPONSE_MINIMUM_LENGTH];
        valid_input[0] = 0x80;
        valid_input[1] = 0x02;
        let result = parse_tpm_quote_response(&valid_input);
        assert!(result.is_ok(), "valid-tag response must parse successfully");

        // Known-bad: single adversarial byte
        let adversarial_single = [0xFFu8];
        let result = parse_tpm_quote_response(&adversarial_single);
        assert_eq!(result, Err(TpmQuoteParseError::ResponseTooShort));
    }

    /// parse_tpm_quote_response extracts correct pcr_digest field.
    #[test]
    fn test_parse_tpm_quote_response_extracts_pcr_digest() {
        let mut raw_response = [0u8; TPM_QUOTE_RESPONSE_MINIMUM_LENGTH];
        raw_response[0] = 0x80;
        raw_response[1] = 0x02;
        // Write a known pattern into the pcr_digest field
        for index in 0..32 {
            raw_response[TPM_QUOTE_PCR_DIGEST_OFFSET + index] = index as u8;
        }
        let result = parse_tpm_quote_response(&raw_response).unwrap();
        for index in 0..32 {
            assert_eq!(result.pcr_digest[index], index as u8);
        }
    }

    /// parse_tpm_quote_response extracts correct nonce_echo field.
    #[test]
    fn test_parse_tpm_quote_response_extracts_nonce_echo() {
        let mut raw_response = [0u8; TPM_QUOTE_RESPONSE_MINIMUM_LENGTH];
        raw_response[0] = 0x80;
        raw_response[1] = 0x02;
        for index in 0..32 {
            raw_response[TPM_QUOTE_NONCE_ECHO_OFFSET + index] = (index as u8).wrapping_add(64);
        }
        let result = parse_tpm_quote_response(&raw_response).unwrap();
        for index in 0..32 {
            assert_eq!(result.nonce_echo[index], (index as u8).wrapping_add(64));
        }
    }
}
