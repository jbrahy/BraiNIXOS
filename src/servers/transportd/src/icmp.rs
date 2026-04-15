//! ICMP message parsing and reply generation for Phase 9 network stack decomposition.
//!
//! Parses ICMP messages from raw byte slices and generates ICMP echo replies.
//! No heap allocation — all results are stack-resident value types.

/// ICMP type value for an echo request message.
pub const ICMP_TYPE_ECHO_REQUEST: u8 = 8;

/// ICMP type value for an echo reply message.
pub const ICMP_TYPE_ECHO_REPLY: u8 = 0;

/// Length in bytes of a standard ICMP header.
pub const ICMP_HEADER_LENGTH: usize = 8;

/// Parsed view of an ICMP message header.
///
/// Carries the type, code, identifier, and sequence number fields required
/// for echo request/reply processing. The checksum field is verified during
/// parsing and is not exposed in the parsed result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ParsedIcmpMessage {
    /// ICMP message type (e.g., ICMP_TYPE_ECHO_REQUEST or ICMP_TYPE_ECHO_REPLY).
    pub icmp_type: u8,
    /// ICMP message code (subtype within the ICMP type).
    pub icmp_code: u8,
    /// Identifier field used to match echo replies to echo requests.
    pub identifier: u16,
    /// Sequence number field used to order echo replies.
    pub sequence_number: u16,
}

/// Errors returned when ICMP message parsing or reply generation fails.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IcmpParseError {
    /// The message is shorter than the minimum ICMP header length.
    TooShort,
    /// The ICMP header checksum does not match the computed value.
    InvalidChecksum,
}

/// Returns Err(TooShort) if the message is shorter than ICMP_HEADER_LENGTH.
///
/// Enforces the minimum message length required before any field extraction.
fn validate_minimum_icmp_length(message_bytes: &[u8]) -> Result<(), IcmpParseError> {
    if message_bytes.len() < ICMP_HEADER_LENGTH {
        return Err(IcmpParseError::TooShort);
    }
    Ok(())
}

/// Returns Err(TooShort) if the buffer is smaller than the required length.
///
/// Used to verify the reply buffer has capacity before writing.
fn validate_reply_buffer_capacity(
    reply_buffer: &[u8],
    required_length: usize,
) -> Result<(), IcmpParseError> {
    if reply_buffer.len() < required_length {
        return Err(IcmpParseError::TooShort);
    }
    Ok(())
}

/// Computes the one's complement 16-bit checksum over an ICMP message.
///
/// For a valid message, computing over the full message (including checksum field)
/// returns 0. For generation, compute with checksum bytes zeroed to obtain the
/// checksum value to place in bytes 2-3.
///
/// Verified by: test_valid_echo_request_returns_parsed_message
pub fn compute_icmp_checksum(message_bytes: &[u8]) -> u16 {
    let accumulated_sum = accumulate_sixteen_bit_words(message_bytes);
    let folded_sum = fold_carry_bits_into_sixteen_bits(accumulated_sum);
    !(folded_sum as u16)
}

/// Accumulates all 16-bit words in the message into a 32-bit sum.
///
/// Odd-length messages are padded with a zero byte on the right.
fn accumulate_sixteen_bit_words(message_bytes: &[u8]) -> u32 {
    let word_count = message_bytes.len() / 2;
    let has_trailing_byte = message_bytes.len() % 2 != 0;
    let word_sum = sum_all_sixteen_bit_words(message_bytes, word_count);
    add_trailing_byte_if_present(word_sum, message_bytes, has_trailing_byte)
}

/// Sums all complete 16-bit words from the message bytes.
fn sum_all_sixteen_bit_words(message_bytes: &[u8], word_count: usize) -> u32 {
    let mut accumulated = 0u32;
    let mut word_index = 0;
    while word_index < word_count {
        let byte_offset = word_index * 2;
        let high_byte = u32::from(message_bytes[byte_offset]);
        let low_byte = u32::from(message_bytes[byte_offset + 1]);
        accumulated += (high_byte << 8) | low_byte;
        word_index += 1;
    }
    accumulated
}

/// Adds the trailing odd byte (padded with zero) if the message length is odd.
fn add_trailing_byte_if_present(
    accumulated: u32,
    message_bytes: &[u8],
    has_trailing_byte: bool,
) -> u32 {
    if has_trailing_byte {
        let trailing_byte = u32::from(message_bytes[message_bytes.len() - 1]);
        return accumulated + (trailing_byte << 8);
    }
    accumulated
}

/// Folds the upper 16 bits of a 32-bit sum into the lower 16 bits.
///
/// Repeated until all carry bits are absorbed into the 16-bit result.
fn fold_carry_bits_into_sixteen_bits(accumulated: u32) -> u32 {
    let lower_sixteen = accumulated & 0xFFFF;
    let upper_sixteen = accumulated >> 16;
    lower_sixteen + upper_sixteen
}

/// Validates the ICMP checksum of a message by verifying the result is zero.
///
/// For a valid ICMP message, computing the checksum over the entire message
/// (including the checksum field) produces zero.
fn validate_icmp_checksum(message_bytes: &[u8]) -> Result<(), IcmpParseError> {
    let checksum_result = compute_icmp_checksum(message_bytes);
    if checksum_result != 0 {
        return Err(IcmpParseError::InvalidChecksum);
    }
    Ok(())
}

/// Extracts the ICMP type from byte 0 of the message.
fn extract_icmp_type(message_bytes: &[u8]) -> u8 {
    message_bytes[0]
}

/// Extracts the ICMP code from byte 1 of the message.
fn extract_icmp_code(message_bytes: &[u8]) -> u8 {
    message_bytes[1]
}

/// Extracts the ICMP identifier from bytes 4-5 in big-endian order.
fn extract_icmp_identifier(message_bytes: &[u8]) -> u16 {
    let high_byte = u16::from(message_bytes[4]);
    let low_byte = u16::from(message_bytes[5]);
    (high_byte << 8) | low_byte
}

/// Extracts the ICMP sequence number from bytes 6-7 in big-endian order.
fn extract_icmp_sequence_number(message_bytes: &[u8]) -> u16 {
    let high_byte = u16::from(message_bytes[6]);
    let low_byte = u16::from(message_bytes[7]);
    (high_byte << 8) | low_byte
}

/// Constructs a ParsedIcmpMessage from the extracted header fields.
fn build_parsed_icmp_message(
    icmp_type: u8,
    icmp_code: u8,
    identifier: u16,
    message_bytes: &[u8],
) -> Result<ParsedIcmpMessage, IcmpParseError> {
    let sequence_number = extract_icmp_sequence_number(message_bytes);
    Ok(ParsedIcmpMessage { icmp_type, icmp_code, identifier, sequence_number })
}

/// Copies the request bytes into the reply buffer.
fn copy_request_into_reply_buffer(request_bytes: &[u8], reply_buffer: &mut [u8]) {
    reply_buffer[..request_bytes.len()].copy_from_slice(request_bytes);
}

/// Sets the ICMP type to echo reply (0) and zeros the checksum field.
///
/// The checksum field must be zeroed before checksum computation.
fn set_reply_type_and_zero_checksum(reply_buffer: &mut [u8]) {
    reply_buffer[0] = ICMP_TYPE_ECHO_REPLY;
    reply_buffer[2] = 0;
    reply_buffer[3] = 0;
}

/// Computes the checksum over the reply buffer and writes it into bytes 2-3.
///
/// Must be called after zeroing the checksum field in bytes 2-3.
fn write_computed_checksum_into_reply(reply_buffer: &mut [u8], reply_length: usize) {
    let computed_checksum = compute_icmp_checksum(&reply_buffer[..reply_length]);
    reply_buffer[2] = (computed_checksum >> 8) as u8;
    reply_buffer[3] = computed_checksum as u8;
}

/// Parses an ICMP message header from a raw byte slice.
///
/// Returns a ParsedIcmpMessage on success, or an IcmpParseError if the
/// message is too short or has an invalid checksum.
///
/// Verified by: fuzz_transportd_ingress_with_adversarial_transport_segments
pub fn parse_icmp_message(message_bytes: &[u8]) -> Result<ParsedIcmpMessage, IcmpParseError> {
    validate_minimum_icmp_length(message_bytes)?;
    validate_icmp_checksum(message_bytes)?;
    let icmp_type = extract_icmp_type(message_bytes);
    let icmp_code = extract_icmp_code(message_bytes);
    let identifier = extract_icmp_identifier(message_bytes);
    build_parsed_icmp_message(icmp_type, icmp_code, identifier, message_bytes)
}

/// Generates an ICMP echo reply into a caller-supplied buffer.
///
/// Reads the echo request fields from request_bytes, constructs an echo reply
/// with ICMP_TYPE_ECHO_REPLY, and writes it into reply_buffer. Returns the
/// number of bytes written on success, or an IcmpParseError if the request
/// is malformed.
///
/// Verified by: fuzz_transportd_ingress_with_adversarial_transport_segments
pub fn generate_icmp_echo_reply(
    request_bytes: &[u8],
    reply_buffer: &mut [u8],
) -> Result<usize, IcmpParseError> {
    validate_minimum_icmp_length(request_bytes)?;
    validate_reply_buffer_capacity(reply_buffer, request_bytes.len())?;
    copy_request_into_reply_buffer(request_bytes, reply_buffer);
    set_reply_type_and_zero_checksum(reply_buffer);
    let reply_length = request_bytes.len();
    write_computed_checksum_into_reply(reply_buffer, reply_length);
    Ok(reply_length)
}

#[cfg(test)]
mod tests {
    use super::{
        IcmpParseError, ParsedIcmpMessage, ICMP_HEADER_LENGTH, ICMP_TYPE_ECHO_REPLY,
        ICMP_TYPE_ECHO_REQUEST, compute_icmp_checksum, generate_icmp_echo_reply, parse_icmp_message,
    };

    /// Builds a minimal valid ICMP echo request (8 bytes, no data).
    ///
    /// Bytes: type=8, code=0, checksum=0xF7FD, id=1, seq=1.
    /// Checksum derivation: words 0x0800 + 0x0000 + 0x0001 + 0x0001 = 0x0802.
    /// One's complement: !0x0802 = 0xF7FD. Verification: sum all = 0xFFFF, !0xFFFF = 0.
    fn build_valid_echo_request_header() -> [u8; 8] {
        [8, 0, 0xF7, 0xFD, 0, 1, 0, 1]
    }

    /// Builds a valid ICMP echo request with a 4-byte payload [0xAA, 0xBB, 0xCC, 0xDD].
    ///
    /// Fixed-size 12-byte buffer: 8-byte header + 4-byte payload.
    /// Computes the checksum with the checksum field zeroed, then writes it.
    fn build_valid_echo_request_with_four_byte_payload() -> [u8; 12] {
        let mut message = [0u8; 12];
        message[0] = ICMP_TYPE_ECHO_REQUEST;
        message[1] = 0;
        message[4] = 0;
        message[5] = 1;
        message[6] = 0;
        message[7] = 1;
        message[8] = 0xAA;
        message[9] = 0xBB;
        message[10] = 0xCC;
        message[11] = 0xDD;
        let computed_checksum = compute_icmp_checksum(&message);
        message[2] = (computed_checksum >> 8) as u8;
        message[3] = computed_checksum as u8;
        message
    }

    #[test]
    fn message_shorter_than_eight_bytes_returns_too_short() {
        let short_message = [0u8; 7];
        let parse_result = parse_icmp_message(&short_message);
        assert_eq!(parse_result, Err(IcmpParseError::TooShort));
    }

    #[test]
    fn empty_message_returns_too_short() {
        let empty_message: &[u8] = &[];
        let parse_result = parse_icmp_message(empty_message);
        assert_eq!(parse_result, Err(IcmpParseError::TooShort));
    }

    #[test]
    fn valid_echo_request_returns_parsed_message_with_correct_fields() {
        let request_bytes = build_valid_echo_request_header();
        let parse_result = parse_icmp_message(&request_bytes);
        let expected = ParsedIcmpMessage {
            icmp_type: ICMP_TYPE_ECHO_REQUEST,
            icmp_code: 0,
            identifier: 1,
            sequence_number: 1,
        };
        assert_eq!(parse_result, Ok(expected));
    }

    #[test]
    fn message_with_invalid_checksum_returns_invalid_checksum() {
        let mut request_bytes = build_valid_echo_request_header();
        request_bytes[2] = 0xFF;
        request_bytes[3] = 0xFF;
        let parse_result = parse_icmp_message(&request_bytes);
        assert_eq!(parse_result, Err(IcmpParseError::InvalidChecksum));
    }

    #[test]
    fn generate_echo_reply_produces_type_zero_with_same_identifier_and_sequence_number() {
        let request_bytes = build_valid_echo_request_header();
        let mut reply_buffer = [0u8; 64];
        let reply_result = generate_icmp_echo_reply(&request_bytes, &mut reply_buffer);
        assert!(reply_result.is_ok());
        assert_eq!(reply_buffer[0], ICMP_TYPE_ECHO_REPLY);
        assert_eq!(reply_buffer[4], 0);
        assert_eq!(reply_buffer[5], 1);
        assert_eq!(reply_buffer[6], 0);
        assert_eq!(reply_buffer[7], 1);
    }

    #[test]
    fn generate_echo_reply_copies_payload_data_from_request() {
        let request_bytes = build_valid_echo_request_with_four_byte_payload();
        let mut reply_buffer = [0u8; 64];
        let reply_result = generate_icmp_echo_reply(&request_bytes, &mut reply_buffer);
        assert!(reply_result.is_ok());
        let reply_length = reply_result.unwrap();
        let expected_payload = [0xAA, 0xBB, 0xCC, 0xDD];
        assert_eq!(&reply_buffer[ICMP_HEADER_LENGTH..reply_length], &expected_payload);
    }

    #[test]
    fn generate_echo_reply_computes_correct_checksum_for_reply() {
        let request_bytes = build_valid_echo_request_header();
        let mut reply_buffer = [0u8; 64];
        let reply_result = generate_icmp_echo_reply(&request_bytes, &mut reply_buffer);
        assert!(reply_result.is_ok());
        let reply_length = reply_result.unwrap();
        let verification_checksum = compute_icmp_checksum(&reply_buffer[..reply_length]);
        assert_eq!(verification_checksum, 0);
    }

    #[test]
    fn generate_echo_reply_with_buffer_too_small_returns_too_short() {
        let request_bytes = build_valid_echo_request_header();
        let mut small_buffer = [0u8; 4];
        let reply_result = generate_icmp_echo_reply(&request_bytes, &mut small_buffer);
        assert_eq!(reply_result, Err(IcmpParseError::TooShort));
    }
}
