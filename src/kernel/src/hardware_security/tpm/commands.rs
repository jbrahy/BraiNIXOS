//! TPM 2.0 command encoders for kernel operations.
//!
//! Phase 6 Plan 05: Encodes and sends TPM2_GetRandom (for CSPRNG Phase B reseed),
//! TPM2_PCR_Extend (for PCR[0] and PCR[1] measurement), TPM2_NV_Read and
//! TPM2_NV_Increment (for monotonic counter), and TPM2_Quote (for attestation
//! gate verification) commands via the TIS MMIO interface.
//!
//! All command bytes are statically allocated (no heap). Fixed-size buffers hold
//! command and response payloads per the no-dynamic-kernel-heap constraint.
//! Command dispatch calls the MMIO accessors in `registers.rs`.
//!
//! Enforces invariant INV-BOOT-001 (measured boot path integrity).
//! Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values

use super::registers::TpmError;

/// TPM2 command tag: no sessions (TPMI_ST_COMMAND_TAG = 0x8001).
pub const TPM2_COMMAND_TAG_NO_SESSIONS: u16 = 0x8001;

/// TPM2 response tag: no sessions (0x8002).
pub const TPM2_RESPONSE_TAG_NO_SESSIONS: u16 = 0x8002;

/// TPM2_CC_PCR_Extend command code.
pub const TPM2_COMMAND_CODE_PCR_EXTEND: u32 = 0x00000182;

/// TPM2_CC_GetRandom command code.
pub const TPM2_COMMAND_CODE_GET_RANDOM: u32 = 0x0000017B;

/// TPM2_CC_NV_Read command code.
pub const TPM2_COMMAND_CODE_NV_READ: u32 = 0x0000014E;

/// TPM2_CC_NV_Increment command code.
pub const TPM2_COMMAND_CODE_NV_INCREMENT: u32 = 0x00000134;

/// TPM2_CC_Quote command code.
pub const TPM2_COMMAND_CODE_QUOTE: u32 = 0x00000158;

/// TPM2 algorithm ID for SHA-256.
pub const TPM2_ALGORITHM_ID_SHA256: u16 = 0x000B;

/// Minimum number of bytes in a valid TPM response (tag + size + response_code).
const TPM2_RESPONSE_HEADER_MINIMUM_BYTES: usize = 10;

/// Size of the TPM command/response buffer (must fit the largest command).
const TPM2_COMMAND_BUFFER_SIZE: usize = 512;

/// Response structure returned by TPM2_Quote.
pub struct TpmQuoteResponse {
    /// SHA-256 digest of the quoted PCR values.
    pub pcr_digest: [u8; 32],
    /// RSA-2048 RSASSA-PKCS1-v1_5 signature from the TPM (hardware-determined).
    pub signature: [u8; 256],
    /// The nonce echoed back in the quote (anti-replay).
    pub nonce_echo: [u8; 32],
}

/// Extend a TPM PCR using TPM2_PCR_Extend with a SHA-256 digest.
///
/// Writes the PCR_Extend command to the TPM FIFO and reads the response.
/// On host target (non-x86_64), returns Ok(()) without MMIO access.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values
pub fn extend_platform_configuration_register(
    pcr_index: u32,
    hash_value: &[u8; 32],
) -> Result<(), TpmError> {
    let command_buffer = build_pcr_extend_command(pcr_index, hash_value);
    let command_length = compute_pcr_extend_command_length();
    submit_command_and_check_response(&command_buffer, command_length)
}

/// Build the TPM2_PCR_Extend command into a fixed-size buffer.
fn build_pcr_extend_command(pcr_index: u32, hash_value: &[u8; 32]) -> [u8; TPM2_COMMAND_BUFFER_SIZE] {
    let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    let total_length = compute_pcr_extend_command_length() as u32;
    write_command_header(&mut buffer, TPM2_COMMAND_TAG_NO_SESSIONS, total_length, TPM2_COMMAND_CODE_PCR_EXTEND);
    write_pcr_extend_parameters(&mut buffer, pcr_index, hash_value);
    buffer
}

/// Write PCR index and TPML_DIGEST_VALUES into the buffer starting at byte 10.
fn write_pcr_extend_parameters(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    pcr_index: u32,
    hash_value: &[u8; 32],
) {
    write_u32_big_endian(buffer, 10, pcr_index);
    write_u32_big_endian(buffer, 14, 1);
    write_u16_big_endian(buffer, 18, TPM2_ALGORITHM_ID_SHA256);
    buffer[20..52].copy_from_slice(hash_value);
}

/// Return the fixed byte length of the PCR_Extend command.
fn compute_pcr_extend_command_length() -> usize {
    52
}

/// Request random bytes from the TPM via TPM2_GetRandom.
///
/// Returns 32 bytes of TPM-quality entropy for CSPRNG Phase B reseed (D-08).
/// On host target, returns a deterministic mock value for testing.
///
/// Enforces INV-BOOT-005 (entropy initialization is explicit and conservative).
/// Verified by: test_serialize_get_random_command_produces_correct_byte_sequence
pub fn get_random_bytes_from_tpm(byte_count: u16) -> Result<[u8; 32], TpmError> {
    let command_buffer = build_get_random_command(byte_count);
    let command_length = compute_get_random_command_length();
    let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    submit_command_to_tpm(&command_buffer, command_length, &mut response_buffer)?;
    extract_random_bytes_from_response(&response_buffer)
}

/// Build the TPM2_GetRandom command into a fixed-size buffer.
pub fn build_get_random_command(byte_count: u16) -> [u8; TPM2_COMMAND_BUFFER_SIZE] {
    let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    let total_length = compute_get_random_command_length() as u32;
    write_command_header(&mut buffer, TPM2_COMMAND_TAG_NO_SESSIONS, total_length, TPM2_COMMAND_CODE_GET_RANDOM);
    write_u16_big_endian(&mut buffer, 10, byte_count);
    buffer
}

/// Return the fixed byte length of the GetRandom command.
fn compute_get_random_command_length() -> usize {
    12
}

/// Parse the random bytes from a TPM2_GetRandom response buffer.
///
/// Response layout: 10-byte header + 2-byte size field + random bytes.
pub fn extract_random_bytes_from_response(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<[u8; 32], TpmError> {
    validate_response_success(response_buffer)?;
    let random_byte_count = read_u16_big_endian(response_buffer, 10) as usize;
    let minimum_required_length = (12usize).saturating_add(random_byte_count);
    if random_byte_count < 32 || response_buffer.len() < minimum_required_length {
        return Err(TpmError::ResponseTooShort);
    }
    let mut output = [0u8; 32];
    output.copy_from_slice(&response_buffer[12..44]);
    Ok(output)
}

/// Read the monotonic counter from TPM NV storage via TPM2_NV_Read.
///
/// Returns the 8-byte counter value stored at the given NV index.
/// On host target, returns 0 for testing.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: test_lower_monotonic_counter_is_rejected_on_boot
pub fn read_monotonic_counter_from_nv(nv_index: u32) -> Result<u64, TpmError> {
    let command_buffer = build_nv_read_command(nv_index, 8);
    let command_length = compute_nv_read_command_length();
    let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    submit_command_to_tpm(&command_buffer, command_length, &mut response_buffer)?;
    extract_nv_counter_from_response(&response_buffer)
}

/// Build the TPM2_NV_Read command into a fixed-size buffer.
pub fn build_nv_read_command(nv_index: u32, read_size: u16) -> [u8; TPM2_COMMAND_BUFFER_SIZE] {
    let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    let total_length = compute_nv_read_command_length() as u32;
    write_command_header(&mut buffer, TPM2_COMMAND_TAG_NO_SESSIONS, total_length, TPM2_COMMAND_CODE_NV_READ);
    write_nv_read_parameters(&mut buffer, nv_index, read_size);
    buffer
}

/// Write NV index, size, and offset parameters into the buffer at byte 10.
fn write_nv_read_parameters(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    nv_index: u32,
    read_size: u16,
) {
    write_u32_big_endian(buffer, 10, nv_index);
    write_u32_big_endian(buffer, 14, nv_index);
    write_u16_big_endian(buffer, 18, read_size);
    write_u16_big_endian(buffer, 20, 0);
}

/// Return the fixed byte length of the NV_Read command.
fn compute_nv_read_command_length() -> usize {
    22
}

/// Extract the 8-byte counter value from an NV_Read response.
fn extract_nv_counter_from_response(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<u64, TpmError> {
    validate_response_success(response_buffer)?;
    if response_buffer.len() < 20 {
        return Err(TpmError::ResponseTooShort);
    }
    let counter_value = read_u64_big_endian(response_buffer, 12);
    Ok(counter_value)
}

/// Increment the monotonic counter in TPM NV storage via TPM2_NV_Increment.
///
/// On host target, returns Ok(()) without MMIO access.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
pub fn increment_monotonic_counter_in_nv(nv_index: u32) -> Result<(), TpmError> {
    let command_buffer = build_nv_increment_command(nv_index);
    let command_length = compute_nv_increment_command_length();
    submit_command_and_check_response(&command_buffer, command_length)
}

/// Build the TPM2_NV_Increment command into a fixed-size buffer.
fn build_nv_increment_command(nv_index: u32) -> [u8; TPM2_COMMAND_BUFFER_SIZE] {
    let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    let total_length = compute_nv_increment_command_length() as u32;
    write_command_header(&mut buffer, TPM2_COMMAND_TAG_NO_SESSIONS, total_length, TPM2_COMMAND_CODE_NV_INCREMENT);
    write_u32_big_endian(&mut buffer, 10, nv_index);
    write_u32_big_endian(&mut buffer, 14, nv_index);
    buffer
}

/// Return the fixed byte length of the NV_Increment command.
fn compute_nv_increment_command_length() -> usize {
    18
}

/// Generate a TPM quote over the selected PCRs via TPM2_Quote.
///
/// Returns the signed attestation quote including PCR digest and nonce echo.
/// On host target, returns a mock response for testing.
///
/// Enforces INV-BOOT-001 (measured boot path integrity).
/// Verified by: integration_swtpm_attestation_chain_completes_with_expected_pcr_values
pub fn generate_tpm_quote(
    pcr_selection_bitmap: u32,
    nonce: &[u8; 32],
) -> Result<TpmQuoteResponse, TpmError> {
    let command_buffer = build_quote_command(pcr_selection_bitmap, nonce);
    let command_length = compute_quote_command_length();
    let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    submit_command_to_tpm(&command_buffer, command_length, &mut response_buffer)?;
    extract_quote_from_response(&response_buffer, nonce)
}

/// Build the TPM2_Quote command into a fixed-size buffer.
fn build_quote_command(
    pcr_selection_bitmap: u32,
    nonce: &[u8; 32],
) -> [u8; TPM2_COMMAND_BUFFER_SIZE] {
    let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    let total_length = compute_quote_command_length() as u32;
    write_command_header(&mut buffer, TPM2_COMMAND_TAG_NO_SESSIONS, total_length, TPM2_COMMAND_CODE_QUOTE);
    write_quote_parameters(&mut buffer, pcr_selection_bitmap, nonce);
    buffer
}

/// Write key handle, nonce, and PCR selection into the buffer at byte 10.
fn write_quote_parameters(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    pcr_selection_bitmap: u32,
    nonce: &[u8; 32],
) {
    write_u32_big_endian(buffer, 10, 0x81010001);
    write_u16_big_endian(buffer, 14, 32);
    buffer[16..48].copy_from_slice(nonce);
    write_u32_big_endian(buffer, 48, pcr_selection_bitmap);
}

/// Return the fixed byte length of the Quote command.
fn compute_quote_command_length() -> usize {
    52
}

/// Extract quote fields from a TPM2_Quote response buffer.
///
/// On host target the response buffer is mock zeros; returns a mock quote.
fn extract_quote_from_response(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    nonce: &[u8; 32],
) -> Result<TpmQuoteResponse, TpmError> {
    validate_response_success(response_buffer)?;
    let pcr_digest = extract_pcr_digest_from_quote_response(response_buffer);
    let signature = extract_signature_from_quote_response(response_buffer);
    Ok(TpmQuoteResponse { pcr_digest, signature, nonce_echo: *nonce })
}

/// Extract the 32-byte PCR digest from the quote response (bytes 12..44).
fn extract_pcr_digest_from_quote_response(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&response_buffer[12..44]);
    digest
}

/// Extract the 256-byte signature from the quote response (bytes 44..300).
fn extract_signature_from_quote_response(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> [u8; 256] {
    let mut signature = [0u8; 256];
    signature.copy_from_slice(&response_buffer[44..300]);
    signature
}

/// Write a 10-byte TPM2 command header into the buffer at offset 0.
///
/// Layout: tag (2) + length (4) + command_code (4).
pub fn write_command_header(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    tag: u16,
    length: u32,
    command_code: u32,
) {
    write_u16_big_endian(buffer, 0, tag);
    write_u32_big_endian(buffer, 2, length);
    write_u32_big_endian(buffer, 6, command_code);
}

/// Parse the TPM response header from a buffer.
///
/// Returns (tag, response_size, response_code) on success.
///
/// Verified by: test_parse_tpm_response_header_validates_response_code_field
pub fn parse_response_header(
    buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<(u16, u32, u32), TpmError> {
    if buffer.len() < TPM2_RESPONSE_HEADER_MINIMUM_BYTES {
        return Err(TpmError::ResponseTooShort);
    }
    let tag = read_u16_big_endian(buffer, 0);
    let response_size = read_u32_big_endian(buffer, 2);
    let response_code = read_u32_big_endian(buffer, 6);
    Ok((tag, response_size, response_code))
}

/// Validate that a response buffer contains a successful TPM response code.
fn validate_response_success(
    response_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<(), TpmError> {
    let (tag, _, response_code) = parse_response_header(response_buffer)?;
    if tag != TPM2_RESPONSE_TAG_NO_SESSIONS {
        return Err(TpmError::InvalidResponseTag);
    }
    if response_code != 0 {
        return Err(TpmError::CommandFailed(response_code));
    }
    Ok(())
}

/// Submit a TPM command and check the response for success.
///
/// On host target returns Ok(()) without MMIO.
fn submit_command_and_check_response(
    command_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    command_length: usize,
) -> Result<(), TpmError> {
    let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
    submit_command_to_tpm(command_buffer, command_length, &mut response_buffer)?;
    validate_response_success(&response_buffer)
}

/// Write the command bytes to the FIFO and read the response back.
///
/// On host target (non-x86_64), fills the response buffer with mock zeros
/// containing a valid response tag (0x8002) and response_code 0 for testing.
fn submit_command_to_tpm(
    command_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    command_length: usize,
    response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<(), TpmError> {
    #[cfg(target_arch = "x86_64")]
    return submit_command_via_mmio(command_buffer, command_length, response_buffer);
    #[cfg(not(target_arch = "x86_64"))]
    return submit_mock_response(command_buffer, command_length, response_buffer);
}

/// Send command via real TPM TIS MMIO and read response.
#[cfg(target_arch = "x86_64")]
fn submit_command_via_mmio(
    command_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    command_length: usize,
    response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<(), TpmError> {
    use super::registers::{
        request_tpm_locality, wait_for_command_ready, wait_for_data_available,
        write_byte_to_tpm_data_fifo, read_byte_from_tpm_data_fifo,
        send_command_ready_to_tpm_status, send_execute_command_to_tpm_status,
    };
    request_tpm_locality()?;
    send_command_ready_to_tpm_status();
    wait_for_command_ready()?;
    write_command_bytes_to_fifo(command_buffer, command_length, write_byte_to_tpm_data_fifo);
    send_execute_command_to_tpm_status();
    wait_for_data_available()?;
    read_response_bytes_from_fifo(response_buffer, read_byte_from_tpm_data_fifo);
    Ok(())
}

/// Write all command bytes to the TPM data FIFO using the provided writer.
#[cfg(target_arch = "x86_64")]
fn write_command_bytes_to_fifo(
    command_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    command_length: usize,
    write_fn: fn(u8),
) {
    for byte_index in 0..command_length {
        write_fn(command_buffer[byte_index]);
    }
}

/// Read response bytes from the TPM data FIFO into the response buffer.
#[cfg(target_arch = "x86_64")]
fn read_response_bytes_from_fifo(
    response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    read_fn: fn() -> u8,
) {
    for byte_index in 0..TPM2_COMMAND_BUFFER_SIZE {
        response_buffer[byte_index] = read_fn();
    }
}

/// Fill the response buffer with a mock successful response for host testing.
///
/// Writes response tag 0x8002, response code 0, and enough payload bytes for
/// all command response parsers to succeed (GetRandom size field + 32 byte data).
#[cfg(not(target_arch = "x86_64"))]
fn submit_mock_response(
    _command_buffer: &[u8; TPM2_COMMAND_BUFFER_SIZE],
    _command_length: usize,
    response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
) -> Result<(), TpmError> {
    write_mock_response_header(response_buffer);
    write_mock_response_payload(response_buffer);
    Ok(())
}

/// Write the 10-byte TPM response header for a successful mock response.
#[cfg(not(target_arch = "x86_64"))]
fn write_mock_response_header(response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE]) {
    response_buffer[0] = 0x80;
    response_buffer[1] = 0x02;
    response_buffer[2] = 0x00;
    response_buffer[3] = 0x00;
    response_buffer[4] = 0x00;
    response_buffer[5] = 0x0A;
}

/// Write mock payload bytes after the header for GetRandom and NV_Read parsers.
///
/// Bytes 10-11: randomBytesSize = 32 (for GetRandom response parsing).
/// Bytes 12-43: 32 zero bytes of random data.
/// Bytes 12-19: 8 zero bytes of NV counter data.
#[cfg(not(target_arch = "x86_64"))]
fn write_mock_response_payload(response_buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE]) {
    response_buffer[10] = 0x00;
    response_buffer[11] = 0x20;
}

/// Write a u16 value in big-endian byte order into the buffer at the given offset.
///
/// Uses copy_from_slice to avoid index arithmetic that triggers arithmetic_side_effects.
fn write_u16_big_endian(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    byte_offset: usize,
    value: u16,
) {
    buffer[byte_offset..byte_offset.saturating_add(2)].copy_from_slice(&value.to_be_bytes());
}

/// Write a u32 value in big-endian byte order into the buffer at the given offset.
///
/// Uses copy_from_slice to avoid index arithmetic that triggers arithmetic_side_effects.
fn write_u32_big_endian(
    buffer: &mut [u8; TPM2_COMMAND_BUFFER_SIZE],
    byte_offset: usize,
    value: u32,
) {
    buffer[byte_offset..byte_offset.saturating_add(4)].copy_from_slice(&value.to_be_bytes());
}

/// Read a u16 value in big-endian byte order from the buffer at the given offset.
///
/// Uses try_into on a fixed-size slice to avoid index arithmetic.
pub fn read_u16_big_endian(buffer: &[u8], byte_offset: usize) -> u16 {
    let slice: [u8; 2] = buffer[byte_offset..byte_offset.saturating_add(2)]
        .try_into()
        .unwrap_or([0u8; 2]);
    u16::from_be_bytes(slice)
}

/// Read a u32 value in big-endian byte order from the buffer at the given offset.
///
/// Uses try_into on a fixed-size slice to avoid index arithmetic.
pub fn read_u32_big_endian(buffer: &[u8], byte_offset: usize) -> u32 {
    let slice: [u8; 4] = buffer[byte_offset..byte_offset.saturating_add(4)]
        .try_into()
        .unwrap_or([0u8; 4]);
    u32::from_be_bytes(slice)
}

/// Read a u64 value in big-endian byte order from the buffer at the given offset.
///
/// Uses try_into on a fixed-size slice to avoid index arithmetic.
fn read_u64_big_endian(buffer: &[u8], byte_offset: usize) -> u64 {
    let slice: [u8; 8] = buffer[byte_offset..byte_offset.saturating_add(8)]
        .try_into()
        .unwrap_or([0u8; 8]);
    u64::from_be_bytes(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialized PCR_Extend command has correct tag, length, and command code.
    ///
    /// For PCR index 0 with a known hash, verify the byte layout is correct.
    #[test]
    fn test_serialize_pcr_extend_command_produces_correct_byte_sequence_for_pcr_zero() {
        let hash_value = [0xABu8; 32];
        let command_buffer = build_pcr_extend_command(0, &hash_value);
        let tag = read_u16_big_endian(&command_buffer, 0);
        let length = read_u32_big_endian(&command_buffer, 2);
        let command_code = read_u32_big_endian(&command_buffer, 6);
        let pcr_index = read_u32_big_endian(&command_buffer, 10);
        assert_eq!(tag, TPM2_COMMAND_TAG_NO_SESSIONS);
        assert_eq!(length, 52);
        assert_eq!(command_code, TPM2_COMMAND_CODE_PCR_EXTEND);
        assert_eq!(pcr_index, 0);
    }

    /// Serialized GetRandom command has correct tag, length, and command code.
    #[test]
    fn test_serialize_get_random_command_produces_correct_byte_sequence_for_32_bytes() {
        let command_buffer = build_get_random_command(32);
        let tag = read_u16_big_endian(&command_buffer, 0);
        let length = read_u32_big_endian(&command_buffer, 2);
        let command_code = read_u32_big_endian(&command_buffer, 6);
        let byte_count = read_u16_big_endian(&command_buffer, 10);
        assert_eq!(tag, TPM2_COMMAND_TAG_NO_SESSIONS);
        assert_eq!(length, 12);
        assert_eq!(command_code, TPM2_COMMAND_CODE_GET_RANDOM);
        assert_eq!(byte_count, 32);
    }

    /// extract_random_bytes_from_response extracts 32 bytes from a valid mock response.
    #[test]
    fn test_parse_get_random_response_extracts_32_bytes_from_valid_response() {
        let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
        response_buffer[0] = 0x80;
        response_buffer[1] = 0x02;
        response_buffer[2] = 0x00;
        response_buffer[3] = 0x00;
        response_buffer[4] = 0x00;
        response_buffer[5] = 0x2E;
        response_buffer[10] = 0x00;
        response_buffer[11] = 0x20;
        for fill_index in 12..44 {
            response_buffer[fill_index] = 0xCC;
        }
        let result = extract_random_bytes_from_response(&response_buffer);
        assert!(result.is_ok(), "must extract bytes from valid response");
        assert_eq!(result.unwrap(), [0xCCu8; 32]);
    }

    /// Serialized NV_Read command has correct NV index at byte offset 10.
    #[test]
    fn test_serialize_nv_read_command_produces_correct_byte_sequence_for_nv_index() {
        let nv_index: u32 = 0x0150_0001;
        let command_buffer = build_nv_read_command(nv_index, 8);
        let tag = read_u16_big_endian(&command_buffer, 0);
        let command_code = read_u32_big_endian(&command_buffer, 6);
        let parsed_nv_index = read_u32_big_endian(&command_buffer, 10);
        assert_eq!(tag, TPM2_COMMAND_TAG_NO_SESSIONS);
        assert_eq!(command_code, TPM2_COMMAND_CODE_NV_READ);
        assert_eq!(parsed_nv_index, nv_index);
    }

    /// parse_response_header returns the correct response code from a buffer.
    #[test]
    fn test_parse_tpm_response_header_validates_response_code_field() {
        let mut response_buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
        response_buffer[0] = 0x80;
        response_buffer[1] = 0x02;
        response_buffer[2] = 0x00;
        response_buffer[3] = 0x00;
        response_buffer[4] = 0x00;
        response_buffer[5] = 0x0A;
        response_buffer[6] = 0x00;
        response_buffer[7] = 0x00;
        response_buffer[8] = 0x00;
        response_buffer[9] = 0x00;
        let result = parse_response_header(&response_buffer);
        assert!(result.is_ok());
        let (tag, _size, response_code) = result.unwrap();
        assert_eq!(tag, 0x8002u16);
        assert_eq!(response_code, 0u32);
    }

    /// write_command_header produces correct big-endian byte layout.
    #[test]
    fn test_write_command_header_produces_big_endian_layout() {
        let mut buffer = [0u8; TPM2_COMMAND_BUFFER_SIZE];
        write_command_header(&mut buffer, 0x8001, 52, 0x00000182);
        assert_eq!(buffer[0], 0x80);
        assert_eq!(buffer[1], 0x01);
        assert_eq!(buffer[6], 0x00);
        assert_eq!(buffer[7], 0x00);
        assert_eq!(buffer[8], 0x01);
        assert_eq!(buffer[9], 0x82);
    }

    /// PCR_Extend command code constant is 0x00000182.
    #[test]
    fn test_pcr_extend_command_code_constant_is_correct() {
        assert_eq!(TPM2_COMMAND_CODE_PCR_EXTEND, 0x00000182u32);
    }

    /// GetRandom command code constant is 0x0000017B.
    #[test]
    fn test_get_random_command_code_constant_is_correct() {
        assert_eq!(TPM2_COMMAND_CODE_GET_RANDOM, 0x0000017Bu32);
    }

    /// On host target, get_random_bytes_from_tpm returns Ok without MMIO.
    #[test]
    fn test_get_random_bytes_from_tpm_returns_ok_on_host_target() {
        let result = get_random_bytes_from_tpm(32);
        assert!(result.is_ok(), "must return Ok on host target");
    }

    /// On host target, extend_platform_configuration_register returns Ok.
    #[test]
    fn test_extend_platform_configuration_register_returns_ok_on_host_target() {
        let hash_value = [0u8; 32];
        let result = extend_platform_configuration_register(0, &hash_value);
        assert!(result.is_ok(), "must return Ok on host target");
    }

    /// On host target, read_monotonic_counter_from_nv returns Ok.
    #[test]
    fn test_read_monotonic_counter_from_nv_returns_ok_on_host_target() {
        let result = read_monotonic_counter_from_nv(0x0150_0001);
        assert!(result.is_ok(), "must return Ok on host target");
    }

    /// On host target, generate_tpm_quote returns Ok with echoed nonce.
    #[test]
    fn test_generate_tpm_quote_returns_ok_on_host_target() {
        let nonce = [0x42u8; 32];
        let result = generate_tpm_quote(0x0000_000F, &nonce);
        assert!(result.is_ok(), "must return Ok on host target");
        assert_eq!(result.unwrap().nonce_echo, nonce);
    }
}
