//! SSH binary packet protocol — RFC 4253 §6 (unencrypted form, pre-NEWKEYS).
//!
//! Packet = uint32 packet_length | byte padding_length | payload | padding.
//! `packet_length` counts padding_length + payload + padding. The whole packet
//! (including the 4-byte length) is padded to a multiple of the cipher block
//! size (8 while unencrypted), with 4..=255 bytes of padding.

/// SSH message numbers used so far.
pub const SSH_MSG_KEXINIT: u8 = 20;
pub const SSH_MSG_NEWKEYS: u8 = 21;
pub const SSH_MSG_KEX_ECDH_INIT: u8 = 30;
pub const SSH_MSG_KEX_ECDH_REPLY: u8 = 31;

/// Block size for the unencrypted packet length rounding.
const UNENCRYPTED_BLOCK_SIZE: usize = 8;
const MINIMUM_PADDING: usize = 4;

/// Writes `payload` as an SSH binary packet into `out`, using `padding_source`
/// for the random padding bytes. Returns the total packet length.
pub fn write_packet(payload: &[u8], padding_source: &[u8], out: &mut [u8]) -> usize {
    // Total length before padding: 4 (length) + 1 (padding_length) + payload.
    let unpadded = 4 + 1 + payload.len();
    let mut padding_length = UNENCRYPTED_BLOCK_SIZE - (unpadded % UNENCRYPTED_BLOCK_SIZE);
    if padding_length < MINIMUM_PADDING {
        padding_length += UNENCRYPTED_BLOCK_SIZE;
    }
    let packet_length = 1 + payload.len() + padding_length;
    out[0..4].copy_from_slice(&(packet_length as u32).to_be_bytes());
    out[4] = padding_length as u8;
    out[5..5 + payload.len()].copy_from_slice(payload);
    let padding_start = 5 + payload.len();
    for index in 0..padding_length {
        out[padding_start + index] = padding_source.get(index).copied().unwrap_or(0);
    }
    padding_start + padding_length
}

/// A parsed binary packet: the payload byte range within the input buffer and
/// the total packet length consumed.
pub struct ParsedPacket {
    pub payload_start: usize,
    pub payload_end: usize,
    pub total_length: usize,
}

/// Parses one SSH binary packet at the start of `input`. Returns None if the
/// buffer does not yet hold a complete packet or it is malformed.
pub fn parse_packet(input: &[u8]) -> Option<ParsedPacket> {
    if input.len() < 4 {
        return None;
    }
    let packet_length = u32::from_be_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if packet_length < 2 || packet_length > 35000 {
        return None;
    }
    let total_length = 4 + packet_length;
    if input.len() < total_length {
        return None;
    }
    let padding_length = input[4] as usize;
    if padding_length + 1 > packet_length {
        return None;
    }
    let payload_start = 5;
    let payload_end = 4 + packet_length - padding_length;
    Some(ParsedPacket { payload_start, payload_end, total_length })
}

#[cfg(test)]
mod tests {
    use super::{parse_packet, write_packet, UNENCRYPTED_BLOCK_SIZE};

    #[test]
    fn test_write_then_parse_round_trip() {
        let payload = b"\x14hello-kexinit-payload";
        let padding = [0xAAu8; 64];
        let mut out = [0u8; 128];
        let total = write_packet(payload, &padding, &mut out);
        // Whole packet must be a multiple of the block size.
        assert_eq!(total % UNENCRYPTED_BLOCK_SIZE, 0);
        let parsed = parse_packet(&out[..total]).unwrap();
        assert_eq!(&out[parsed.payload_start..parsed.payload_end], payload);
        assert_eq!(parsed.total_length, total);
    }

    #[test]
    fn test_parse_incomplete_returns_none() {
        let payload = b"abcdefgh";
        let padding = [0u8; 64];
        let mut out = [0u8; 128];
        let total = write_packet(payload, &padding, &mut out);
        assert!(parse_packet(&out[..total - 1]).is_none());
        assert!(parse_packet(&out[..2]).is_none());
    }
}
