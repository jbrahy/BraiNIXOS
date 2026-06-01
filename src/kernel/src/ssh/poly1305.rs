//! Poly1305 one-time MAC (RFC 8439 §2.5), 32-bit radix-2^26 implementation
//! (poly1305-donna style). Used by the chacha20-poly1305@openssh.com transport.

/// Computes the 16-byte Poly1305 tag over `message` with the 32-byte one-time
/// `key` (r = key[0..16] clamped, s = key[16..32]).
pub fn poly1305_mac(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    // Clamp r into five 26-bit limbs.
    let r0 = (load_u32(&key[0..4])) & 0x3ff_ffff;
    let r1 = (load_u32(&key[3..7]) >> 2) & 0x3ff_ff03;
    let r2 = (load_u32(&key[6..10]) >> 4) & 0x3ff_c0ff;
    let r3 = (load_u32(&key[9..13]) >> 6) & 0x3f0_3fff;
    let r4 = (load_u32(&key[12..16]) >> 8) & 0x00f_ffff;

    let s1 = r1 * 5;
    let s2 = r2 * 5;
    let s3 = r3 * 5;
    let s4 = r4 * 5;

    let mut h0: u32 = 0;
    let mut h1: u32 = 0;
    let mut h2: u32 = 0;
    let mut h3: u32 = 0;
    let mut h4: u32 = 0;

    let mut offset = 0;
    while offset < message.len() {
        let remaining = message.len() - offset;
        let block_length = remaining.min(16);
        let mut buffer = [0u8; 16];
        buffer[..block_length].copy_from_slice(&message[offset..offset + block_length]);
        // High "2^128" marker: a full block carries it beyond the 16 bytes
        // (hibit), a partial block sets the 0x01 byte just past the data.
        let hibit = if block_length < 16 {
            buffer[block_length] = 0x01;
            0u32
        } else {
            1u32 << 24
        };

        // Add the block to the accumulator, repacking 4x32-bit -> 5x26-bit limbs.
        let t0 = load_u32(&buffer[0..4]);
        let t1 = load_u32(&buffer[4..8]);
        let t2 = load_u32(&buffer[8..12]);
        let t3 = load_u32(&buffer[12..16]);
        h0 += t0 & 0x3ff_ffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff;
        h4 += (t3 >> 8) | hibit;

        // h *= r  (mod 2^130 - 5)
        let d0 = mul_add(h0, r0, h1, s4, h2, s3, h3, s2, h4, s1);
        let d1 = mul_add(h0, r1, h1, r0, h2, s4, h3, s3, h4, s2);
        let d2 = mul_add(h0, r2, h1, r1, h2, r0, h3, s4, h4, s3);
        let d3 = mul_add(h0, r3, h1, r2, h2, r1, h3, r0, h4, s4);
        let d4 = mul_add(h0, r4, h1, r3, h2, r2, h3, r1, h4, r0);

        // Carry propagate.
        let mut carry = (d0 >> 26) as u32;
        h0 = (d0 as u32) & 0x3ff_ffff;
        let d1 = d1 + carry as u64;
        carry = (d1 >> 26) as u32;
        h1 = (d1 as u32) & 0x3ff_ffff;
        let d2 = d2 + carry as u64;
        carry = (d2 >> 26) as u32;
        h2 = (d2 as u32) & 0x3ff_ffff;
        let d3 = d3 + carry as u64;
        carry = (d3 >> 26) as u32;
        h3 = (d3 as u32) & 0x3ff_ffff;
        let d4 = d4 + carry as u64;
        carry = (d4 >> 26) as u32;
        h4 = (d4 as u32) & 0x3ff_ffff;
        h0 += carry * 5;
        carry = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += carry;

        offset += block_length;
    }

    // Final reduction.
    let mut carry = h1 >> 26;
    h1 &= 0x3ff_ffff;
    h2 += carry;
    carry = h2 >> 26;
    h2 &= 0x3ff_ffff;
    h3 += carry;
    carry = h3 >> 26;
    h3 &= 0x3ff_ffff;
    h4 += carry;
    carry = h4 >> 26;
    h4 &= 0x3ff_ffff;
    h0 += carry * 5;
    carry = h0 >> 26;
    h0 &= 0x3ff_ffff;
    h1 += carry;

    // Compute h - p (to decide final modular value).
    let mut g0 = h0.wrapping_add(5);
    carry = g0 >> 26;
    g0 &= 0x3ff_ffff;
    let mut g1 = h1.wrapping_add(carry);
    carry = g1 >> 26;
    g1 &= 0x3ff_ffff;
    let mut g2 = h2.wrapping_add(carry);
    carry = g2 >> 26;
    g2 &= 0x3ff_ffff;
    let mut g3 = h3.wrapping_add(carry);
    carry = g3 >> 26;
    g3 &= 0x3ff_ffff;
    let g4 = h4.wrapping_add(carry).wrapping_sub(1 << 26);

    // Select h if h < p, else h - p (constant-time via mask).
    let mask = (g4 >> 31).wrapping_sub(1); // 0xffffffff if g4 >= 0 (use h-p), else 0
    let invert = !mask;
    h0 = (h0 & invert) | (g0 & mask);
    h1 = (h1 & invert) | (g1 & mask);
    h2 = (h2 & invert) | (g2 & mask);
    h3 = (h3 & invert) | (g3 & mask);
    h4 = (h4 & invert) | (g4 & mask);

    // Serialize h (mod 2^128) and add s.
    let mut h = [0u32; 4];
    h[0] = (h0 | (h1 << 26)) & 0xffff_ffff;
    h[1] = ((h1 >> 6) | (h2 << 20)) & 0xffff_ffff;
    h[2] = ((h2 >> 12) | (h3 << 14)) & 0xffff_ffff;
    h[3] = ((h3 >> 18) | (h4 << 8)) & 0xffff_ffff;

    let mut tag = [0u8; 16];
    let mut carry_add: u64 = 0;
    for index in 0..4 {
        let s_word = load_u32(&key[16 + index * 4..16 + index * 4 + 4]) as u64;
        let sum = h[index] as u64 + s_word + carry_add;
        carry_add = sum >> 32;
        tag[index * 4..index * 4 + 4].copy_from_slice(&((sum as u32).to_le_bytes()));
    }
    tag
}

#[allow(clippy::too_many_arguments)]
fn mul_add(h0: u32, m0: u32, h1: u32, m1: u32, h2: u32, m2: u32, h3: u32, m3: u32, h4: u32, m4: u32) -> u64 {
    (h0 as u64) * (m0 as u64)
        + (h1 as u64) * (m1 as u64)
        + (h2 as u64) * (m2 as u64)
        + (h3 as u64) * (m3 as u64)
        + (h4 as u64) * (m4 as u64)
}

fn load_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

#[cfg(test)]
mod tests {
    use super::poly1305_mac;

    #[test]
    fn test_rfc8439_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let message = b"Cryptographic Forum Research Group";
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(poly1305_mac(&key, message), expected);
    }
}
