#![no_std]
#![deny(unsafe_code)]

//! SHA-256, in tree, from FIPS 180-4 (X-T4).
//!
//! The north star's dependency-closure rule names the target set exactly:
//! **SHA-256, HKDF, ChaCha20 and Poly1305, reimplemented from their
//! specifications, which deletes `sha2` and `chacha20`.** HKDF and Poly1305 are
//! already in tree; `sha2` and `chacha20` are the two that remain, and they are
//! the reason no document may currently describe this system's primitive set as
//! in-tree. This is the first of the two.
//!
//! # Why hand-rolling this is not the usual mistake
//!
//! "Do not roll your own crypto" is about *design*, and nothing here is
//! designed: SHA-256 is a published specification with published test vectors,
//! and an implementation either produces the specified digest for the specified
//! input or it does not. That is the case where reimplementation is checkable —
//! and the contrast with the Ed25519 stack is exactly the north star's
//! reasoning. Verifying a signature needs curve arithmetic whose correctness is
//! not decided by a handful of vectors, so `fiat-crypto`'s machine-verified
//! field arithmetic **stays**, permanently, because owning that code would
//! lower assurance rather than raise it.
//!
//! # No secret-dependent branching, no secret-dependent indexing
//!
//! Every operation below is a fixed sequence of adds, rotates and xors over the
//! whole input. There is no branch on message content and no table indexed by
//! it, so the timing of a digest depends on the message's *length* and nothing
//! else — which is the property a hash over key material needs, and the reason
//! this is worth reading closely rather than skimming.

/// Bytes in a SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Bytes in a SHA-256 compression block.
pub const BLOCK_LEN: usize = 64;

/// The eight initial hash values: FIPS 180-4 §5.3.3, the first 32 bits of the
/// fractional parts of the square roots of the first eight primes.
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// The sixty-four round constants: FIPS 180-4 §4.2.2, the first 32 bits of the
/// fractional parts of the cube roots of the first sixty-four primes.
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// An incremental SHA-256 computation.
///
/// Fixed size, no allocation: one 64-byte block buffer, eight words of state,
/// and a length. It is `Copy` so a caller can fork a computation without a
/// second buffer, which the BXW1 loader's streaming digest wants.
#[derive(Debug, Clone, Copy)]
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    length_bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh computation over the empty message.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            length_bits: 0,
        }
    }

    /// Absorbs `input`.
    ///
    /// The message length is tracked in **bits** and saturates rather than
    /// wrapping. A wrapped length would silently produce the digest of a
    /// different message, which is the one failure mode of a hash that no test
    /// vector catches — every vector is far below the boundary.
    pub fn update(&mut self, input: &[u8]) {
        self.length_bits = self
            .length_bits
            .saturating_add((input.len() as u64).saturating_mul(8));

        let mut offset = 0;
        while offset < input.len() {
            let room = BLOCK_LEN.saturating_sub(self.buffered);
            let take = room.min(input.len().saturating_sub(offset));
            // COVERAGE-EXEMPT: `take` is `min(room, len - offset)`, so this
            // range is inside `input` by construction. The `let else` exists
            // so the crate needs no indexing, which is what lets it hold
            // `deny(unsafe_code)` and the workspace's `indexing_slicing` lint
            // at once. `input[a..b]` here would be a panic path in a hash.
            let Some(chunk) = input.get(offset..offset.saturating_add(take)) else {
                return;
            };
            // COVERAGE-EXEMPT: `take` is bounded by `room`, which is
            // `BLOCK_LEN - buffered`, so this range is inside the fixed-size
            // buffer. Same reason as the `chunk` guard above.
            let Some(slot) = self
                .buffer
                .get_mut(self.buffered..self.buffered.saturating_add(take))
            else {
                return;
            };
            slot.copy_from_slice(chunk);
            self.buffered = self.buffered.saturating_add(take);
            offset = offset.saturating_add(take);

            if self.buffered == BLOCK_LEN {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }
    }

    /// Finishes the computation and returns the digest.
    ///
    /// Consumes by value: a hash state that has been padded is not a hash state
    /// that may be updated again, and taking `self` is how that stops being a
    /// rule someone has to remember.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        // §5.1.1: append 0x80, then zeros, then the 64-bit big-endian length,
        // so that the total is a multiple of the block size.
        let length_bits = self.length_bits;
        self.update_unbounded(&[0x80]);
        while self.buffered != BLOCK_LEN.saturating_sub(8) {
            self.update_unbounded(&[0x00]);
        }
        self.update_unbounded(&length_bits.to_be_bytes());

        let mut digest = [0u8; DIGEST_LEN];
        // `as_chunks_mut` hands back `&mut [[u8; 4]]`, so each write is a whole
        // array assignment: no range to compute, no length for
        // `copy_from_slice` to disagree with, and no unreachable `else` arm to
        // excuse. DIGEST_LEN is 32 and the state is 8 words, so the chunk count
        // and the word count agree by construction and `zip` needs no bound.
        let (words, _) = digest.as_chunks_mut::<4>();
        for (slot, word) in words.iter_mut().zip(self.state.iter()) {
            *slot = word.to_be_bytes();
        }
        digest
    }

    /// `update` without counting the bytes, for the padding itself.
    ///
    /// The padding is not part of the message, so counting it would put the
    /// wrong length into the very field being appended.
    fn update_unbounded(&mut self, input: &[u8]) {
        let saved = self.length_bits;
        self.update(input);
        self.length_bits = saved;
    }

    /// One application of the FIPS 180-4 §6.2.2 compression function.
    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut schedule = [0u32; 64];

        // The block read as 16 four-byte arrays rather than 16 fallible
        // four-byte ranges. `zip` supplies the bound that `take(16)` used to
        // spell out, and the element type is already `[u8; 4]`, so the
        // conversion that needed an unreachable error arm is now infallible.
        let (chunks, _) = block.as_chunks::<4>();
        for (slot, bytes) in schedule.iter_mut().zip(chunks) {
            *slot = u32::from_be_bytes(*bytes);
        }

        for index in 16usize..64 {
            let (Some(a), Some(b), Some(c), Some(d)) = (
                schedule.get(index.saturating_sub(15)).copied(),
                schedule.get(index.saturating_sub(2)).copied(),
                schedule.get(index.saturating_sub(16)).copied(),
                schedule.get(index.saturating_sub(7)).copied(),
                // COVERAGE-EXEMPT: `schedule` is `[u32; 64]` and `index` runs
                // 16..64, so index-15, index-2, index-16 and index-7 are all
                // within it.
            ) else {
                return;
            };
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
            // COVERAGE-EXEMPT: `index` runs 16..64 and `schedule` is 64 long.
            let Some(slot) = schedule.get_mut(index) else {
                return;
            };
            *slot = c.wrapping_add(s0).wrapping_add(d).wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // Both are `[u32; 64]`, so zipping runs exactly the 64 rounds the
        // index form ran, with the pair of unreachable `None` arms deleted
        // instead of justified.
        for (word, constant) in schedule.iter().copied().zip(ROUND_CONSTANTS) {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(constant)
                .wrapping_add(word);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// The SHA-256 digest of one contiguous message.
#[must_use]
pub fn digest(message: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize()
}
