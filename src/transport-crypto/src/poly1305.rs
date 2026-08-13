//! Poly1305 one-time MAC (RFC 8439 §2.5), radix-2^26 (poly1305-donna style).
//!
//! **Provenance.** §4.2's code-provenance note says the record construction
//! lives in `src/kernel/src/ssh/transport.rs` today and that P2-T2 factors it
//! into this crate. This module is the `poly1305` half of that move: it is the
//! in-tree implementation from `src/kernel/src/ssh/poly1305.rs`, brought across
//! with three changes and no algorithmic ones —
//!
//! 1. every `+`, `-`, and `*` is `wrapping_add` / `wrapping_sub` /
//!    `wrapping_mul`, because this crate denies
//!    `clippy::arithmetic_side_effects`. The donna limb arithmetic is defined
//!    not to overflow at any of those sites, so the wrapping form is
//!    behaviour-preserving, and it removes a panic in any build that enables
//!    overflow checks;
//! 2. every slice read goes through `get`, so no input length can panic;
//! 3. the message is absorbed through a **streaming** API, so the record layer
//!    can authenticate `enc_length || ciphertext` without first copying them
//!    into one buffer — which is what lets [`crate::record`] seal and open in
//!    place with no scratch of its own.
//!
//! The kernel's SSH transport is **not** deleted here: P2-T6 deletes the SSH
//! bridge, and removing a live path from a task that only adds one is outside
//! this task's scope.
//!
//! Poly1305 is **not vendored** — there is no `poly1305` crate in `vendor/` —
//! so unlike SHA-256 and ChaCha20 it cannot be consumed rather than written.
//! It is checked against RFC 8439 §2.5.2 and §A.3 in `tests/known_answer.rs`.
//!
//! # Constant time
//!
//! The final conditional subtraction of `p = 2^130 − 5` is a **mask select**,
//! not a branch: `mask = (g4 >> 31) − 1` is all-ones or all-zeros and both
//! candidates are computed unconditionally. That is manual constant-time
//! reasoning rather than a `subtle` primitive, and the report names it as such.
//! The only data-dependent branch in the module is on the message *length*,
//! which is public.

/// Bytes in a Poly1305 tag.
pub const POLY1305_TAG_BYTES: usize = 16;

/// Bytes in a Poly1305 one-time key (`r || s`).
pub const POLY1305_KEY_BYTES: usize = 32;

/// Bytes in one Poly1305 block.
const BLOCK_BYTES: usize = 16;

/// The 26-bit limb mask.
const LIMB_MASK: u32 = 0x3ff_ffff;

/// A streaming Poly1305 state.
///
/// One-time by construction: [`Poly1305::finalize`] consumes `self`, so the
/// same key cannot authenticate two messages through this type.
pub struct Poly1305 {
    /// `r`, clamped, in five 26-bit limbs.
    r: [u32; 5],
    /// `5·r_1 .. 5·r_4`, precomputed for the wrap-around reduction.
    r_times_five: [u32; 4],
    /// `s`, the final addend, as four little-endian words.
    s: [u32; 4],
    /// The accumulator, in five 26-bit limbs.
    accumulator: [u32; 5],
    /// A partial block carried between `update` calls.
    partial: [u8; BLOCK_BYTES],
    /// How many bytes of `partial` are occupied.
    partial_length: usize,
}

impl Poly1305 {
    /// Starts a MAC under the one-time key `r = key[0..16]` (clamped),
    /// `s = key[16..32]`.
    #[must_use]
    pub fn new(key: &[u8; POLY1305_KEY_BYTES]) -> Self {
        let r = clamp_r(key);
        Self {
            r,
            r_times_five: [
                r[1].wrapping_mul(5),
                r[2].wrapping_mul(5),
                r[3].wrapping_mul(5),
                r[4].wrapping_mul(5),
            ],
            s: load_s(key),
            accumulator: [0u32; 5],
            partial: [0u8; BLOCK_BYTES],
            partial_length: 0,
        }
    }

    /// Absorbs message bytes, buffering across calls so the caller may hand
    /// over `enc_length` and `ciphertext` as two separate slices.
    pub fn update(&mut self, message: &[u8]) {
        let mut offset = self.fill_partial(message);
        while message.len().saturating_sub(offset) >= BLOCK_BYTES {
            let mut block = [0u8; BLOCK_BYTES];
            copy_from(&mut block, message, offset);
            self.absorb(&block, true);
            offset = offset.saturating_add(BLOCK_BYTES);
        }
        self.buffer_remainder(message, offset);
    }

    /// Produces the 16-byte tag.
    #[must_use]
    pub fn finalize(mut self) -> [u8; POLY1305_TAG_BYTES] {
        self.absorb_partial();
        self.carry_fully();
        let reduced = self.select_reduced();
        serialize(&reduced, &self.s)
    }

    /// Tops up a carried partial block from the head of `message`, absorbing it
    /// once full. Returns how many bytes of `message` were consumed.
    fn fill_partial(&mut self, message: &[u8]) -> usize {
        if self.partial_length == 0 {
            return 0;
        }
        let taken = BLOCK_BYTES
            .saturating_sub(self.partial_length)
            .min(message.len());
        copy_into(&mut self.partial, self.partial_length, message, taken);
        self.partial_length = self.partial_length.saturating_add(taken);
        if self.partial_length == BLOCK_BYTES {
            let block = self.partial;
            self.absorb(&block, true);
            self.partial_length = 0;
        }
        taken
    }

    /// Carries the tail of `message` into the partial buffer.
    fn buffer_remainder(&mut self, message: &[u8], offset: usize) {
        let remaining = message.len().saturating_sub(offset);
        if remaining == 0 {
            return;
        }
        let mut block = [0u8; BLOCK_BYTES];
        copy_from(&mut block, message, offset);
        self.partial = block;
        self.partial_length = remaining;
    }

    /// Absorbs the trailing partial block, if any, with the `0x01` marker.
    fn absorb_partial(&mut self) {
        if self.partial_length == 0 {
            return;
        }
        let occupied = self.partial_length.min(BLOCK_BYTES);
        let mut block = self.partial;
        if let Some(tail) = block.get_mut(occupied..) {
            tail.fill(0);
        }
        if let Some(marker) = block.get_mut(occupied) {
            *marker = 0x01;
        }
        self.absorb(&block, false);
        self.partial_length = 0;
    }

    /// `h = (h + block) · r mod 2^130 − 5` for one 16-byte block.
    ///
    /// `is_full` selects the `2^128` marker: a full block carries it beyond the
    /// 16 bytes, a partial block already has the `0x01` byte written just past
    /// its data.
    fn absorb(&mut self, block: &[u8; BLOCK_BYTES], is_full: bool) {
        let high_bit = if is_full { 1u32 << 24 } else { 0u32 };
        self.add_block(block, high_bit);
        let products = self.schoolbook();
        self.propagate(&products);
    }

    /// Repacks the block into 26-bit limbs and adds it to the accumulator.
    fn add_block(&mut self, block: &[u8; BLOCK_BYTES], high_bit: u32) {
        let words = load_block(block);
        let limbs = [
            words[0] & LIMB_MASK,
            ((words[0] >> 26) | (words[1] << 6)) & LIMB_MASK,
            ((words[1] >> 20) | (words[2] << 12)) & LIMB_MASK,
            ((words[2] >> 14) | (words[3] << 18)) & LIMB_MASK,
            (words[3] >> 8) | high_bit,
        ];
        for (accumulated, limb) in self.accumulator.iter_mut().zip(limbs.iter()) {
            *accumulated = accumulated.wrapping_add(*limb);
        }
    }

    /// The five 64-bit column sums of `h · r` with the `5·r_i` wrap-around.
    fn schoolbook(&self) -> [u64; 5] {
        let h = self.accumulator;
        let r = self.r;
        let five = self.r_times_five;
        [
            column(&h, &[r[0], five[3], five[2], five[1], five[0]]),
            column(&h, &[r[1], r[0], five[3], five[2], five[1]]),
            column(&h, &[r[2], r[1], r[0], five[3], five[2]]),
            column(&h, &[r[3], r[2], r[1], r[0], five[3]]),
            column(&h, &[r[4], r[3], r[2], r[1], r[0]]),
        ]
    }

    /// Reduces the five column sums back into 26-bit limbs.
    fn propagate(&mut self, products: &[u64; 5]) {
        let mut carry = 0u64;
        for (limb, product) in self.accumulator.iter_mut().zip(products.iter()) {
            let total = product.wrapping_add(carry);
            carry = total >> 26;
            *limb = (total as u32) & LIMB_MASK;
        }
        self.fold_carry(carry as u32);
    }

    /// `h_0 += 5·carry`, then spill `h_0`'s overflow into `h_1`.
    fn fold_carry(&mut self, carry: u32) {
        let folded = self.accumulator[0].wrapping_add(carry.wrapping_mul(5));
        self.accumulator[0] = folded & LIMB_MASK;
        self.accumulator[1] = self.accumulator[1].wrapping_add(folded >> 26);
    }

    /// The final carry pass, from limb 1 upward, before the conditional
    /// subtraction.
    fn carry_fully(&mut self) {
        let mut carry = 0u32;
        for limb in self.accumulator.iter_mut().skip(1) {
            let total = limb.wrapping_add(carry);
            carry = total >> 26;
            *limb = total & LIMB_MASK;
        }
        self.fold_carry(carry);
    }

    /// Constant-time select between `h` and `h − p`.
    ///
    /// `mask` is all-ones exactly when `h ≥ p`. Both candidates are computed
    /// and the choice is an arithmetic mask, so no branch observes `h`.
    fn select_reduced(&self) -> [u32; 5] {
        let candidate = subtract_p(&self.accumulator);
        let mask = (candidate[4] >> 31).wrapping_sub(1);
        let keep = !mask;
        let mut chosen = [0u32; 5];
        for (position, slot) in chosen.iter_mut().enumerate() {
            let unreduced = self.accumulator.get(position).copied().unwrap_or(0);
            let reduced = candidate.get(position).copied().unwrap_or(0);
            *slot = (unreduced & keep) | (reduced & mask);
        }
        chosen
    }
}

/// `h + 5` propagated across the low four limbs, then `− 2^130` in the top
/// limb. The top limb's sign bit is set exactly when `h < p`.
fn subtract_p(accumulator: &[u32; 5]) -> [u32; 5] {
    let mut candidate = *accumulator;
    let mut carry = 5u32;
    for slot in candidate.iter_mut().take(4) {
        let total = slot.wrapping_add(carry);
        carry = total >> 26;
        *slot = total & LIMB_MASK;
    }
    candidate[4] = candidate[4].wrapping_add(carry).wrapping_sub(1 << 26);
    candidate
}

/// One column of the schoolbook product, widened to 64 bits.
fn column(accumulated: &[u32; 5], multipliers: &[u32; 5]) -> u64 {
    let mut total = 0u64;
    for (limb, multiplier) in accumulated.iter().zip(multipliers.iter()) {
        total = total.wrapping_add(u64::from(*limb).wrapping_mul(u64::from(*multiplier)));
    }
    total
}

/// `r`, clamped per RFC 8439, in five 26-bit limbs.
fn clamp_r(key: &[u8; POLY1305_KEY_BYTES]) -> [u32; 5] {
    [
        load_le32(key, 0) & 0x3ff_ffff,
        (load_le32(key, 3) >> 2) & 0x3ff_ff03,
        (load_le32(key, 6) >> 4) & 0x3ff_c0ff,
        (load_le32(key, 9) >> 6) & 0x3f0_3fff,
        (load_le32(key, 12) >> 8) & 0x00f_ffff,
    ]
}

/// `s = key[16..32]` as four little-endian words.
fn load_s(key: &[u8; POLY1305_KEY_BYTES]) -> [u32; 4] {
    [
        load_le32(key, 16),
        load_le32(key, 20),
        load_le32(key, 24),
        load_le32(key, 28),
    ]
}

/// The block as four little-endian words.
fn load_block(block: &[u8; BLOCK_BYTES]) -> [u32; 4] {
    [
        load_le32(block, 0),
        load_le32(block, 4),
        load_le32(block, 8),
        load_le32(block, 12),
    ]
}

/// A little-endian `u32` at `offset`, or zero if it does not fit — total by
/// construction, so no index can panic.
fn load_le32(bytes: &[u8], offset: usize) -> u32 {
    let end = offset.saturating_add(4);
    match bytes.get(offset..end) {
        Some([first, second, third, fourth]) => {
            u32::from_le_bytes([*first, *second, *third, *fourth])
        }
        // COVERAGE-EXEMPT: load_le32 is only called on 16-byte-aligned offsets within a block whose length was already checked, so the 4-byte slice always matches. Returning 0 keeps it total instead of indexing.
        _ => 0,
    }
}

/// Copies up to one block out of `message` at `offset`, zero-filling the rest.
fn copy_from(block: &mut [u8; BLOCK_BYTES], message: &[u8], offset: usize) {
    let take = message.len().saturating_sub(offset).min(BLOCK_BYTES);
    let end = offset.saturating_add(take);
    if let (Some(destination), Some(source)) = (block.get_mut(..take), message.get(offset..end)) {
        destination.copy_from_slice(source);
    }
}

/// Copies `count` bytes from the head of `message` into `block` at `at`.
fn copy_into(block: &mut [u8; BLOCK_BYTES], at: usize, message: &[u8], count: usize) {
    let end = at.saturating_add(count);
    if let (Some(destination), Some(source)) = (block.get_mut(at..end), message.get(..count)) {
        destination.copy_from_slice(source);
    }
}

/// Serializes `h mod 2^128` and adds `s`, little-endian.
fn serialize(limbs: &[u32; 5], s: &[u32; 4]) -> [u8; POLY1305_TAG_BYTES] {
    let packed = [
        limbs[0] | (limbs[1] << 26),
        (limbs[1] >> 6) | (limbs[2] << 20),
        (limbs[2] >> 12) | (limbs[3] << 14),
        (limbs[3] >> 18) | (limbs[4] << 8),
    ];
    let mut tag = [0u8; POLY1305_TAG_BYTES];
    let mut carry = 0u64;
    for (position, word) in packed.iter().enumerate() {
        let addend = u64::from(s.get(position).copied().unwrap_or(0));
        let sum = u64::from(*word).wrapping_add(addend).wrapping_add(carry);
        carry = sum >> 32;
        write_le32(&mut tag, position, sum as u32);
    }
    tag
}

/// Writes `value` little-endian into word slot `position` of `tag`.
fn write_le32(tag: &mut [u8; POLY1305_TAG_BYTES], position: usize, value: u32) {
    let start = position.saturating_mul(4);
    let end = start.saturating_add(4);
    if let Some(destination) = tag.get_mut(start..end) {
        destination.copy_from_slice(&value.to_le_bytes());
    }
}

/// One-shot Poly1305 over a single contiguous message.
#[must_use]
pub fn poly1305_mac(key: &[u8; POLY1305_KEY_BYTES], message: &[u8]) -> [u8; POLY1305_TAG_BYTES] {
    let mut state = Poly1305::new(key);
    state.update(message);
    state.finalize()
}
