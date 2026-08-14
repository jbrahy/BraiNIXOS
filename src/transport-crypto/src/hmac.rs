//! HMAC-SHA256 (RFC 2104), the PRF every derivation in BSP v2 is built on.
//!
//! **In-tree, and it has to be.** `docs/NORTH_STAR.md` names SHA-256, HKDF,
//! ChaCha20, and Poly1305 as the crypto set; `sha2` and `chacha20` are vendored
//! and this crate consumes them. There is no vendored `hmac` and no vendored
//! `hkdf`, and P2-T2 may not add a dependency — so the HMAC construction and
//! the HKDF construction above it are written here, over the vendored SHA-256
//! compression function. That is the whole of the hand-written cryptography in
//! this module: **no hash function is reimplemented.**
//!
//! The construction is checked against RFC 4231 in `tests/known_answer.rs`, not
//! merely against itself.

use brainix_sha256::Sha256;

use crate::secret::Secret;

/// SHA-256's block size in bytes — HMAC's `B`.
pub const HMAC_BLOCK_BYTES: usize = 64;

/// SHA-256's output size in bytes — HMAC's `L`, and every PRK width here.
pub const HMAC_OUTPUT_BYTES: usize = 32;

/// RFC 2104's inner padding byte.
const INNER_PAD: u8 = 0x36;

/// RFC 2104's outer padding byte.
const OUTER_PAD: u8 = 0x5c;

/// A streaming HMAC-SHA256 over a key that is held as a [`Secret`].
///
/// The key-derived pads are zeroized when the value is dropped, including on
/// the path where a derivation fails partway.
pub struct HmacSha256 {
    /// `K0 ^ opad`, retained until finalization. Key-derived, so it is a
    /// [`Secret`].
    outer_pad: Secret<HMAC_BLOCK_BYTES>,
    /// The inner hash, already primed with `K0 ^ ipad`.
    inner: Sha256,
}

impl HmacSha256 {
    /// Starts an HMAC under `key`.
    ///
    /// Keys longer than [`HMAC_BLOCK_BYTES`] are hashed first, per RFC 2104.
    /// No key in BSP v2 reaches that branch — every one is a 16-byte label or a
    /// 32-byte PRK — but the branch exists so the RFC 4231 vectors that
    /// exercise it can be run, and a construction checked only on the inputs it
    /// happens to receive is a construction that has not been checked.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let key_block = normalize_key(key);
        let mut inner = Sha256::new();
        inner.update(xor_pad(&key_block, INNER_PAD).expose());
        Self {
            outer_pad: xor_pad(&key_block, OUTER_PAD),
            inner,
        }
    }

    /// Absorbs message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Produces the 32-byte tag and destroys the key-derived pads.
    #[must_use]
    pub fn finalize(mut self) -> [u8; HMAC_OUTPUT_BYTES] {
        let inner_digest = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(self.outer_pad.expose());
        outer.update(&inner_digest);
        self.outer_pad.zeroize();
        outer.finalize()
    }
}

/// RFC 2104's `K0`: the key, hashed if it is longer than a block, then
/// right-padded with zeros to exactly one block.
fn normalize_key(key: &[u8]) -> Secret<HMAC_BLOCK_BYTES> {
    let mut block = Secret::<HMAC_BLOCK_BYTES>::zero();
    if key.len() > HMAC_BLOCK_BYTES {
        let digest: [u8; HMAC_OUTPUT_BYTES] = brainix_sha256::digest(key);
        block.expose_mut()[..HMAC_OUTPUT_BYTES].copy_from_slice(&digest);
    } else {
        block.expose_mut()[..key.len()].copy_from_slice(key);
    }
    block
}

/// `K0 ^ pad`, as its own [`Secret`] so both pads are tracked and destroyed.
fn xor_pad(key_block: &Secret<HMAC_BLOCK_BYTES>, pad: u8) -> Secret<HMAC_BLOCK_BYTES> {
    let mut padded = Secret::<HMAC_BLOCK_BYTES>::zero();
    for (destination, source) in padded
        .expose_mut()
        .iter_mut()
        .zip(key_block.expose().iter())
    {
        *destination = source ^ pad;
    }
    padded
}

/// One-shot HMAC-SHA256 over a single contiguous message.
#[must_use]
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; HMAC_OUTPUT_BYTES] {
    let mut state = HmacSha256::new(key);
    state.update(message);
    state.finalize()
}
