//! §5.2 enrollment, §5.3 blinded identification, and the fixed credential
//! table.
//!
//! # §5.2 — derivation, once, at enrollment
//!
//! ```text
//! PRK_enroll = HKDF-Extract(salt = LABEL_ENROLL_SALT, ikm = key_material[32])
//! handle     = HKDF-Expand(PRK_enroll, LABEL_KEY_HANDLE || role, 16)
//! K_id       = HKDF-Expand(PRK_enroll, LABEL_KEY_ID     || role, 32)
//! CK_0       = HKDF-Expand(PRK_enroll, LABEL_CHAIN_INIT || role, 32)
//! zeroize(key_material, PRK_enroll)
//! ```
//!
//! **The enrolled 32 bytes are destroyed on both ends**, which is why
//! [`Credential::enroll`] takes them by `&mut` and zeroizes the caller's array
//! rather than borrowing them. §5.2: "This is load-bearing for §6: if the root
//! were retained, every past chain key would be recomputable from it by
//! re-running the ratchet, and the ratchet would buy nothing."
//!
//! # §5.3 — identifying the credential without leaking it
//!
//! ```text
//! PRK_id       = HKDF-Extract(salt = LABEL_ID_SALT, ikm = K_id)         # precomputable
//! key_selector = HKDF-Expand(PRK_id, LABEL_SELECTOR || chain_counter || client_nonce, 16)
//! ```
//!
//! **`K_id` is not retained.** §5.3 calls `PRK_id` precomputable and rests the
//! §5.7/§8 DoS arithmetic on it being precomputed, and `PRK_id` is a one-way
//! function of `K_id`, so a store that keeps only `PRK_id` yields strictly less
//! to a compromise than one that keeps both. Nothing in the protocol needs
//! `K_id` after this `Extract`. This is a deviation from §2.2's description of
//! a credential record, in the safe direction, and it is reported as one.
//!
//! # The scan is constant work and constant time
//!
//! [`CredentialTable::scan`] computes a candidate selector for **every** slot,
//! compares constant-time, accumulates the match with a constant-time select,
//! and never breaks early. Empty slots hold a per-boot random `PRK_id` so their
//! iteration is indistinguishable in work and timing from an occupied one, and
//! the matched credential's material is **copied out by constant-time select
//! over all slots** rather than by indexing the table with the matched index —
//! an index-dependent load is a cache-timing signal, and §5.3 requires that
//! "neither the matching slot's index nor the presence of a match is
//! timing-visible".
//!
//! The price is a fixed `MAX_ENROLLED_KEYS × 5` SHA-256 compressions per
//! `ClientHello` (§5.3 derives the multiplier). It is a `const` an attacker
//! cannot steer, and §5.7 names it as the standing cost of blinded lookup.

use brainix_bsp::{
    ClientHello, CredentialRole, LEN_CHAIN_KEY, LEN_HANDLE, LEN_KEY_ID, LEN_NONCE, LEN_PSK,
    LEN_SELECTOR, MAX_ENROLLED_KEYS,
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::error::TransportCryptoError;
use crate::hkdf::{expand, extract};
use crate::labels::{
    info_label_role, info_selector, LABEL_CHAIN_INIT, LABEL_ENROLL_SALT, LABEL_ID_SALT,
    LABEL_KEY_HANDLE, LABEL_KEY_ID,
};
use crate::ratchet::{ChainKey, ChainState, ScratchChain};
use crate::secret::Secret;

/// `flags` bit 0 — the break-glass credential (§2.5).
///
/// A `ClientHello` whose selector matches a record with this bit set is refused
/// **before any chain resolution runs** (§12 row K5). The break-glass
/// credential authenticates on the serial transport only; on this listener it
/// is never accepted, whatever else is well-formed.
pub const FLAG_BREAK_GLASS: u8 = 0b0000_0001;

/// One enrolled credential.
///
/// Holds `handle`, `PRK_id`, the chain state, the role, and the flags. It does
/// **not** hold the enrolled key material (destroyed at §5.2) or `K_id` (see
/// the module documentation).
pub struct Credential {
    handle: [u8; LEN_HANDLE],
    identity_prk: Secret<LEN_KEY_ID>,
    chain: ChainState,
    role: CredentialRole,
    flags: u8,
    occupied: bool,
}

/// The material the §5.3 scan hands to the handshake, copied out of the table
/// in constant time.
///
/// The chain key is a **clone** of the table's, so the handshake can resolve
/// and derive without holding a borrow on the table across the whole exchange;
/// its `Drop` destroys the clone.
pub struct MatchedCredential {
    /// Which slot matched. Server-internal, and never on the wire.
    pub slot: usize,
    /// The credential's administrative handle (§2.2).
    pub handle: [u8; LEN_HANDLE],
    /// The credential's role, as its §10.4 wire byte — the value bound into
    /// every §5.4 `info`.
    pub role: u8,
    /// The credential's persisted chain position `s`.
    pub chain_counter: u64,
    /// A copy of the credential's persisted chain key `CK_s`.
    pub chain_key: ChainKey,
}

impl Credential {
    /// Runs §5.2 over 32 bytes of enrolled key material and **destroys them**.
    ///
    /// `key_material` is zeroized before this function returns, on every path.
    /// The caller cannot opt out, because the parameter is `&mut` rather than
    /// `&`: there is no signature through which the material survives the call.
    #[must_use]
    pub fn enroll(key_material: &mut [u8; LEN_PSK], role: CredentialRole, flags: u8) -> Self {
        let role_byte = role.to_wire();
        let enroll_prk = extract(&LABEL_ENROLL_SALT, key_material);
        key_material.fill(0);
        let handle =
            expand::<LEN_HANDLE>(&enroll_prk, &info_label_role(&LABEL_KEY_HANDLE, role_byte));
        let key_id = expand::<LEN_KEY_ID>(&enroll_prk, &info_label_role(&LABEL_KEY_ID, role_byte));
        let chain_key =
            expand::<LEN_CHAIN_KEY>(&enroll_prk, &info_label_role(&LABEL_CHAIN_INIT, role_byte));
        Self {
            handle: *handle.expose(),
            identity_prk: extract(&LABEL_ID_SALT, key_id.expose()),
            chain: ChainState::new(chain_key),
            role,
            flags,
            occupied: true,
        }
    }

    /// An unoccupied slot whose `PRK_id` is derived from per-boot random bytes.
    ///
    /// §5.3 requires this: an empty slot that skipped its derivation would make
    /// the table's occupancy readable from the timing of a single
    /// `ClientHello`.
    #[must_use]
    pub fn empty(filler: &[u8; LEN_KEY_ID]) -> Self {
        Self {
            handle: [0u8; LEN_HANDLE],
            identity_prk: extract(&LABEL_ID_SALT, filler),
            chain: ChainState::new(Secret::zero()),
            role: CredentialRole::Client,
            flags: 0,
            occupied: false,
        }
    }

    /// The credential's administrative handle (§2.2), never sent pre-key.
    #[must_use]
    pub const fn handle(&self) -> &[u8; LEN_HANDLE] {
        &self.handle
    }

    /// The credential's role.
    #[must_use]
    pub const fn role(&self) -> CredentialRole {
        self.role
    }

    /// Whether this slot holds an enrolled credential.
    ///
    /// **Not consulted by the scan** — see the module documentation.
    #[must_use]
    pub const fn is_occupied(&self) -> bool {
        self.occupied
    }

    /// The persisted chain position.
    #[must_use]
    pub const fn chain_counter(&self) -> u64 {
        self.chain.counter()
    }

    /// The persisted chain state, for §6.2's commit.
    pub const fn chain_mut(&mut self) -> &mut ChainState {
        &mut self.chain
    }

    /// A scratch copy of the chain at its current position — the client's
    /// derivation source (§6.3).
    #[must_use]
    pub fn scratch(&self) -> ScratchChain {
        self.chain.scratch()
    }

    /// §5.3's candidate selector for this slot.
    ///
    /// One `HKDF-Expand` with `L = 16` over a 56-byte `info`, which §5.3
    /// derives as five SHA-256 compressions.
    #[must_use]
    pub fn candidate_selector(
        &self,
        chain_counter: u64,
        client_nonce: &[u8; LEN_NONCE],
    ) -> Secret<LEN_SELECTOR> {
        expand::<LEN_SELECTOR>(
            &self.identity_prk,
            &info_selector(chain_counter, client_nonce),
        )
    }

    /// Destroys everything secret in the slot and marks it free — revocation
    /// (§10.4) and teardown.
    pub fn revoke(&mut self) {
        self.identity_prk.zeroize();
        self.chain.zeroize();
        self.handle.fill(0);
        self.occupied = false;
        self.flags = 0;
    }
}

/// The fixed credential table: exactly [`MAX_ENROLLED_KEYS`] slots, in BSS.
///
/// Never grown, never indexed by a client-supplied value, and never iterated a
/// client-dependent number of times.
pub struct CredentialTable {
    slots: [Credential; MAX_ENROLLED_KEYS],
}

impl CredentialTable {
    /// An empty table whose slots hold per-boot random `PRK_id` material.
    ///
    /// `filler` must come from the kernel CSPRNG after entropy initialization
    /// (`INV-BOOT-005`). It is consumed by `&mut` and zeroized, for the same
    /// reason enrolled material is.
    #[must_use]
    pub fn new(filler: &mut [[u8; LEN_KEY_ID]; MAX_ENROLLED_KEYS]) -> Self {
        const NO_FILLER: [u8; LEN_KEY_ID] = [0u8; LEN_KEY_ID];
        let slots = core::array::from_fn(|position| {
            Credential::empty(filler.get(position).unwrap_or(&NO_FILLER))
        });
        for bytes in filler.iter_mut() {
            bytes.fill(0);
        }
        Self { slots }
    }

    /// Borrows a slot.
    #[must_use]
    pub fn slot(&self, index: usize) -> Option<&Credential> {
        self.slots.get(index)
    }

    /// Borrows a slot mutably — for §6.2's commit and for revocation.
    pub fn slot_mut(&mut self, index: usize) -> Option<&mut Credential> {
        self.slots.get_mut(index)
    }

    /// Installs a credential in the lowest free slot (§12 row A2).
    pub fn insert(&mut self, credential: Credential) -> Result<usize, TransportCryptoError> {
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if !slot.is_occupied() {
                *slot = credential;
                return Ok(index);
            }
        }
        Err(TransportCryptoError::CredentialTableFull)
    }

    /// §5.3's constant-work scan, and §12 rows K1, K2, and K5.
    ///
    /// Runs all [`MAX_ENROLLED_KEYS`] iterations regardless of when a match
    /// occurs, accumulates the match with constant-time selects, and only then
    /// decides:
    ///
    /// - exactly one match, not break-glass ⇒ the credential;
    /// - zero matches ⇒ [`TransportCryptoError::NoCredentialMatch`] (row K1);
    /// - two or more ⇒ [`TransportCryptoError::AmbiguousCredentialMatch`] (row K2);
    /// - break-glass ⇒ [`TransportCryptoError::BreakGlassCredentialRefused`]
    ///   (row K5), checked **immediately** after the match so no later step can
    ///   be reached with that credential.
    ///
    /// The three final comparisons are on accumulated counts and flags, not on
    /// which slot matched, so the branch they take is uniform in the table's
    /// contents.
    pub fn scan(&self, hello: &ClientHello) -> Result<MatchedCredential, TransportCryptoError> {
        let mut accumulator = ScanAccumulator::new();
        for (index, slot) in self.slots.iter().enumerate() {
            let candidate = slot.candidate_selector(hello.chain_counter, &hello.client_nonce);
            let is_match = candidate.expose().ct_eq(&hello.key_selector);
            accumulator.absorb(index, slot, is_match);
        }
        accumulator.finish()
    }
}

/// The constant-time accumulator of a scan.
///
/// Every field is written on every iteration, under a [`Choice`], so the
/// sequence of stores does not depend on which slot matched.
struct ScanAccumulator {
    matches: u8,
    slot: u32,
    handle: [u8; LEN_HANDLE],
    role: u8,
    flags: u8,
    chain_counter: u64,
    chain_key: ChainKey,
}

impl ScanAccumulator {
    fn new() -> Self {
        Self {
            matches: 0,
            slot: 0,
            handle: [0u8; LEN_HANDLE],
            role: 0,
            flags: 0,
            chain_counter: 0,
            chain_key: Secret::zero(),
        }
    }

    /// Folds one slot in, taking its material only when `is_match` is set.
    fn absorb(&mut self, index: usize, slot: &Credential, is_match: Choice) {
        self.matches
            .conditional_assign(&self.matches.wrapping_add(1), is_match);
        let position = u32::try_from(index).unwrap_or(u32::MAX);
        self.slot.conditional_assign(&position, is_match);
        for (destination, source) in self.handle.iter_mut().zip(slot.handle.iter()) {
            destination.conditional_assign(source, is_match);
        }
        self.role.conditional_assign(&slot.role.to_wire(), is_match);
        self.flags.conditional_assign(&slot.flags, is_match);
        self.chain_counter
            .conditional_assign(&slot.chain.counter(), is_match);
        self.chain_key
            .conditional_assign(slot.chain_key(), is_match);
    }

    /// Rows K1, K2, and K5, in that order.
    fn finish(self) -> Result<MatchedCredential, TransportCryptoError> {
        if self.matches == 0 {
            return Err(TransportCryptoError::NoCredentialMatch);
        }
        if self.matches > 1 {
            return Err(TransportCryptoError::AmbiguousCredentialMatch);
        }
        if self.flags & FLAG_BREAK_GLASS != 0 {
            return Err(TransportCryptoError::BreakGlassCredentialRefused);
        }
        Ok(MatchedCredential {
            slot: usize::try_from(self.slot).unwrap_or(usize::MAX),
            handle: self.handle,
            role: self.role,
            chain_counter: self.chain_counter,
            chain_key: self.chain_key,
        })
    }
}

impl Credential {
    /// The persisted chain key, for the scan's constant-time copy-out.
    fn chain_key(&self) -> &ChainKey {
        self.chain.key()
    }
}
