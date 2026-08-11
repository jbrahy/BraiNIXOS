//! §6 — the session-key ratchet.
//!
//! ```text
//! PRK_step = HKDF-Extract(salt = LABEL_CHAIN_SALT, ikm = CK_n)
//! CK_{n+1} = HKDF-Expand(PRK_step, LABEL_CHAIN_STEP, 32)
//! zeroize(CK_n, PRK_step)
//! ```
//!
//! This is the mechanism that recovers forward secrecy from symmetric
//! primitives alone (`INV-BOOT-007`). It buys nothing unless the old key is
//! actually gone — §5.6h: "Once the ratchet ships, `CK_m` is zeroized after use
//! and one-wayness of HKDF makes it unrecoverable from `CK_{m+1}`, so recorded
//! traffic stops being retrospectively readable." Every advance in this module
//! therefore ends in a [`Secret::zeroize`](crate::Secret::zeroize) call that is
//! not merely a `Drop`.
//!
//! # Two orderings that are load-bearing, not optimizations
//!
//! **Resolution is uncommitted.** [`ChainState::resolve`] walks forward into
//! *scratch* and never touches the persisted state. §6.2: "If an unauthenticated
//! peer could advance the persisted chain by replaying a captured `ClientHello`,
//! it could push the server's chain arbitrarily far forward and lock the
//! legitimate client out permanently, without ever holding the credential."
//! That is the difference between a ratchet and a remote kill switch.
//!
//! **The commit is a monotonic compare-and-swap.** [`ChainState::commit`] takes
//! effect only if the new position is strictly greater than the persisted one.
//! `MAX_SESSIONS_PER_CREDENTIAL` permits two concurrent handshakes under one
//! credential; they may resolve from different positions and complete in either
//! order, and without the compare-and-swap the later commit could move the
//! persisted counter **backwards** and reinstate a chain key the server had
//! already advanced past. §6.2 names that a direct violation of
//! `INV-BOOT-007`, "not conditional on exploitability".

use brainix_bsp::{LEN_CHAIN_KEY, MAX_CHAIN_CATCHUP};

use crate::error::TransportCryptoError;
use crate::hkdf::{expand, extract};
use crate::labels::{LABEL_CHAIN_SALT, LABEL_CHAIN_STEP};
use crate::secret::Secret;

/// A chain key `CK_n`.
pub type ChainKey = Secret<LEN_CHAIN_KEY>;

/// §6.1's single advance: `CK_n → CK_{n+1}`.
///
/// `PRK_step` is a local [`Secret`] and is destroyed when this function
/// returns, which is `zeroize(PRK_step)`. Destroying `CK_n` is the caller's,
/// because only the caller knows whether its copy is the persisted one or a
/// scratch one — [`ChainState::commit`] and [`ScratchChain::advance`] each do
/// it explicitly.
#[must_use]
pub fn advance_key(current: &ChainKey) -> ChainKey {
    let step_prk = extract(&LABEL_CHAIN_SALT, current.expose());
    expand::<LEN_CHAIN_KEY>(&step_prk, &LABEL_CHAIN_STEP)
}

/// The persisted `(CK_n, n)` of one credential.
///
/// Both ends hold one of these (§6.3). The client sends `n` as `chain_counter`
/// and derives from `CK_n`; the server compares the received `n` against its
/// own position.
pub struct ChainState {
    key: ChainKey,
    counter: u64,
}

/// A chain position resolved into scratch, uncommitted.
///
/// Dropping one destroys its key. §6.2: "Until then the derived material lives
/// in scratch that teardown zeroizes", and "Each session zeroizes its own
/// scratch copy at teardown, whether or not its commit won."
pub struct ScratchChain {
    key: ChainKey,
    counter: u64,
}

impl ChainState {
    /// The initial state `(CK_0, 0)` from §5.2's enrollment.
    #[must_use]
    pub const fn new(chain_key: ChainKey) -> Self {
        Self {
            key: chain_key,
            counter: 0,
        }
    }

    /// A state at a known position — for restoring persisted credential-store
    /// state at boot, and for reaching the §6.3 boundaries in tests without
    /// `MAX_CHAIN_CATCHUP` real advances.
    #[must_use]
    pub const fn at(chain_key: ChainKey, counter: u64) -> Self {
        Self {
            key: chain_key,
            counter,
        }
    }

    /// The persisted position `n`.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// The persisted key `CK_n`.
    ///
    /// Borrowed, never copied out: the §5.3 scan's constant-time select reads
    /// through this and the handshake clones only the slot that matched.
    #[must_use]
    pub const fn key(&self) -> &ChainKey {
        &self.key
    }

    /// §6.3 — resolves the position the client declared, **into scratch**.
    ///
    /// | Relation | Action |
    /// |---|---|
    /// | `n == s` | clone `CK_s` |
    /// | `s < n ≤ s + MAX_CHAIN_CATCHUP` | `n − s` advances in scratch |
    /// | `n > s + MAX_CHAIN_CATCHUP` | [`TransportCryptoError::ChainCounterTooFarAhead`] (row K4) |
    /// | `n < s` | [`TransportCryptoError::ChainDesynchronized`] (row K3) |
    ///
    /// The `n < s` case is §6.4's desynchronization: the chain is one-way and
    /// the server cannot go back. It fails closed. **There is no fallback to an
    /// un-ratcheted key and there MUST never be one**, because a fallback any
    /// failure can trigger is a downgrade any attacker can trigger. Recovery is
    /// re-enrollment over the admin channel, or the serial console.
    ///
    /// Branching on `requested` is safe: `chain_counter` is plaintext on the
    /// wire (§5.7 names it a metadata leak), so its value is already public.
    pub fn resolve(&self, requested: u64) -> Result<ScratchChain, TransportCryptoError> {
        let distance = self.catch_up_distance(requested)?;
        let mut scratch = self.scratch();
        let mut walked = 0u64;
        while walked < distance {
            let _retired = scratch.advance();
            walked = walked.saturating_add(1);
        }
        Ok(scratch)
    }

    /// A scratch copy at this exact position, with no advance.
    ///
    /// The client's derivation source: §6.3 has the client derive from `CK_n`
    /// at the position it declares, so it never walks forward at all.
    #[must_use]
    pub fn scratch(&self) -> ScratchChain {
        ScratchChain {
            key: self.key.clone(),
            counter: self.counter,
        }
    }

    /// Rows K3 and K4 — how many advances the request costs, or a denial.
    fn catch_up_distance(&self, requested: u64) -> Result<u64, TransportCryptoError> {
        if requested < self.counter {
            return Err(TransportCryptoError::ChainDesynchronized);
        }
        let distance = requested
            .checked_sub(self.counter)
            .ok_or(TransportCryptoError::ChainDesynchronized)?;
        if distance > MAX_CHAIN_CATCHUP {
            return Err(TransportCryptoError::ChainCounterTooFarAhead);
        }
        Ok(distance)
    }

    /// §6.2 — the monotonic compare-and-swap commit.
    ///
    /// Advances `scratch` one step past the position the session derived from,
    /// and installs `(CK_{m+1}, m+1)` **only if `m + 1 > s_persisted`**.
    /// Returns whether the commit took effect. Either way the scratch material
    /// is destroyed: `scratch` is taken by value and its `Drop` zeroizes it,
    /// and the losing branch leaves the persisted state untouched.
    ///
    /// The old persisted key is zeroized explicitly before the new one is
    /// written, which is the whole of the forward-secrecy claim.
    pub fn commit(&mut self, mut scratch: ScratchChain) -> bool {
        let Some(position) = scratch.counter.checked_add(1) else {
            return false;
        };
        if position <= self.counter {
            return false;
        }
        let _retired = scratch.advance();
        self.key.zeroize();
        self.key = scratch.key.clone();
        self.counter = position;
        true
    }

    /// Destroys the persisted key — §9.4 teardown and revocation.
    pub fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ScratchChain {
    /// The chain key this session derives from, `CK_m`.
    #[must_use]
    pub const fn key(&self) -> &ChainKey {
        &self.key
    }

    /// The position this scratch sits at, `m`.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// One step forward, destroying the key it advanced past.
    ///
    /// Returns the buffer that held `CK_n`, **already zeroized**. Returning it
    /// is what makes §6.1's `zeroize(CK_n)` a testable fact rather than a
    /// claim: a test can assert the returned key is all zeros, and a mutation
    /// that drops the erasure fails that assertion. Callers that do not care
    /// discard it, and its `Drop` zeroizes again, which is idempotent.
    pub fn advance(&mut self) -> ChainKey {
        let next = advance_key(&self.key);
        let mut retired = core::mem::replace(&mut self.key, next);
        retired.zeroize();
        self.counter = self.counter.saturating_add(1);
        retired
    }
}

impl Drop for ScratchChain {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
