//! The single failure enum for the BSP v2 transport cryptography.
//!
//! # The one rule that shapes this enum
//!
//! **Every authentication failure is [`TransportCryptoError::AuthenticationFailed`],
//! and nothing else is.** A Poly1305 tag mismatch, a record at the wrong
//! sequence, a `packet_length` that decrypted out of range, a padding field the
//! sender could not have produced, a `client_confirm` mismatch (§12 row H5) and
//! a `server_confirm` mismatch (row H6) all return the *same* variant with no
//! payload. A caller cannot distinguish them, cannot log which one occurred, and
//! therefore cannot build the oracle that logging them would be.
//!
//! §12 row H5 states the property for the peer — "the failure is
//! indistinguishable from H4 to the peer" — and this enum extends it to the
//! process boundary, because an audit line that says *why* a record failed to
//! authenticate is an oracle with a timestamp on it.
//!
//! The cost is stated: a genuine interoperability bug in the record layer is
//! harder to diagnose from a log, because the log says only that authentication
//! failed. That is the correct trade for the only authenticated path into the
//! system, and the test suite — not the log — is where the distinctions live.
//!
//! # What is *not* folded in
//!
//! Failures that a passive peer already knows the answer to, or that no
//! attacker choice influences, keep their own variants: the credential-table
//! outcomes of rows K1/K2/K5, the chain-position outcomes of rows K3/K4, the
//! sequence ceiling of row R5, and structural faults the P2-T3 decoder already
//! reported. Every one of these is a **Drop** in §12 exactly as
//! `AuthenticationFailed` is, so the peer's observation is identical in every
//! case; the distinction exists only for the server's own audit record
//! (§9.5), which §5.3 explicitly requires to report a desynchronized client
//! "rather than presenting as an unknown peer".

use brainix_bsp::BspError;

/// Every way a BSP v2 transport-cryptography operation can fail.
///
/// Deliberately not `#[non_exhaustive]`: callers inside BraiNIX match
/// exhaustively so a newly added failure mode is a compile error rather than a
/// silent wildcard arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportCryptoError {
    /// **The single authentication failure.** §12 rows R1, R2, R3, H5, and H6.
    ///
    /// Carries nothing. Returned identically for a forged tag, a replayed or
    /// reordered record, a `packet_length` that decrypted outside
    /// `[2, 35000]`, a record plaintext whose padding violates §4.2, a
    /// `client_confirm` that did not match, and a `server_confirm` that did not
    /// match.
    ///
    /// The §12 action is **Drop** in every case: terminate the connection,
    /// release the slot, zeroize its key material and any scratch chain
    /// material, and commit no chain advance.
    AuthenticationFailed,

    /// The stream does not yet hold a whole record. **Not a failure.**
    ///
    /// The caller reads more bytes and retries. This is distinguishable from
    /// [`TransportCryptoError::AuthenticationFailed`] and that is unavoidable:
    /// §4.2 makes the `packet_length` range check normative *before* the tag
    /// check, so a peer necessarily learns whether its four bytes decrypted
    /// into range. See the crate documentation's "Residual observables".
    RecordIncomplete,

    /// The caller's output buffer is smaller than the operation needs.
    ///
    /// A programming fault on this side of the wire, never a peer's doing:
    /// every buffer this crate needs has a `const` size.
    OutputBufferTooSmall,

    /// Row R4 — a payload larger than
    /// [`BSP_MAX_RECORD_PLAINTEXT`](brainix_bsp::BSP_MAX_RECORD_PLAINTEXT) was
    /// offered to the sealer.
    PayloadExceedsRecordPlaintext,

    /// Row R5 — the sequence would exceed
    /// [`MAX_RECORD_SEQ`](brainix_bsp::MAX_RECORD_SEQ). The session is torn
    /// down (§9.4) rather than reusing a nonce.
    SequenceExhausted,

    /// Row K1 — the `key_selector` matched no enrolled credential.
    ///
    /// The scan ran all [`MAX_ENROLLED_KEYS`](brainix_bsp::MAX_ENROLLED_KEYS)
    /// slots before producing this, exactly as it does for a match.
    NoCredentialMatch,

    /// Row K2 — the `key_selector` matched two or more credentials.
    ///
    /// A 16-byte collision is a `2^-128`-scale event per pair; §5.3 treats it
    /// as an attack because doing so costs nothing and avoids an arbitrary
    /// choice between the two.
    AmbiguousCredentialMatch,

    /// Row K5 — the selector matched the **break-glass** credential.
    ///
    /// Refused unconditionally and before any chain resolution: the
    /// break-glass credential authenticates on the serial transport only
    /// (§2.5, §6.5).
    BreakGlassCredentialRefused,

    /// Row K3 — `chain_counter` is behind the server's persisted position.
    ///
    /// The chain is one-way and the server cannot go back. Recovery is §6.4 —
    /// re-enrollment — and is **never** a fallback key.
    ChainDesynchronized,

    /// Row K4 — `chain_counter` exceeds the persisted position by more than
    /// [`MAX_CHAIN_CATCHUP`](brainix_bsp::MAX_CHAIN_CATCHUP).
    ChainCounterTooFarAhead,

    /// A `chain_counter` at `u64::MAX`, where the catch-up bound cannot be
    /// computed without wrapping.
    ///
    /// Denied rather than saturated: a saturating bound would silently accept
    /// a position the comparison was meant to reject.
    ChainCounterOverflow,

    /// The credential table has no free slot (§12 row A2).
    CredentialTableFull,

    /// An operation was attempted in a handshake state that does not permit it.
    ///
    /// Distinct from the P2-T3 decoder's own state guard: this one covers the
    /// *cryptographic* half — asking for session keys before `ServerHello` was
    /// produced, for instance.
    WrongState,

    /// The P2-T3 decoder denied the bytes before any key material was touched.
    ///
    /// Carries the structural reason (rows H1, H2, H4, R1's framing half) so
    /// the audit record can name it. Nothing here is an authentication
    /// outcome — the bytes never reached a comparison against key material.
    Wire(BspError),
}

impl From<BspError> for TransportCryptoError {
    fn from(error: BspError) -> Self {
        Self::Wire(error)
    }
}
