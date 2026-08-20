//! Kani proof harnesses for the BSP v2 transport cryptography
//! (`brainix-transport-crypto`).
//!
//! The key schedule and the record layer are the only authenticated path into
//! the system, and `RecordOpener::open` is the only code a remote peer reaches
//! after the handshake with every byte under its control except the key. The
//! crate is **Full tier** under `SECURITY_INVARIANTS.md` §16 ("Full tier covers
//! the TCB, every parser of hostile input, and all crypto"), and §15's
//! `INV-PARSE-002` requires both a fuzz target and a Kani harness.
//!
//! This crate follows the repository's convention that proofs live in a
//! dedicated verify crate beside the crate they verify, as `src/adt-verify/`
//! and `src/bsp-verify/` do. It adds no code to `brainix-transport-crypto` and
//! changes none.
//!
//! # The bounds, stated honestly
//!
//! Kani is a **bounded** model checker, and this crate's inputs are worse for
//! it than a plain parser's: a single `open` runs three ChaCha20 keystream
//! blocks and a Poly1305 over the record, and a single ratchet advance runs
//! four HMAC-SHA256 invocations. Two things keep the harnesses in reach, and
//! both are limitations that have to be named:
//!
//! - **The key is concrete.** [`DIRECTION_MATERIAL`] is a constant, so the
//!   keystream and the one-time MAC key are constant-foldable and only the
//!   *stream* is symbolic. This is the right threat model — a peer controls
//!   every byte except the key — but it means nothing here is proved *for all
//!   keys*.
//! - **The stream is short.** [`STREAM_LEN`] is 40 bytes: a 4-byte encrypted
//!   length, up to 20 ciphertext bytes, and a 16-byte tag. That is enough for a
//!   complete record whose plaintext is two §4.2 blocks, so the length check,
//!   the tag check, the decrypt, and the unpad are all reachable.
//!
//! **What remains unproven above the bounds**, named rather than implied:
//!
//! 1. **Nothing about a full-size record.** `BSP_MAX_RECORD_PLAINTEXT` is 4096
//!    and `RECORD_PLAINTEXT_CAPACITY` is 4352. The record harnesses say what
//!    they say about a 40-byte stream and no more. The large-payload paths are
//!    covered by the crate's `every_payload_length_across_the_padding_boundaries_round_trips`
//!    test and by the fuzz target's sealed-at-the-ceiling seeds.
//! 2. **The primitives are not verified here.** SHA-256 and ChaCha20 are
//!    vendored, and HMAC, HKDF and Poly1305 are in-tree; all five are pinned by
//!    the RFC known-answer tests in `tests/known_answer.rs`. These harnesses
//!    prove properties of the *protocol code around* them — bounds, ordering,
//!    monotonicity, totality — not the correctness of the primitives.
//! 3. **The catch-up walk is proved to a distance of two, not 64.**
//!    `MAX_CHAIN_CATCHUP` is 64, and 64 advances is 256 HMAC-SHA256
//!    invocations, which is out of reach. The *window* is proved unbounded for
//!    every `u64` pair by
//!    [`proofs::transport_crypto_ratchet_window_denies_outside_the_catch_up_bound`];
//!    what is bounded is only the walk that follows an accepted window.
//! 4. **The §5.3 credential scan is not proved.** One scan is
//!    `MAX_ENROLLED_KEYS × 5` SHA-256 compressions over 32 slots. It is fuzzed
//!    instead, with seeds whose `key_selector` genuinely matches an enrolled
//!    credential.
//!
//! # The cost bound: six harnesses are behind `long-proofs` and not in CI
//!
//! The bounds above were chosen to keep these harnesses "in reach". Measured,
//! they are not. Every harness in this crate was run on an M2 Pro with a
//! 700-second cap, and **six of the ten did not finish**:
//!
//! | Harness | Verdict |
//! |---|---|
//! | `record_open_never_panics_on_any_short_stream` | no verdict in 700s |
//! | `record_open_respects_the_caller_scratch_buffer` | no verdict in 700s |
//! | `record_seal_stays_within_the_caller_buffer` | no verdict in 700s |
//! | `ratchet_resolve_lands_at_the_declared_position` | no verdict in 700s |
//! | `ratchet_commit_advances_by_exactly_one` | no verdict in 700s |
//! | `ratchet_advance_is_monotone_and_erases_the_retired_key` | no verdict in 700s |
//! | [`proofs::transport_crypto_ratchet_window_denies_outside_the_catch_up_bound`] | **4.6s** |
//! | [`proofs::transport_crypto_ratchet_commit_refuses_to_move_backwards`] | passes |
//! | [`proofs::transport_crypto_constant_time_eq_agrees_with_equality`] | passes |
//! | [`proofs::transport_crypto_secret_compares_exactly_and_zeroizes_completely`] | passes |
//!
//! The six are exactly the harnesses that drive a **hash or an AEAD over
//! symbolic bytes**. A concrete key makes the keystream constant-foldable, but
//! Poly1305 over a symbolic stream, and HMAC-SHA256 over a chain key the
//! ratchet has already advanced once, are not; a concrete chain key did not
//! rescue the advance harness either. They are behind the `long-proofs`
//! feature, off by default.
//!
//! The four that remain are not a token set — the window proof quantifies over
//! **every** `u64` pair, and the two comparison proofs over every 16- and
//! 32-byte array — but what is **not** gated by CI is worth stating without
//! euphemism: **no proof of `open` or `seal` runs on a pull request.** The
//! record layer's protection on every commit is its tests, its RFC
//! known-answer vectors, and its fuzz target.
//!
//! Run the excluded set deliberately, with a long budget:
//!
//! ```text
//! cargo kani -p brainix-transport-crypto-verify --features long-proofs
//! ```
//!
//! # The constant-time tag comparison is **not** proved here, and why
//!
//! §4.2 row R2 requires the Poly1305 tag comparison to be constant-time, and
//! the task that produced this crate asked for that as a Kani property. **It is
//! not expressible as one, and it is not claimed.**
//!
//! Kani reduces a Rust program to a set of reachability queries over its
//! *values*: an assertion is discharged by showing no input makes it false.
//! Execution time is not a value in that model. There is no term a harness can
//! write that denotes "the number of cycles this comparison took", so there is
//! no assertion whose falsity would correspond to a timing leak. A harness that
//! appeared to prove constant-timeness would be proving something else —
//! typically that the two branches return the same *error variant*, which is a
//! real property but a different one, and stating it as a timing proof would be
//! the kind of overclaim this repository's proof tracker exists to prevent.
//!
//! What is proved here instead is the comparison's **functional** contract:
//! [`proofs::transport_crypto_constant_time_eq_agrees_with_equality`] shows
//! that `constant_time_eq` returns `true` exactly when the two arrays are
//! equal, for every pair of 16-byte arrays — so the constant-time
//! implementation has not been made *wrong* in the course of making it
//! oblivious, which is the failure mode a hand-rolled comparison actually has.
//!
//! **How the timing property is assured instead**, stated so the gap is
//! covered rather than merely admitted:
//!
//! - The comparison is `subtle::ConstantTimeEq` for `[u8]`, reached through
//!   `crate::secret::constant_time_eq`. `subtle` is data-oblivious by
//!   construction — it accumulates an OR of XOR differences over the whole
//!   array with no early exit, no branch on a compared byte, and no index
//!   derived from one — and it uses optimisation barriers to stop a compiler
//!   reintroducing a branch. That is a property of the *shape* of the code,
//!   reviewable by reading it, and it is the same crate the rest of the tree
//!   already depends on through `curve25519-dalek`.
//! - `verify_tag` compares two fixed 16-byte arrays. Neither the length nor the
//!   number of iterations depends on any attacker-controlled value, so there is
//!   no data-dependent trip count for a timing analysis to find.
//! - The single branch that follows is on the resulting `bool`, and both arms
//!   are indistinguishable to the peer: a mismatch is
//!   `TransportCryptoError::AuthenticationFailed` carrying nothing, returned
//!   identically for a forged tag, a replay, an out-of-range length, and a bad
//!   padding field. That a record either opened or did not is an inherent
//!   observable of any AEAD, not a leak this comparison introduces.
//! - The residual — that a compiler could in principle vectorise `subtle`'s
//!   loop into something with data-dependent timing on some target — is not
//!   closed by anything in this repository, and is recorded here rather than
//!   glossed. Closing it needs a timing-analysis tool over the emitted machine
//!   code, which is a different instrument from a model checker.
//!
//! # The handshake state guards are **not** proved here, and what stopped it
//!
//! `commit_chain` and `establish` in `handshake.rs` each carry a coverage
//! exemption saying they run only after row H5 passed, so their `None` arms
//! cannot be reached. Both are private, so the claim is only expressible
//! through the public statement it implies: a server still in `WaitHello` must
//! refuse every `ClientAuth`, because `require_phase` denies before a byte is
//! read.
//!
//! That harness was written on 2026-08-20 and **removed rather than shipped
//! failing**. Kani unwinds what is COMPILED, not what executes, and
//! `accept_client_auth` pulls SHA-256's 64-round compression, HMAC's 64-byte
//! `xor_pad` and `CredentialTable::new`'s 32 slots into the call graph whether
//! or not the phase guard reaches any of them. At `unwind(65)` it did not
//! finish in ten minutes with a 64-byte input, and shrinking the input to four
//! bytes did not help -- the cost is the crypto in the graph, not the input.
//!
//! The route that would work is `kani::stub` over the hash, which is
//! legitimate here precisely because the property does not depend on what the
//! hash computes. It is not done, so it is not claimed. Recorded because the
//! dead end cost ten minutes and the next attempt should start from the stub
//! rather than from the unwind bound.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
// On the host target it is not defined; this allow suppresses the warning.
#![allow(unexpected_cfgs)]

/// Bytes of the symbolic record stream the `open` harnesses drive.
///
/// A 4-byte encrypted length, up to 20 ciphertext bytes, and a 16-byte tag —
/// enough for a complete record whose plaintext is two §4.2 blocks, so the
/// range check, the tag check, the decrypt, and the unpad are all reachable.
pub const STREAM_LEN: usize = 40;

/// Bytes of payload the seal harness seals.
pub const SEAL_PAYLOAD_LEN: usize = 4;

/// The largest catch-up distance the resolve harness walks.
///
/// `MAX_CHAIN_CATCHUP` is 64; each advance is four HMAC-SHA256 invocations, so
/// walking the whole window is out of reach. Two is enough to reach the loop's
/// second iteration, which is where a walk that failed to advance would show.
pub const RESOLVE_DISTANCE_BOUND: u64 = 2;

/// One direction's 64-byte HKDF-Expand output, held concrete.
///
/// The same constant the record fuzz target installs. A peer controls every
/// byte of a record except the key, so holding the key concrete is the threat
/// model rather than a weakening of it — but it does mean nothing in this crate
/// is proved *for all keys*.
pub const DIRECTION_MATERIAL: [u8; 64] = [
    0x2c, 0x91, 0x7f, 0x04, 0xbb, 0x38, 0xe6, 0x5a, 0x13, 0xcd, 0x70, 0xa2, 0x49, 0x86, 0xf1, 0x0b,
    0xd4, 0x27, 0x63, 0x9e, 0x58, 0xac, 0x31, 0xe0, 0x0f, 0x75, 0xb8, 0x42, 0x96, 0x1d, 0xca, 0x63,
    0x87, 0x3e, 0xd1, 0x6a, 0x05, 0xf4, 0x29, 0xbc, 0x51, 0x08, 0xe7, 0x93, 0x2a, 0xdf, 0x64, 0x1b,
    0xa8, 0x35, 0xc2, 0x79, 0x0e, 0x96, 0x4d, 0xe3, 0x21, 0xb7, 0x5c, 0x88, 0x3f, 0xd0, 0x6b, 0x17,
];

#[cfg(kani)]
mod proofs {
    #[cfg(feature = "long-proofs")]
    use brainix_bsp::record::{RECORD_LENGTH_PREFIX_BYTES, RECORD_TAG_BYTES};
    #[cfg(feature = "long-proofs")]
    use brainix_bsp::BSP_MAX_RECORD_PLAINTEXT;
    #[cfg(feature = "long-proofs")]
    use brainix_bsp::LEN_DIR_KEYS;
    use brainix_bsp::{LEN_CHAIN_KEY, MAX_CHAIN_CATCHUP};
    use brainix_transport_crypto::{constant_time_eq, ChainState, Secret, TransportCryptoError};
    #[cfg(feature = "long-proofs")]
    use brainix_transport_crypto::{
        DirectionKeys, RecordOpener, RecordSealer, MAX_SEALED_RECORD_BYTES,
    };

    #[cfg(feature = "long-proofs")]
    use crate::{DIRECTION_MATERIAL, RESOLVE_DISTANCE_BOUND, SEAL_PAYLOAD_LEN, STREAM_LEN};

    // Every harness that runs a keystream or a hash carries an explicit
    // `#[kani::unwind(N)]`. The attribute takes an integer literal, so the
    // numbers cannot be given names; they are explained once here.
    //
    // **66** is one past the longest counted loop anywhere in the reachable
    // model: the 64-element `GenericArray` initialisation that `sha2` and
    // `chacha20` use for their block buffers. It therefore covers every harness
    // that can reach a keystream or a hash — the record harnesses and every
    // ratchet harness that can run an advance. The first draft used 4 for the
    // ratchet, reasoning only about the catch-up walk's own trip count, and
    // Kani reported unwinding-assertion failures: the visible failure the
    // mechanism exists to produce rather than a silent false success. Every
    // harness that needs 66 is now behind `long-proofs`, because none of them
    // terminates.
    //
    // **4** is for the two harnesses whose constraint makes the advance branch
    // infeasible, so no hash is in their model:
    // `transport_crypto_ratchet_commit_refuses_to_move_backwards`, and
    // `transport_crypto_ratchet_window_denies_outside_the_catch_up_bound`,
    // which was written at 66 and inherited the record harnesses' cost for a
    // derivation it never runs — at 4 it verifies in 4.6s. That it verifies at
    // all at this bound is itself evidence that the denying branch really does
    // return before any key derivation.
    //
    // **34** is one past a 32-byte scan, for the two harnesses that only
    // compare and zeroize.

    /// Bytes in the comparison harness's arrays: the Poly1305 tag width.
    const TAG_WIDTH: usize = 16;

    /// A fresh key set built from the concrete material.
    #[cfg(feature = "long-proofs")]
    fn keys() -> DirectionKeys {
        DirectionKeys::from_material(Secret::<LEN_DIR_KEYS>::from_bytes(DIRECTION_MATERIAL))
    }

    /// Every failure `open` may report.
    ///
    /// A variant outside this set would be a new observable a peer can
    /// distinguish, which is a change to §4.2's residual-observable list rather
    /// than an implementation detail.
    #[cfg(feature = "long-proofs")]
    fn is_expected_open_failure(error: TransportCryptoError) -> bool {
        matches!(
            error,
            TransportCryptoError::AuthenticationFailed
                | TransportCryptoError::RecordIncomplete
                | TransportCryptoError::OutputBufferTooSmall
                | TransportCryptoError::SequenceExhausted
        )
    }

    /// **No panic on any record, and a failure never moves the sequence.**
    ///
    /// The headline property. For every one of the 2^320 forty-byte streams,
    /// under the concrete key, `RecordOpener::open` returns an `OpenedRecord`
    /// or a `TransportCryptoError` — never a panic, never an out-of-bounds read
    /// of the stream or the scratch buffer, never a wrapped arithmetic
    /// operation (Kani's default checks).
    ///
    /// Beyond "no panic", two properties §4.2 states in prose:
    ///
    /// - **A failed open does not advance the receive sequence.** Every
    ///   authentication fault is a Drop, so there is no state to resynchronize;
    ///   a sequence that moved on a forgery would let a peer desynchronize a
    ///   live channel by sending garbage.
    /// - **A successful open advances it by exactly one**, and consumes at
    ///   least a prefix and a tag and no more bytes than arrived.
    ///
    /// The forty bytes are a bound, not a proof about a real record: see the
    /// crate documentation for what that leaves unproven.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_record_open_never_panics_on_any_short_stream() {
        let stream: [u8; STREAM_LEN] = kani::any();
        let mut scratch = [0u8; MAX_SEALED_RECORD_BYTES];
        let mut opener = RecordOpener::new(keys());
        let before = opener.sequence();
        kani::assert(before == 0, "a fresh opener did not start at sequence zero");
        match opener.open(&stream, &mut scratch) {
            Ok(record) => {
                kani::assert(
                    record.payload.len() <= BSP_MAX_RECORD_PLAINTEXT,
                    "an opened payload exceeded the row R4 ceiling",
                );
                kani::assert(
                    record.consumed <= stream.len(),
                    "an opened record consumed more bytes than arrived",
                );
                kani::assert(
                    record.consumed >= RECORD_LENGTH_PREFIX_BYTES.saturating_add(RECORD_TAG_BYTES),
                    "an opened record consumed less than a prefix and a tag",
                );
                kani::assert(
                    opener.sequence() == before.saturating_add(1),
                    "a successful open did not advance the sequence by one",
                );
            }
            Err(error) => {
                kani::assert(
                    is_expected_open_failure(error),
                    "open reported a failure outside its documented set",
                );
                kani::assert(
                    opener.sequence() == before,
                    "a failed open advanced the receive sequence",
                );
            }
        }
    }

    /// **Opening respects the caller's scratch buffer.**
    ///
    /// The plaintext is decrypted into a buffer the caller sized, so a record
    /// that does not fit must deny rather than write past the end. The harness
    /// gives `open` a scratch buffer far too small for anything the length
    /// prefix could legally declare and proves the call still returns without
    /// writing outside it — Kani's own bounds check is what would catch the
    /// overrun, and the assertion is that no path reaches one.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_record_open_respects_the_caller_scratch_buffer() {
        let stream: [u8; STREAM_LEN] = kani::any();
        let mut scratch = [0u8; 1];
        let mut opener = RecordOpener::new(keys());
        match opener.open(&stream, &mut scratch) {
            Ok(record) => kani::assert(
                record.payload.len() <= 1,
                "an opened payload is longer than the scratch buffer it was decrypted into",
            ),
            Err(error) => kani::assert(
                is_expected_open_failure(error),
                "open reported a failure outside its documented set",
            ),
        }
    }

    /// **Sealing respects the caller's output buffer, and never half-writes.**
    ///
    /// For every four-byte payload, `seal` into a buffer large enough reports a
    /// length that fits the buffer and is at least payload + prefix + tag, and
    /// advances the send sequence by exactly one. Into a buffer too small to
    /// hold the framing it denies, and a denied seal leaves the sequence where
    /// it was — a sender that advanced its nonce on a failed seal would skip a
    /// position the receiver still expects.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_record_seal_stays_within_the_caller_buffer() {
        let payload: [u8; SEAL_PAYLOAD_LEN] = kani::any();

        let mut out = [0u8; MAX_SEALED_RECORD_BYTES];
        let mut sealer = RecordSealer::new(keys());
        match sealer.seal(&payload, &mut out) {
            Ok(written) => {
                kani::assert(
                    written <= MAX_SEALED_RECORD_BYTES,
                    "a seal reported more bytes than the buffer holds",
                );
                kani::assert(
                    written
                        >= SEAL_PAYLOAD_LEN
                            .saturating_add(RECORD_LENGTH_PREFIX_BYTES)
                            .saturating_add(RECORD_TAG_BYTES),
                    "a sealed record is smaller than its own payload plus framing",
                );
                kani::assert(
                    sealer.sequence() == 1,
                    "a successful seal did not advance the sequence by one",
                );
            }
            Err(_) => kani::assert(false, "a four-byte payload failed to seal"),
        }

        let mut cramped = [0u8; RECORD_TAG_BYTES];
        let mut second = RecordSealer::new(keys());
        kani::assert(
            second.seal(&payload, &mut cramped).is_err(),
            "a record was sealed into a buffer too small to frame it",
        );
        kani::assert(
            second.sequence() == 0,
            "a failed seal advanced the send sequence",
        );
    }

    // -----------------------------------------------------------------------
    // §6 — the ratchet
    // -----------------------------------------------------------------------

    /// **§6.3's catch-up window denies everything outside it — unbounded.**
    ///
    /// Quantifies over both `u64` counters. Constrained to the *denial* region,
    /// so no chain advance runs and the proof holds for every pair of positions
    /// rather than for a bounded distance: for every persisted `s` and every
    /// declared `n` with `n < s` or `n > s + MAX_CHAIN_CATCHUP`, `resolve`
    /// returns row K3's `ChainDesynchronized` or row K4's
    /// `ChainCounterTooFarAhead`, and never a scratch chain.
    ///
    /// This is the half of §6.3 that matters for denial of service: the number
    /// of advances a `ClientHello` can cost the server is bounded by a `const`,
    /// and there is no arithmetic on the way that could wrap a far-ahead
    /// position back into the window.
    #[kani::proof]
    #[kani::unwind(4)]
    fn transport_crypto_ratchet_window_denies_outside_the_catch_up_bound() {
        let persisted: u64 = kani::any();
        let requested: u64 = kani::any();
        // `is_some_and`, not `is_none_or`: when `persisted + MAX_CHAIN_CATCHUP`
        // overflows, the window runs to `u64::MAX` and every `requested` at or
        // above `persisted` is *inside* it. Kani caught the first version of
        // this line, which had the overflow case backwards and so asserted that
        // `resolve` must deny positions it correctly accepts.
        kani::assume(
            requested < persisted
                || persisted
                    .checked_add(MAX_CHAIN_CATCHUP)
                    .is_some_and(|limit| requested > limit),
        );
        let state = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), persisted);
        match state.resolve(requested) {
            Ok(_) => kani::assert(false, "resolve accepted a position outside §6.3's window"),
            Err(error) => kani::assert(
                matches!(
                    error,
                    TransportCryptoError::ChainDesynchronized
                        | TransportCryptoError::ChainCounterTooFarAhead
                ),
                "resolve denied for a reason §6.3 does not name",
            ),
        }
    }

    /// **The catch-up walk terminates and lands where it was told to.**
    ///
    /// Constrained to a distance of at most [`RESOLVE_DISTANCE_BOUND`], because
    /// each advance is four HMAC-SHA256 invocations and the full 64-step window
    /// is out of reach. Within that bound: `resolve` accepts, the resulting
    /// scratch chain sits at exactly the position the peer declared — not one
    /// short and not one past — and the walk terminates, which the unwinding
    /// assertion at 4 discharges. A walk that failed to advance would run past
    /// the unwind bound and be reported, not silently accepted.
    ///
    /// The persisted state is **not** touched: `resolve` walks into scratch, and
    /// the counter it started from is asserted unchanged. §6.2 makes that the
    /// difference between a ratchet and a remote kill switch.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_ratchet_resolve_lands_at_the_declared_position() {
        let persisted: u64 = kani::any();
        let distance: u64 = kani::any();
        kani::assume(distance <= RESOLVE_DISTANCE_BOUND);
        let requested = match persisted.checked_add(distance) {
            Some(requested) => requested,
            None => return,
        };
        let state = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), persisted);
        match state.resolve(requested) {
            Ok(scratch) => {
                kani::assert(
                    scratch.counter() == requested,
                    "a resolved scratch chain is not at the position declared",
                );
                kani::assert(
                    state.counter() == persisted,
                    "resolve moved the persisted counter",
                );
            }
            Err(_) => kani::assert(false, "resolve denied a position inside §6.3's window"),
        }
    }

    /// **§6.2's commit is monotonic — unbounded in the losing direction.**
    ///
    /// Quantifies over both `u64` counters, constrained to the branch where the
    /// commit must lose: a scratch position whose successor does not strictly
    /// exceed the persisted one, including the position at `u64::MAX` whose
    /// successor does not exist. The commit is refused, the persisted counter
    /// is unchanged, and no advance runs.
    ///
    /// `MAX_SESSIONS_PER_CREDENTIAL` permits two concurrent handshakes under one
    /// credential; they may resolve from different positions and complete in
    /// either order, and without the compare-and-swap the later commit could
    /// move the persisted counter **backwards** and reinstate a chain key the
    /// server had already advanced past. §6.2 names that a direct violation of
    /// `INV-BOOT-007`, "not conditional on exploitability".
    #[kani::proof]
    #[kani::unwind(4)]
    fn transport_crypto_ratchet_commit_refuses_to_move_backwards() {
        let persisted: u64 = kani::any();
        let scratch_at: u64 = kani::any();
        kani::assume(
            scratch_at
                .checked_add(1)
                .is_none_or(|position| position <= persisted),
        );
        let mut target = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), persisted);
        let scratch = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), scratch_at).scratch();
        kani::assert(
            !target.commit(scratch),
            "a commit that does not move strictly forward took effect",
        );
        kani::assert(
            target.counter() == persisted,
            "a losing commit moved the persisted counter",
        );
    }

    /// **A winning commit moves the counter strictly forward, and only by one.**
    ///
    /// The other branch of the compare-and-swap, bounded to the region just
    /// above the persisted position so exactly one advance runs. Proves that a
    /// commit that takes effect installs `m + 1` — the position the session
    /// derived from, plus one — and that this is strictly greater than what was
    /// there before, so the chain is monotone under every interleaving of two
    /// concurrent handshakes.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_ratchet_commit_advances_by_exactly_one() {
        let persisted: u64 = kani::any();
        let scratch_at: u64 = kani::any();
        let position = match scratch_at.checked_add(1) {
            Some(position) => position,
            None => return,
        };
        kani::assume(position > persisted);
        let mut target = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), persisted);
        let scratch = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), scratch_at).scratch();
        kani::assert(
            target.commit(scratch),
            "a strictly forward commit was refused",
        );
        kani::assert(
            target.counter() == position,
            "a winning commit did not install the position it computed",
        );
        kani::assert(
            target.counter() > persisted,
            "a winning commit did not move the counter forward",
        );
    }

    /// **A scratch advance is strictly monotone and destroys what it left.**
    ///
    /// One step, over an arbitrary starting position. Proves the counter moves
    /// forward by exactly one and that the buffer the advance retired is
    /// returned already zeroized — §6.1's `zeroize(CK_n)` as a checked fact
    /// rather than a claim. Forward secrecy buys nothing unless the old key is
    /// actually gone.
    ///
    /// **The chain key is concrete**, as it is in every other ratchet harness
    /// here. It was symbolic, which made the advance a symbolic HMAC-SHA256 and
    /// stalled the Kani job for twenty-five minutes with no verdict. Neither
    /// property this harness states reads the key's bytes, so nothing was lost
    /// by fixing it — but it did not rescue the harness either: with a concrete
    /// key it still returned no verdict in 700s, which is why it sits behind
    /// `long-proofs`. The change is kept because a symbolic hash is strictly
    /// further out of reach than a concrete one, and whoever next attacks this
    /// cost should start from the cheaper of the two.
    ///
    /// **Behind `long-proofs`, and not in CI** — see the crate documentation's
    /// *The cost bound*.
    #[cfg(feature = "long-proofs")]
    #[kani::proof]
    #[kani::unwind(66)]
    fn transport_crypto_ratchet_advance_is_monotone_and_erases_the_retired_key() {
        let start: u64 = kani::any();
        kani::assume(start < u64::MAX);
        let state = ChainState::at(Secret::<LEN_CHAIN_KEY>::zero(), start);
        let mut scratch = state.scratch();
        kani::assert(
            scratch.counter() == start,
            "a scratch chain is not at the position it was taken from",
        );
        let retired = scratch.advance();
        kani::assert(
            scratch.counter() == start.saturating_add(1) && scratch.counter() > start,
            "a scratch advance did not move forward by exactly one",
        );
        let mut index = 0usize;
        while index < LEN_CHAIN_KEY {
            kani::assert(
                retired.expose()[index] == 0,
                "an advance returned a retired key that was not erased",
            );
            index = index.saturating_add(1);
        }
    }

    // -----------------------------------------------------------------------
    // The comparison and the zeroization
    // -----------------------------------------------------------------------

    /// **The constant-time comparison is functionally exact — unbounded.**
    ///
    /// Quantifies over every pair of 16-byte arrays, which is the Poly1305 tag
    /// width. Proves `constant_time_eq(a, b)` is `true` exactly when `a == b`:
    /// it never reports a match for arrays that differ in any byte at any
    /// position, and never reports a mismatch for arrays that are equal.
    ///
    /// **This is not a timing proof and is not offered as one.** See the crate
    /// documentation for why a timing property is not expressible in Kani's
    /// model and how it is assured instead. What this closes is the failure
    /// mode a hand-rolled oblivious comparison actually has: being made
    /// *wrong* in the course of being made branchless. A comparison that
    /// returned `true` for a near-miss would accept a forged tag in constant
    /// time, which is worse than a variable-time comparison that is correct.
    #[kani::proof]
    #[kani::unwind(34)]
    fn transport_crypto_constant_time_eq_agrees_with_equality() {
        let left: [u8; TAG_WIDTH] = kani::any();
        let right: [u8; TAG_WIDTH] = kani::any();
        let mut identical = true;
        let mut index = 0usize;
        while index < TAG_WIDTH {
            if left[index] != right[index] {
                identical = false;
            }
            index = index.saturating_add(1);
        }
        kani::assert(
            constant_time_eq(&left, &right) == identical,
            "the constant-time comparison disagrees with byte equality",
        );
    }

    /// **`Secret::ct_eq_bytes` agrees with equality, and zeroize destroys
    /// everything — unbounded over the material.**
    ///
    /// The confirmation values of rows H5 and H6 are compared through
    /// `ct_eq_bytes`, and §5.2, §6.1 and §9.4 each name an explicit
    /// zeroization. Both are proved over an arbitrary 32-byte secret: the
    /// comparison is exact, and after `zeroize` every byte is zero and the
    /// secret compares equal to the all-zero array and unequal to any array
    /// that is not.
    #[kani::proof]
    #[kani::unwind(34)]
    fn transport_crypto_secret_compares_exactly_and_zeroizes_completely() {
        let material: [u8; LEN_CHAIN_KEY] = kani::any();
        let other: [u8; LEN_CHAIN_KEY] = kani::any();
        let mut secret = Secret::<LEN_CHAIN_KEY>::from_bytes(material);

        let mut identical = true;
        let mut index = 0usize;
        while index < LEN_CHAIN_KEY {
            if material[index] != other[index] {
                identical = false;
            }
            index = index.saturating_add(1);
        }
        kani::assert(
            secret.ct_eq_bytes(&other) == identical,
            "a secret's constant-time comparison disagrees with byte equality",
        );

        secret.zeroize();
        let mut position = 0usize;
        while position < LEN_CHAIN_KEY {
            kani::assert(
                secret.expose()[position] == 0,
                "zeroize left a byte of key material behind",
            );
            position = position.saturating_add(1);
        }
        kani::assert(
            secret.ct_eq_bytes(&[0u8; LEN_CHAIN_KEY]),
            "a zeroized secret does not compare equal to zero",
        );
    }
}
