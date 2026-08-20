//! Kani proof harnesses for the BXW1 weight-blob loader (`brainix-bxw1`).
//!
//! BXW1 blobs are the second untrusted input this system parses with real
//! authority, after the device tree: a served model is a file, and a file is
//! whatever the thing that wrote it says. `adt-verify` exists for the
//! firmware-supplied half of that sentence; this is the model-supplied half.
//!
//! # The length bound
//!
//! Kani is a bounded model checker, so every harness fixes the blob's length
//! and proves the property for *every* byte string of exactly that length.
//! The constants are chosen at the format's own thresholds rather than for
//! round numbers:
//!
//! - **8 bytes** -- far below `BXW1_HEADER_BYTES` (256), so every input must be
//!   refused. This proves the reject path is total: no 8-byte string panics,
//!   indexes out of bounds, or wraps an arithmetic operation on the way to its
//!   denial.
//!
//! A 256-byte harness -- exactly one header -- was written and **removed**. It
//! reaches `verify_table_digest` and does not finish; see below. That is a
//! correction to the obvious guess, which is that a blob with no tensor data
//! after the header has nothing to hash.
//!
//! # What is bounded away, named rather than implied
//!
//! **The digest check, and it starts earlier than it looks.** `parse` calls
//! `payload::verify_table_digest`, which runs SHA-256 over the tensor table.
//! Kani unwinds what is compiled, so any blob that reaches it drags 64 rounds
//! of compression into the call graph and the harness stops finishing -- the
//! same wall `transport-crypto-verify`'s handshake proof hit.
//!
//! I expected 256 bytes to be safe on the reasoning that a header with no
//! tensor data after it has nothing to hash. That is wrong: the harness was
//! written, ran into `Sha256::update`, and did not finish in 550 seconds. The
//! two harnesses that remain deny on length before any of it.
//!
//! The obvious way out is the one that worked for `transport-crypto-verify`'s
//! handshake proof: stub `Sha256::update` and `Sha256::finalize`, which is
//! sound for a no-panic property because it cannot depend on what the hash
//! computes. **That was tried on 2026-08-20 and it is not enough here.**
//! Stubbed, behind `long-proofs`, at `unwind(257)`, with `region_capacity`
//! symbolic, the harness produced no output at all in roughly fifty minutes --
//! not a verdict, not an unwinding failure, nothing.
//!
//! The difference from the handshake is what remains after the hash is gone.
//! There the phase guard denies immediately and the rest of the call graph is
//! dead; here 256 symbolic bytes are a header the decoder reads field by field,
//! and every field feeds the extent arithmetic that follows. Removing SHA-256
//! removes a cost that was never the dominant one at this length.
//!
//! So the harness is **not shipped**, and this is a record of an attempt rather
//! than a plan. A gated proof nobody has watched pass is worth less than an
//! honest note saying what was tried and what it cost.
//!
//! ## Two routes that look open and are not
//!
//! Written down because both are the obvious next thought and both cost
//! nothing to rule out once stated:
//!
//! - **A harness over `header::decode` alone.** `mod header` is private in
//!   `brainix-bxw1`; only the `Header` type is re-exported, not the decoder.
//!   Reaching it means widening a crate's API purely to enable a proof, which
//!   is a worse trade than the missing proof.
//! - **A shorter blob that still reaches the table decoder.** There is none.
//!   `parse` refuses anything below `BXW1_HEADER_BYTES`, so 256 IS the floor,
//!   and it is the length that does not finish.
//!
//! What remains is to shrink the symbolic surface rather than the length: fix
//! most of the header to a well-formed value and leave one field arbitrary.
//! That proves something strictly weaker -- a statement about one field rather
//! than about every 256-byte string -- and it should be written to say so, not
//! left to read like the headline property.
//!
//! **The 22 GiB ceiling.** `BXW1_MAX_BLOB_BYTES` is about 22 GiB. No bounded
//! harness can construct a blob past it, so the guard that refuses one is
//! outside what this crate can say anything about. That is why its coverage
//! exemption cites the arithmetic rather than a proof.

#![no_std]
#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
// On the host target it is not defined; this allow suppresses the warning.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_bxw1::Bxw1Error;

    /// A blob far shorter than the header, where every input must be refused.
    const SHORT_BLOB_LEN: usize = 8;

    /// **No panic on any eight-byte input, for any region capacity.**
    ///
    /// Eight bytes cannot encode a header, so every input is refused and this
    /// harness is about the *reject* path being total. `region_capacity` is
    /// symbolic too: it is a caller-supplied `u64` that the loader compares
    /// against sizes it reads from the blob, which is exactly the shape of
    /// arithmetic that wraps if it is written carelessly.
    #[kani::proof]
    #[kani::unwind(9)]
    fn bxw1_parse_never_panics_on_any_eight_byte_input() {
        let blob: [u8; SHORT_BLOB_LEN] = kani::any();
        let region_capacity: u64 = kani::any();

        let outcome = brainix_bxw1::WeightBlob::parse(&blob, region_capacity);

        kani::assert(
            outcome.is_err(),
            "an eight-byte blob cannot encode a BXW1 header and must be refused",
        );
        kani::assert(
            matches!(outcome, Err(Bxw1Error::BlobTooSmallForHeader)),
            "the refusal must be the header-length guard rather than a later \
             check that happens to deny",
        );
    }

    /// **No panic on the empty blob.**
    ///
    /// Its own guard, before the length arithmetic, and the one input where a
    /// slice-based parser is most likely to index rather than deny.
    #[kani::proof]
    fn bxw1_parse_refuses_the_empty_blob() {
        let region_capacity: u64 = kani::any();
        let outcome = brainix_bxw1::WeightBlob::parse(&[], region_capacity);
        kani::assert(
            matches!(outcome, Err(Bxw1Error::EmptyBlob)),
            "the empty blob must be refused as empty",
        );
    }
}
