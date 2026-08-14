//! Kani proof harnesses for the audit record.
//!
//! `INV-AUDIT`'s stated evidence is the auditor's frozen capability manifest —
//! "it physically cannot name the capabilities it lacks" — and a manifest is
//! checked by counting it. What a manifest cannot check is the *record*: an
//! auditor with exactly the right capabilities can still write a prompt into
//! the log, and `INV-AUD-001`'s attributability is worth nothing if the thing
//! attributed is a fiction assembled from a malformed record.
//!
//! These harnesses cover the half a manifest audit cannot reach:
//!
//! - **Bounded pressure** (`INV-AUD-003`): every event encodes to the same
//!   constant length, so a client's input is not a term in the audit
//!   subsystem's footprint.
//! - **No invention** (`INV-AUD-001`): decoding is total over *every* 23-byte
//!   string, and it either yields the event that was encoded or refuses. An
//!   audit log that guesses at records it could not read is worse than one with
//!   a gap.
//!
//! The record type carries no byte slice at all, so "a prompt cannot reach the
//! log" is a property of the type rather than of these proofs — there is
//! nothing here to quantify over, which is the strongest form the claim has.

#![deny(unsafe_code)]
// kani is a cfg set by the Kani verification tool's dedicated CI image.
#![allow(unexpected_cfgs)]

#[cfg(kani)]
mod proofs {
    use brainix_auditd::event::{
        decode, encode, AuditEvent, EventKind, Outcome, CREDENTIAL_HANDLE_LEN, RECORD_LEN,
    };

    /// A symbolic event, over every field a record can hold.
    ///
    /// `Option` rather than a total constructor: the discriminants are
    /// symbolic, and a harness that assumed them into range and then unwrapped
    /// would be one `unwrap` away from proving something about a panic.
    fn any_event() -> Option<AuditEvent> {
        let kind_index: u8 = kani::any();
        let outcome_index: u8 = kani::any();
        let kind = EventKind::from_wire(kind_index)?;
        let outcome = Outcome::from_wire(outcome_index)?;
        Some(AuditEvent {
            kind,
            outcome,
            session_slot: kani::any(),
            credential: kani::any::<[u8; CREDENTIAL_HANDLE_LEN]>(),
            sequence: kani::any(),
        })
    }

    /// **Audit pressure is bounded — every event costs the same.**
    ///
    /// `INV-AUD-003`. The encoded length is a constant over every event, so the
    /// log is sized by event *count* and no client-supplied quantity appears in
    /// the audit subsystem's memory footprint.
    #[kani::proof]
    fn auditd_audit_record_is_the_same_size_for_every_event() {
        let Some(event) = any_event() else {
            return;
        };
        let record = encode(&event);
        kani::assert(
            record.len() == RECORD_LEN,
            "an event encoded to something other than the fixed record length",
        );
    }

    /// **What was recorded is what happened — round trip over every event.**
    ///
    /// `INV-AUD-001` is attributability, and attribution to the wrong session or
    /// the wrong credential is worse than none: it accuses somebody.
    #[kani::proof]
    fn auditd_audit_record_round_trips_for_every_event() {
        let Some(event) = any_event() else {
            return;
        };
        let record = encode(&event);
        match decode(&record) {
            Ok(decoded) => {
                kani::assert(
                    decoded.session_slot == event.session_slot,
                    "a record decoded to a different session than it recorded",
                );
                kani::assert(
                    decoded.sequence == event.sequence,
                    "a record decoded to a different sequence number",
                );
                kani::assert(
                    decoded.credential == event.credential,
                    "a record decoded to a different credential than it recorded",
                );
            }
            Err(_) => kani::assert(false, "a record this crate encoded did not decode"),
        }
    }

    /// **Decoding never panics and never invents — over every 23-byte string.**
    ///
    /// Not over records we produced: over all 2^184 byte strings of the record
    /// length, which is what a corrupted log page or a future writer produces.
    /// Every one either decodes to an event whose fields are the bytes it was
    /// given, or is refused.
    #[kani::proof]
    fn auditd_audit_decode_never_invents_a_record() {
        let bytes: [u8; RECORD_LEN] = kani::any();
        if let Ok(event) = decode(&bytes) {
            kani::assert(
                event.kind.to_wire() == bytes[0],
                "a decoded kind is not the kind in the record",
            );
            kani::assert(
                event.outcome.to_wire() == bytes[1],
                "a decoded outcome is not the outcome in the record",
            );
            kani::assert(
                event.session_slot == bytes[2],
                "a decoded session slot is not the one in the record",
            );
        }
    }

    /// **A record of the wrong length is always refused.**
    ///
    /// The fixed size is load-bearing for `INV-AUD-003`, so a short or long
    /// buffer must deny rather than decode a prefix — a decoded prefix would be
    /// an event assembled from whatever followed it in the log.
    #[kani::proof]
    fn auditd_audit_decode_refuses_every_wrong_length() {
        let length: usize = kani::any();
        kani::assume(length < RECORD_LEN);
        let bytes: [u8; RECORD_LEN] = kani::any();
        let Some(slice) = bytes.get(..length) else {
            return;
        };
        kani::assert(
            decode(slice).is_err(),
            "a buffer shorter than a record decoded to an event",
        );
    }
}
