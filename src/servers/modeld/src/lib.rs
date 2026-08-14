#![no_std]
#![deny(unsafe_code)]

//! `modeld`: the one-shot weight loader's stage sequence and manifest (P3-T3a).
//!
//! `BXW1-weight-format.md` §10.1 says of its stage table that **"the order is
//! normative"**, and §10.0 says of the manifest that it is **"exactly three
//! capabilities"**. Both were prose. This crate makes them executable: the
//! sequence is a state machine that cannot be driven out of order, and the
//! manifest is a `const` table a test can count.
//!
//! # Why the order is a security property and not a style
//!
//! Two placements in §10.1 are load-bearing, and both are about *when*
//! something is trusted:
//!
//! - **S1 copies `L` bytes, where `L` came from the storage layer and was
//!   bounds-checked at S0** — never `total_size`, which is a number the blob
//!   makes up about itself and which has not even been read yet. The only write
//!   into the region is therefore bounded by a quantity checked against a
//!   `const`.
//! - **Everything after S1 is parsed from region-resident bytes.** Parsing the
//!   storage object and copying it afterwards would leave a
//!   time-of-check/time-of-use gap, because nothing makes the storage object
//!   immutable between the two reads. Copying first closes the gap and costs
//!   nothing.
//!
//! A state machine that permits S2 before S1 permits validating bytes that are
//! not the bytes that will be used. That is the defect this type exists to make
//! unrepresentable.
//!
//! # Fail closed, and the difference S0 makes
//!
//! Every stage from S0 to S9 denies on failure. **S0 denies with no copy; every
//! later stage denies and zeroizes**, because from S1 onward the region holds
//! attacker-supplied bytes. [`LoadSequence::deny`] returns which of the two is
//! owed, so a caller cannot forget the difference — and cannot zeroize a region
//! it never wrote, which would look like defensive coding and would in fact be
//! a write through a capability the loader should not be exercising yet.
//!
//! # What this crate is not
//!
//! It reads no storage, writes no region, computes no digest, and seals
//! nothing: it holds the *ordering* and the *manifest*, which are the parts of
//! §10 that can be checked before a kernel exists to hold capabilities. The
//! stages themselves are `brainix-bxw1`'s parser plus the storage and memory
//! capabilities that P3-T3a still owes. §11 of the spec says "there is no
//! `modeld`"; this is the first half of one, and the spec's sentence stays true
//! of the other half.

/// A stage of the §10.1 sequence.
///
/// The discriminants are the stage numbers, so a reader comparing this to the
/// spec's table is comparing like with like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Obtain and bounds-check the object's byte length `L`.
    S0ObtainLength = 0,
    /// Copy exactly `L` bytes into the region.
    S1CopyIntoRegion = 1,
    /// Parse and validate the header from region bytes.
    S2ValidateHeader = 2,
    /// Derive the tensor-table extent; check overflow and containment.
    S3TableExtent = 3,
    /// Digest the table bytes and compare to `tensor_table_digest`.
    S4TableDigest = 4,
    /// Validate every record in index order.
    S5ValidateRecords = 5,
    /// Resolve the required name set and its shape cross-checks.
    S6RequiredNames = 6,
    /// One payload pass: whole-blob digest, per-tensor digests, encodings, pads.
    S7PayloadPass = 7,
    /// Compare the whole-blob digest and verify the detached signature.
    S8DigestAndSignature = 8,
    /// Verify the tokenizer blob's length, digest, and entry count.
    S9TokenizerBlob = 9,
    /// Seal the region read-only and non-executable.
    S10Seal = 10,
    /// Emit the audit event and exit.
    S11AuditAndExit = 11,
}

impl Stage {
    /// The stage that follows this one, or `None` after S11.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        match self {
            Self::S0ObtainLength => Some(Self::S1CopyIntoRegion),
            Self::S1CopyIntoRegion => Some(Self::S2ValidateHeader),
            Self::S2ValidateHeader => Some(Self::S3TableExtent),
            Self::S3TableExtent => Some(Self::S4TableDigest),
            Self::S4TableDigest => Some(Self::S5ValidateRecords),
            Self::S5ValidateRecords => Some(Self::S6RequiredNames),
            Self::S6RequiredNames => Some(Self::S7PayloadPass),
            Self::S7PayloadPass => Some(Self::S8DigestAndSignature),
            Self::S8DigestAndSignature => Some(Self::S9TokenizerBlob),
            Self::S9TokenizerBlob => Some(Self::S10Seal),
            Self::S10Seal => Some(Self::S11AuditAndExit),
            Self::S11AuditAndExit => None,
        }
    }

    /// Whether a failure at this stage may still deny the load.
    ///
    /// S0 to S9 deny. S10 and S11 have no failure column in §10.1: by then the
    /// bytes are verified, and the remaining actions are a kernel seal and an
    /// audit event.
    #[must_use]
    pub const fn can_deny(self) -> bool {
        (self as u8) <= (Self::S9TokenizerBlob as u8)
    }
}

/// What a denial owes the region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialDuty {
    /// Deny without touching the region: nothing was ever written to it.
    ///
    /// Only S0. Zeroizing here would be a write through the writable-weights
    /// capability at a point where the loader has no reason to exercise it.
    NoCopy,
    /// Deny and zeroize the region: it holds attacker-supplied bytes.
    Zeroize,
}

/// Why the sequence refused to advance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    /// A stage was attempted out of order. The field is the stage that was due.
    OutOfOrder {
        /// The stage the sequence was waiting for.
        expected: Stage,
    },
    /// The sequence already denied, and a denied load never resumes: §10.5
    /// makes a reload a new generation, not a continuation.
    AlreadyDenied,
    /// The sequence already completed and `modeld` has exited.
    AlreadyFinished,
}

/// Where a load has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceState {
    /// Waiting for this stage to be performed.
    Awaiting(Stage),
    /// Denied at this stage, with the duty its denial carried.
    Denied {
        /// The stage that refused the blob.
        stage: Stage,
        /// What the denial owed the region.
        duty: DenialDuty,
    },
    /// S11 completed: the region is sealed and `modeld` has exited.
    Exited,
}

/// The §10.1 sequence, as a machine that cannot be driven out of order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSequence {
    state: SequenceState,
}

impl Default for LoadSequence {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadSequence {
    /// A sequence waiting at S0.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: SequenceState::Awaiting(Stage::S0ObtainLength),
        }
    }

    /// Where the load has got to.
    #[must_use]
    pub const fn state(&self) -> SequenceState {
        self.state
    }

    /// Records that `stage` completed successfully and advances.
    ///
    /// # Errors
    ///
    /// [`SequenceError::OutOfOrder`] if `stage` is not the stage due — which is
    /// how "the order is normative" stops being prose. [`SequenceError::AlreadyDenied`]
    /// and [`SequenceError::AlreadyFinished`] for a sequence that is over.
    pub fn complete(&mut self, stage: Stage) -> Result<SequenceState, SequenceError> {
        let expected = match self.state {
            SequenceState::Awaiting(expected) => expected,
            SequenceState::Denied { .. } => return Err(SequenceError::AlreadyDenied),
            SequenceState::Exited => return Err(SequenceError::AlreadyFinished),
        };
        if stage != expected {
            return Err(SequenceError::OutOfOrder { expected });
        }
        self.state = match expected.next() {
            Some(next) => SequenceState::Awaiting(next),
            None => SequenceState::Exited,
        };
        Ok(self.state)
    }

    /// Records that the stage due failed, and returns what its denial owes.
    ///
    /// The duty is returned rather than left to the caller's memory: S0 denies
    /// with no copy because nothing has been written, and every later stage
    /// denies and zeroizes because the region holds bytes an attacker supplied.
    ///
    /// # Errors
    ///
    /// [`SequenceError::OutOfOrder`] if the stage due cannot deny — S10 and S11
    /// have no failure column in §10.1. [`SequenceError::AlreadyDenied`] or
    /// [`SequenceError::AlreadyFinished`] for a sequence that is over.
    pub fn deny(&mut self) -> Result<DenialDuty, SequenceError> {
        let stage = match self.state {
            SequenceState::Awaiting(stage) => stage,
            SequenceState::Denied { .. } => return Err(SequenceError::AlreadyDenied),
            SequenceState::Exited => return Err(SequenceError::AlreadyFinished),
        };
        if !stage.can_deny() {
            return Err(SequenceError::OutOfOrder { expected: stage });
        }
        let duty = if matches!(stage, Stage::S0ObtainLength) {
            DenialDuty::NoCopy
        } else {
            DenialDuty::Zeroize
        };
        self.state = SequenceState::Denied { stage, duty };
        Ok(duty)
    }

    /// Whether the region is sealed and `modeld` has exited.
    ///
    /// `inferd` launches only after this is true (§10.2), because until it is,
    /// a writable capability over `WEIGHTS_REGION` is still held by a running
    /// process.
    #[must_use]
    pub const fn has_exited(&self) -> bool {
        matches!(self.state, SequenceState::Exited)
    }
}

/// One capability in `modeld`'s manifest, and the stage that needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestEntry {
    /// What the capability names, in the words §10.0 uses.
    pub subject: &'static str,
    /// The stage that cannot run without it.
    pub required_by: Stage,
    /// Whether it confers write authority.
    pub writable: bool,
}

/// `modeld`'s manifest: **exactly three capabilities** (§10.0).
///
/// The authoritative statement is `SECURITY_INVARIANTS.md` §14; this is that
/// statement in a form a test can count. The number is the invariant — the
/// rejected alternative to this whole component was a *fourth* capability on
/// `inferd`, which would degrade `INV-MODEL-001`, whose entire content is the
/// number three.
///
/// Absent, and deliberately: `CapServe`, `CapModel`, `CapAdmin`, any network
/// capability, and any spawn authority. `modeld` cannot accept a connection, is
/// unreachable from any client session, and cannot release a seal — unsealing
/// is a kernel operation (§10.5).
pub const MANIFEST: [ManifestEntry; 3] = [
    ManifestEntry {
        subject: "CapEndpoint -> devd-ans2 (storage)",
        required_by: Stage::S0ObtainLength,
        writable: false,
    },
    ManifestEntry {
        subject: "CapMemory over WEIGHTS_REGION (writable, never executable)",
        required_by: Stage::S1CopyIntoRegion,
        writable: true,
    },
    ManifestEntry {
        subject: "CapEndpoint -> auditd (send-only)",
        required_by: Stage::S11AuditAndExit,
        writable: false,
    },
];

/// How many capabilities in the manifest confer write authority.
///
/// One, over the weights region, and it is why `modeld` exits: the writable
/// view must exist in no running process while the system serves.
#[must_use]
pub fn writable_capability_count() -> usize {
    MANIFEST.iter().filter(|entry| entry.writable).count()
}
