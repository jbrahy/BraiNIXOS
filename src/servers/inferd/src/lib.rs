#![no_std]
#![deny(unsafe_code)]

//! `inferd`: the confined tenant's manifest and its per-session KV binding
//! (P3-T7).
//!
//! `INV-MODEL-001` is one sentence — *"`inferd` holds `{Model, its serving
//! endpoint, its own KV slice}`. Not spawn. Not kernel mutation. Not network.
//! Not another session."* — and its evidence is *"manifest audit; the diff must
//! show zero capabilities beyond the three."* A diff is audited by a person.
//! This crate makes the same statement countable by a test, which is the form
//! that survives someone being in a hurry.
//!
//! # Confinement is structural, not behavioural
//!
//! The invariant's own reason: **the model physically cannot name a capability
//! it was not granted, so no prompt — however sophisticated — can cause it to
//! use one.** That is why the manifest is a `const` here and there is no
//! function anywhere in this crate that adds to it. Confinement that depended
//! on the model's judgment would be no confinement at all, and confinement that
//! depended on a runtime check would be confinement an attacker gets to argue
//! with.
//!
//! # The KV binding is one slice, chosen by nobody
//!
//! A session's KV partition is not looked up, requested, or named on the wire:
//! it is the partition belonging to the session's own slot, and
//! [`KvBinding::for_session`] is the only way to make one. There is no
//! constructor that takes an arbitrary index, because a constructor that takes
//! an index is an API that can be handed the wrong one — and the wrong one is
//! another client's cache (`INV-SERVE-001`).
//!
//! # What P3-T7 still owes
//!
//! No IPC, no model execution, no tensor call. `brainix-transformer` is the
//! engine and it landed already; what this crate holds is the *confinement*
//! around it — the manifest, the session-to-slice binding, and the teardown
//! obligation. Wiring `servd` to it over synchronous IPC, and running the
//! transformer inside it, is the rest of P3-T7 and needs a kernel.

use brainix_bsp::MAX_SESSIONS;

/// One capability in `inferd`'s manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestEntry {
    /// What the capability names.
    pub subject: &'static str,
    /// Why the tenant cannot serve without it.
    pub because: &'static str,
}

/// `inferd`'s manifest: **exactly three capabilities**, frozen at launch.
///
/// The count is the invariant. `modeld` exists as a separate principal
/// precisely so this array stays at three: the rejected alternative was a
/// fourth entry here granting storage authority, which would put a capability
/// that can read the weight blob inside the one component that is long-lived,
/// reachable through `servd`, and adversarially prompted by design.
pub const MANIFEST: [ManifestEntry; 3] = [
    ManifestEntry {
        subject: "CapModel",
        because: "the sealed, read-only view of WEIGHTS_REGION it runs the model from",
    },
    ManifestEntry {
        subject: "CapEndpoint -> servd (its serving endpoint)",
        because: "prompts arrive and tokens leave through this one channel and no other",
    },
    ManifestEntry {
        subject: "CapMemory over its own KV partition",
        because: "the session's cache; one partition, never the region",
    },
];

/// Capabilities `inferd` must never hold, by the invariant's own list.
///
/// Kept as data rather than prose so a test can assert against it. "Not spawn.
/// Not kernel mutation. Not network. Not another session." — and storage, which
/// `INV-MODEL-001` withholds by granting it to `modeld` instead.
pub const FORBIDDEN_SUBJECTS: [&str; 5] = ["spawn", "kernel", "network", "storage", "capadmin"];

/// The KV partition bound to one session, and nothing else.
///
/// Deliberately carries the session's own slot index rather than a partition
/// index: they are the same number by construction, and keeping one of them
/// removes the possibility of them disagreeing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KvBinding {
    session_slot: usize,
}

/// Why a KV binding could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// The slot index is not one `servd` can admit.
    ///
    /// Denies rather than clamping: a clamped index binds the tenant to the
    /// last partition, which belongs to a different client.
    NoSuchSession,
}

impl KvBinding {
    /// Binds the session in `session_slot` to its own partition.
    ///
    /// # Errors
    ///
    /// [`BindingError::NoSuchSession`] for a slot past [`MAX_SESSIONS`].
    pub const fn for_session(session_slot: usize) -> Result<Self, BindingError> {
        if session_slot >= MAX_SESSIONS {
            return Err(BindingError::NoSuchSession);
        }
        Ok(Self { session_slot })
    }

    /// The session slot this binding serves.
    #[must_use]
    pub const fn session_slot(&self) -> usize {
        self.session_slot
    }

    /// The KV partition index this binding names.
    ///
    /// Equal to the session slot, by construction. This function exists to be
    /// read, not to compute: it documents that the partition is *derived* from
    /// the session rather than chosen alongside it.
    #[must_use]
    pub const fn partition_index(&self) -> usize {
        self.session_slot
    }

    /// Whether this binding names the same partition as `other`.
    ///
    /// Two live bindings that answer `true` here would be two tenants sharing a
    /// cache, which is the cross-tenant read `INV-SERVE-001` forbids.
    #[must_use]
    pub const fn shares_partition_with(&self, other: &Self) -> bool {
        self.partition_index() == other.partition_index()
    }
}

/// What a session's teardown owes its partition before the slot is reused.
///
/// `INV-SERVE-004`: the partition is zeroized on teardown, before it can be
/// reused. Residue visible to the next occupant is a cross-tenant leak that
/// never technically violated the naming rule — which is exactly the kind of
/// leak a naming-based argument misses, so it is named separately here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "a teardown that does not zeroize leaves one tenant's cache visible to the next"]
pub struct TeardownDuty {
    /// The partition that must be zeroized.
    pub partition_index: usize,
}

/// The duty a session's teardown carries.
///
/// The returned type carries its own `#[must_use]` message, which is the one
/// that matters: dropping the duty is the leak.
pub const fn teardown(binding: KvBinding) -> TeardownDuty {
    TeardownDuty {
        partition_index: binding.partition_index(),
    }
}
