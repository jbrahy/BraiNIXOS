#![no_std]
#![deny(unsafe_code)]

//! `servd`: the fixed session-slot pool and its admission control (P2-T4).
//!
//! `brainix-bsp`'s [`Session`] is one connection's *protocol* state machine and
//! says so: it holds no keys, no prompt buffer, and no slot index, because
//! those are `servd`'s (BSP v2 §9.1). This crate is that half — the `static`
//! pool the spec describes, the admission limits that bound it, and the handle
//! discipline that keeps one client from ever naming another's slot.
//!
//! # What this crate is, and what P2-T4 still owes
//!
//! Host-testable and kernel-free. It is the part of `servd` that can be written
//! and proved before there is a kernel to accept connections into: **the pool,
//! the limits, and the handles.** What it deliberately does not contain, and
//! what P2-T4 is not complete without:
//!
//! - accepting from `transportd` — there is no IPC here;
//! - the clock itself: [`Tick`] is a reading someone else takes, because a
//!   crate with no IPC has no business deciding what time it is;
//! - minting the per-session capability — `CapServe` and `CapAdmin` are the
//!   kernel's to grant, and the grant is what freezes a session's type;
//! - the directional keys, sequence counters, and `prompt_buf` the slot is
//!   specified to hold — those arrive with the transport wiring.
//!
//! Reading this crate as "servd exists" would be exactly the mistake the
//! roadmap's `P3-T3` row already warns about for the weight loader.
//!
//! # Admission is the invariant, not a policy knob
//!
//! `INV-SERVE-003` is bounded admission, and BSP v2 §9.1 is precise about what
//! makes it hold: a slot is acquired **after the selector match but before the
//! client has authenticated**, so a party replaying a captured `ClientHello`
//! holds a real slot until the handshake times out. The limits therefore have
//! to count half-open handshakes, and here they do — [`SessionSlots::acquire`]
//! is the counting point and there is no other way in.
//!
//! Three `const` ceilings, each with its own denial:
//!
//! | Ceiling | Value | Denial |
//! |---|---|---|
//! | [`MAX_SESSIONS`] | 8 | [`AdmissionDenied::PoolFull`] |
//! | [`MAX_ADMIN_SESSIONS`] | 1 | [`AdmissionDenied::AdminLimitReached`] |
//! | [`MAX_SESSIONS_PER_CREDENTIAL`] | 2 | [`AdmissionDenied::CredentialLimitReached`] |
//!
//! **What that bound does not do**, restated here because the spec is careful
//! about it and a summary that drops it would be the misleading half: the
//! per-credential limit protects *every other client* and does not protect the
//! victim. An attacker replaying one captured `ClientHello` twice occupies both
//! of that credential's admission slots and can refresh them every handshake
//! timeout, denying that one client service indefinitely, at a cost of two
//! 64-byte packets and no credential at all. That is a known, accepted
//! consequence of admitting before authenticating; it is not closed here.
//!
//! # Handles, and why they carry a generation
//!
//! [`SlotHandle`] is the only way to reach a session, and it is opaque: the
//! slot index is server-internal and never appears on the wire (§9.1). Each
//! handle carries the generation its slot held when the handle was issued, and
//! [`SessionSlots::release`] advances that generation. A handle to a released
//! slot therefore resolves to nothing, permanently — which is what stops a
//! stale handle from reading whatever client took the slot next. Without it,
//! slot reuse would be a cross-tenant read (`INV-SERVE`) reachable by holding
//! on to an old handle.

pub mod admin;

use brainix_bsp::{
    Session, SessionType, HS_TIMEOUT_SECONDS, IDLE_TIMEOUT_SECONDS, LEN_HANDLE, MAX_ADMIN_SESSIONS,
    MAX_SESSIONS, MAX_SESSIONS_PER_CREDENTIAL,
};

/// A reading of `servd`'s monotonic clock, in seconds.
///
/// Monotonic, not wall time: a clock that can move backwards is a clock an
/// attacker who can influence it uses to hold a slot forever. Nothing here
/// converts to a date, because nothing here needs to know one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tick(u64);

impl Tick {
    /// A reading at `seconds` since boot.
    #[must_use]
    pub const fn from_seconds(seconds: u64) -> Self {
        Self(seconds)
    }

    /// The reading, in seconds since boot.
    #[must_use]
    pub const fn seconds(&self) -> u64 {
        self.0
    }

    /// This reading advanced by `seconds`, saturating.
    ///
    /// Saturating rather than checked: a deadline that overflows is a deadline
    /// at the end of time, which keeps the slot rather than reclaiming it
    /// early. Reclaiming early would tear down a live session on an arithmetic
    /// edge, which is a worse failure than holding one slot too long.
    #[must_use]
    pub const fn plus_seconds(&self, seconds: u64) -> Self {
        Self(self.0.saturating_add(seconds))
    }
}

/// The credential that authenticated a session, by its enrolled handle.
///
/// Sixteen bytes, matching `LEN_HANDLE`. This is a *handle*, never key
/// material: it is what the audit record names (`INV-AUTH-008`) and what
/// admission counts against, and it is safe to compare and to log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CredentialHandle([u8; LEN_HANDLE]);

impl CredentialHandle {
    /// Wraps sixteen bytes as a credential handle.
    #[must_use]
    pub const fn new(bytes: [u8; LEN_HANDLE]) -> Self {
        Self(bytes)
    }

    /// The handle's bytes, for audit correlation.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; LEN_HANDLE] {
        &self.0
    }
}

/// Why admission was refused.
///
/// Every variant is a `const` ceiling being enforced, and the three are
/// distinguished rather than collapsed because they mean different things to an
/// operator: the pool being full is a whole-server condition, and the other two
/// are about one credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDenied {
    /// Every slot in the fixed pool is occupied ([`MAX_SESSIONS`]).
    PoolFull,
    /// This credential already holds [`MAX_SESSIONS_PER_CREDENTIAL`] slots,
    /// counting half-open handshakes.
    CredentialLimitReached,
    /// An admin session is already live ([`MAX_ADMIN_SESSIONS`]).
    AdminLimitReached,
}

/// Why a handle did not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotError {
    /// The handle names a slot that has since been released and possibly
    /// reissued. It never resolves again.
    Stale,
}

/// An opaque reference to one live session slot.
///
/// Copyable so a caller can keep one while calling; it is not a capability and
/// grants nothing on its own. It is only meaningful to the [`SessionSlots`]
/// that issued it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlotHandle {
    index: usize,
    generation: u32,
}

/// One slot of the fixed pool.
#[derive(Debug, Clone, Copy)]
struct Slot {
    /// `None` when free. Holding the credential here is what lets admission
    /// count a credential's slots without a second table.
    credential: Option<CredentialHandle>,
    session_type: SessionType,
    session: Session,
    /// When this slot is reclaimed if nothing moves it.
    ///
    /// `HS_TIMEOUT` from acquisition while the handshake is half-open, then
    /// `IDLE_TIMEOUT` from the last activity once the session is established.
    deadline: Tick,
    /// Advanced on every release, so handles issued before it never resolve.
    generation: u32,
}

impl Slot {
    const fn free() -> Self {
        Self {
            credential: None,
            session_type: SessionType::Client,
            session: Session::new(),
            deadline: Tick::from_seconds(0),
            generation: 0,
        }
    }

    const fn is_occupied(&self) -> bool {
        self.credential.is_some()
    }
}

/// The `static` session pool of BSP v2 §9.1.
///
/// Fixed at build time: no allocator, no growth, and no client input changes
/// its size (`INV-MEM`, `INV-SERVE-002`).
#[derive(Debug)]
pub struct SessionSlots {
    slots: [Slot; MAX_SESSIONS],
}

impl Default for SessionSlots {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionSlots {
    /// An empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            slots: [Slot::free(); MAX_SESSIONS],
        }
    }

    /// Acquires a slot for `credential`, or denies.
    ///
    /// This is the admission point of §5.5, and it runs **before** the client
    /// has authenticated, so every limit it enforces counts half-open
    /// handshakes (`INV-SERVE-003`).
    ///
    /// The order of the checks is the order of their scope: the per-credential
    /// and admin limits are decided before the pool is searched, so a
    /// credential at its limit is refused for the same reason whether or not
    /// the server happens to be busy. An operator reading two different denials
    /// for the same client depending on unrelated load would be reading noise.
    ///
    /// # Errors
    ///
    /// [`AdmissionDenied`], one variant per ceiling.
    pub fn acquire(
        &mut self,
        credential: CredentialHandle,
        session_type: SessionType,
        now: Tick,
    ) -> Result<SlotHandle, AdmissionDenied> {
        if self.live_for_credential(credential) >= MAX_SESSIONS_PER_CREDENTIAL {
            return Err(AdmissionDenied::CredentialLimitReached);
        }
        if matches!(session_type, SessionType::Admin)
            && self.live_of_type(SessionType::Admin) >= MAX_ADMIN_SESSIONS
        {
            return Err(AdmissionDenied::AdminLimitReached);
        }

        for (index, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_occupied() {
                continue;
            }
            slot.credential = Some(credential);
            slot.session_type = session_type;
            slot.session = Session::new();
            slot.deadline = now.plus_seconds(u64::from(HS_TIMEOUT_SECONDS));
            return Ok(SlotHandle {
                index,
                generation: slot.generation,
            });
        }
        Err(AdmissionDenied::PoolFull)
    }

    /// Releases a slot and invalidates every handle to it.
    ///
    /// Teardown clears the credential and resets the protocol state, so nothing
    /// of the departing session is readable by whoever takes the slot next, and
    /// the generation advance makes the old handle unusable rather than merely
    /// unlucky.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has already been released.
    pub fn release(&mut self, handle: SlotHandle) -> Result<(), SlotError> {
        let slot = self.resolve_mut(handle)?;
        slot.credential = None;
        slot.session = Session::new();
        slot.session_type = SessionType::Client;
        slot.deadline = Tick::from_seconds(0);
        slot.generation = slot.generation.wrapping_add(1);
        Ok(())
    }

    /// The protocol state machine of the session this handle names.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn session(&self, handle: SlotHandle) -> Result<&Session, SlotError> {
        self.resolve(handle).map(|slot| &slot.session)
    }

    /// The protocol state machine, mutably.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn session_mut(&mut self, handle: SlotHandle) -> Result<&mut Session, SlotError> {
        self.resolve_mut(handle).map(|slot| &mut slot.session)
    }

    /// The session type frozen at admission.
    ///
    /// There is no setter. A session's type is decided when its slot is
    /// acquired and never changes, which is the `servd` half of "nothing
    /// promotes a client session into an admin one" — the kernel half is the
    /// capability model's, and `no_derivation_path_leads_between_serve_and_admin`
    /// is its proof.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn session_type(&self, handle: SlotHandle) -> Result<SessionType, SlotError> {
        self.resolve(handle).map(|slot| slot.session_type)
    }

    /// The credential that authenticated this slot, for audit correlation.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn credential(&self, handle: SlotHandle) -> Result<CredentialHandle, SlotError> {
        self.resolve(handle)
            .and_then(|slot| slot.credential.ok_or(SlotError::Stale))
    }

    /// How many slots are occupied, half-open handshakes included.
    #[must_use]
    pub fn live(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_occupied()).count()
    }

    /// How many slots this credential holds, half-open handshakes included.
    #[must_use]
    pub fn live_for_credential(&self, credential: CredentialHandle) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.credential == Some(credential))
            .count()
    }

    /// How many live slots are of this session type.
    #[must_use]
    pub fn live_of_type(&self, session_type: SessionType) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.is_occupied() && slot.session_type == session_type)
            .count()
    }

    /// Moves a slot from the handshake deadline to the idle one.
    ///
    /// Called when the session reaches `ESTABLISHED`. Until then the slot is
    /// held on `HS_TIMEOUT`, which is what bounds a replayed `ClientHello`.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn note_established(&mut self, handle: SlotHandle, now: Tick) -> Result<(), SlotError> {
        let slot = self.resolve_mut(handle)?;
        slot.deadline = now.plus_seconds(u64::from(IDLE_TIMEOUT_SECONDS));
        Ok(())
    }

    /// Postpones an established session's idle deadline.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn note_activity(&mut self, handle: SlotHandle, now: Tick) -> Result<(), SlotError> {
        self.note_established(handle, now)
    }

    /// When this slot is reclaimed if nothing moves it.
    ///
    /// # Errors
    ///
    /// [`SlotError::Stale`] if the handle has been released.
    pub fn deadline(&self, handle: SlotHandle) -> Result<Tick, SlotError> {
        self.resolve(handle).map(|slot| slot.deadline)
    }

    /// Reclaims every slot whose deadline has passed, and returns how many.
    ///
    /// **This is the other half of admission.** The per-credential limit counts
    /// half-open handshakes precisely so a replayed `ClientHello` cannot
    /// consume the pool — but a limit with no expiry only bounds how many slots
    /// one credential holds *at once*, not for how long, so without this the
    /// attacker holds them forever and the bound protects nobody. BSP v2 §9.1
    /// says the hold lasts "until `HS_TIMEOUT`"; this is what makes that
    /// sentence true.
    ///
    /// Reclaiming releases the slot, so every handle to it goes stale exactly
    /// as it would on an orderly teardown. A caller holding one learns from
    /// [`SlotError::Stale`] rather than from silence.
    pub fn expire(&mut self, now: Tick) -> usize {
        let mut reclaimed: usize = 0;
        for slot in &mut self.slots {
            if !slot.is_occupied() || slot.deadline > now {
                continue;
            }
            slot.credential = None;
            slot.session = Session::new();
            slot.session_type = SessionType::Client;
            slot.deadline = Tick::from_seconds(0);
            slot.generation = slot.generation.wrapping_add(1);
            reclaimed = reclaimed.saturating_add(1);
        }
        reclaimed
    }

    fn resolve(&self, handle: SlotHandle) -> Result<&Slot, SlotError> {
        let slot = self.slots.get(handle.index).ok_or(SlotError::Stale)?;
        if !slot.is_occupied() || slot.generation != handle.generation {
            return Err(SlotError::Stale);
        }
        Ok(slot)
    }

    fn resolve_mut(&mut self, handle: SlotHandle) -> Result<&mut Slot, SlotError> {
        let slot = self.slots.get_mut(handle.index).ok_or(SlotError::Stale)?;
        if !slot.is_occupied() || slot.generation != handle.generation {
            return Err(SlotError::Stale);
        }
        Ok(slot)
    }
}
