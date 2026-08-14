//! The serving log: fixed pool, and no session can read another's rows
//! (P2-T7, part).
//!
//! `INV-SERVE`'s blast-radius entry is one client reading another client's
//! session state. A log is where that leaks quietly: everything about a
//! session's activity passes through it, and a read interface that takes a
//! *filter* rather than a *capability* is one wrong comparison away from
//! returning somebody else's rows.
//!
//! So there is no filter here. [`ServingLog::read`] takes the reader's own
//! session slot and can return nothing else — the slot is not a parameter the
//! caller varies to choose whose rows to see; it is who the caller is.
//!
//! # Fixed pool, oldest-first eviction
//!
//! `INV-MEM` and `INV-AUD-003`: capacity is a `const`, so a client that
//! generates events cannot grow the log. When it is full the oldest row is
//! overwritten, which is the honest trade — losing the oldest event is a known
//! cost, and refusing to record new ones would let a noisy session blind the
//! audit trail for everybody else, which is worse.
//!
//! # What P2-T7 still owes
//!
//! Persistence. The kernel's `db/` fixed-pool store is where these rows
//! eventually live, and this is the shape of the row and the isolation rule
//! rather than the storage. Nothing here writes a disk.

use brainix_bsp::MAX_SESSIONS;

/// Rows the log holds before it begins overwriting.
pub const LOG_CAPACITY: usize = 64;

/// One row: which session, what happened, and when.
///
/// The event is a `u8` tag rather than a payload. A row that could carry bytes
/// would be a row that could carry a prompt, and this log is read back over an
/// admin session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogRow {
    /// The session slot the event belongs to.
    pub session_slot: usize,
    /// The event's tag, from `brainix_auditd::event::EventKind`.
    pub event_tag: u8,
    /// Monotonic position in the log.
    pub sequence: u64,
}

/// A fixed-capacity log of serving events.
///
/// Generic in its capacity so that a proof can be about the *algorithm* rather
/// than about 64 rows: `ServingLogOf<4>` obeys the same rules and fits in a
/// model checker, where the production size does not. [`ServingLog`] is the
/// production instance and is what everything but the harnesses uses.
#[derive(Debug, Clone, Copy)]
pub struct ServingLogOf<const CAPACITY: usize> {
    rows: [Option<LogRow>; CAPACITY],
    next: usize,
    sequence: u64,
}

/// The log as the server holds it: [`LOG_CAPACITY`] rows.
pub type ServingLog = ServingLogOf<LOG_CAPACITY>;

impl<const CAPACITY: usize> Default for ServingLogOf<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> ServingLogOf<CAPACITY> {
    /// An empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rows: [None; CAPACITY],
            next: 0,
            sequence: 0,
        }
    }

    /// Records an event for a session, overwriting the oldest row when full.
    ///
    /// Returns the sequence number assigned, or `None` if the slot is not one
    /// the server can admit — a row for a session that cannot exist is a row
    /// nothing could ever read back, and writing it would only mislead.
    pub fn append(&mut self, session_slot: usize, event_tag: u8) -> Option<u64> {
        if session_slot >= MAX_SESSIONS {
            return None;
        }
        let sequence = self.sequence;
        let row = LogRow {
            session_slot,
            event_tag,
            sequence,
        };
        *self.rows.get_mut(self.next)? = Some(row);
        // `checked_rem` rather than `%`: CAPACITY is a const generic, so a
        // zero-capacity instantiation is expressible and a bare `%` would be a
        // division by zero the kernel's lint refuses on sight. A log with no
        // rows wraps to slot zero and stores nothing, which is the honest
        // behaviour of a log that was asked to hold nothing.
        self.next = self
            .next
            .saturating_add(1)
            .checked_rem(CAPACITY)
            .unwrap_or(0);
        self.sequence = self.sequence.saturating_add(1);
        Some(sequence)
    }

    /// Reads up to `limit` of **this session's** rows, oldest first.
    ///
    /// `reader_slot` is who the caller is, not a filter it chooses: there is no
    /// argument through which a session names another session's rows, which is
    /// what makes the isolation structural rather than a comparison that has to
    /// be right on every path.
    ///
    /// Returns how many rows were written into `out`.
    pub fn read(&self, reader_slot: usize, out: &mut [LogRow]) -> usize {
        let mut written = 0;
        for row in self.rows.iter().flatten() {
            if row.session_slot != reader_slot {
                continue;
            }
            let Some(slot) = out.get_mut(written) else {
                break;
            };
            *slot = *row;
            written = written.saturating_add(1);
        }
        written
    }

    /// How many rows the log currently holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.iter().flatten().count()
    }

    /// Whether the log holds no rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops every row belonging to a session.
    ///
    /// Called at teardown. A slot is reused, and rows outliving their session
    /// would be readable by whoever takes the slot next — the same reuse hazard
    /// the session handles carry a generation for, in a different table.
    pub fn forget_session(&mut self, session_slot: usize) {
        for row in &mut self.rows {
            if row.is_some_and(|held| held.session_slot == session_slot) {
                *row = None;
            }
        }
    }
}
