//! Write-once audit ring buffer for kernel security events.
//!
//! The ring buffer is backed by BSS (zero-initialized static storage) with no
//! dynamic allocation. Each entry is fixed-size (24 bytes) for constant-time
//! append. The buffer wraps at AUDIT_LOG_CAPACITY; oldest entries are overwritten.
//!
//! Enforces INV-AUD-001 and INV-AUD-003 (ring wrap never panics or allocates).

use super::audit_event_type::AuditEventType;

/// A single audit log entry. Fixed-size for constant-time append.
///
/// Format per D-07: sequence number, RDTSC timestamp, event type,
/// relevant slot index (or 0 for non-capability events).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct AuditLogEntry {
    pub sequence_number: u64,
    pub timestamp: u64,
    pub event_type: AuditEventType,
    pub capability_slot_index: u8,
    pub _padding: [u8; 6], // Pad to 24 bytes for alignment
}

impl AuditLogEntry {
    /// Returns a zeroed audit log entry representing an empty slot.
    pub const fn empty() -> Self {
        AuditLogEntry {
            sequence_number: 0,
            timestamp: 0,
            event_type: AuditEventType::BootSequenceEvent,
            capability_slot_index: 0,
            _padding: [0u8; 6],
        }
    }
}

/// Total number of entries in the audit ring buffer (~96 KiB at 24 bytes/entry).
pub const AUDIT_LOG_CAPACITY: usize = 4096;

/// BSS-backed fixed-size ring buffer for kernel audit log entries.
///
/// The buffer wraps at AUDIT_LOG_CAPACITY — oldest entries are overwritten.
/// Sequence numbers are monotonically increasing across wraps.
///
/// Enforces INV-AUD-001: all capability authority changes produce an entry.
/// Enforces INV-AUD-003: no panic, no allocation on overflow (ring wrap).
pub struct AuditRingBuffer {
    entries: [AuditLogEntry; AUDIT_LOG_CAPACITY],
    write_head: usize,
    sequence_counter: u64,
    is_write_protected: bool,
}

impl Default for AuditRingBuffer {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditRingBuffer {
    /// Creates a new ring buffer with all entries zeroed and counters at zero.
    pub const fn new() -> Self {
        AuditRingBuffer {
            entries: [AuditLogEntry::empty(); AUDIT_LOG_CAPACITY],
            write_head: 0,
            sequence_counter: 0,
            is_write_protected: false,
        }
    }

    /// Appends a security event to the ring buffer.
    ///
    /// If the buffer is hardware write-protected, temporarily unprotects the
    /// target page, writes the entry, then reprotects. Wraps at capacity.
    pub fn append_entry(
        &mut self,
        event_type: AuditEventType,
        capability_slot_index: u8,
        timestamp: u64,
    ) {
        let entry = self.create_audit_log_entry(event_type, capability_slot_index, timestamp);
        self.write_entry_at_head(entry);
        self.advance_write_head();
        self.increment_sequence_counter();
    }

    /// Returns the entry at the given index, or None if index is out of range.
    pub fn read_entry(&self, index: usize) -> Option<&AuditLogEntry> {
        if index < AUDIT_LOG_CAPACITY {
            Some(&self.entries[index])
        } else {
            None
        }
    }

    /// Returns the entry at the given sequence number if it still exists in the ring buffer.
    ///
    /// Computes the slot index from `target_sequence % AUDIT_LOG_CAPACITY`. Returns
    /// `None` if the stored entry's sequence number does not match `target_sequence`
    /// (meaning the slot has been overwritten since that sequence was written).
    pub fn read_entry_at_sequence(&self, target_sequence: u64) -> Option<&AuditLogEntry> {
        let slot_index = (target_sequence as usize) % AUDIT_LOG_CAPACITY;
        let stored_entry = &self.entries[slot_index];
        let sequence_matches = stored_entry.sequence_number == target_sequence;
        if sequence_matches { Some(stored_entry) } else { None }
    }

    /// Returns the current value of the monotonic sequence counter.
    ///
    /// Equal to the total number of entries appended since construction.
    pub fn current_sequence_counter(&self) -> u64 {
        self.sequence_counter
    }

    /// Returns true if the ring buffer pages are currently hardware write-protected.
    ///
    /// Enforces INV-AUD-001: audit log entries cannot be modified after write.
    /// Verified by: process::tests::test_audit_log_pages_are_write_protected_after_initialization
    pub fn is_write_protected(&self) -> bool {
        self.is_write_protected
    }

    /// Sets the hardware write-protection flag to the given value.
    ///
    /// Called by `audit_log_protection` functions to update the flag in sync
    /// with any x86_64 PTE manipulation performed externally.
    pub fn set_write_protected(&mut self, protected: bool) {
        self.is_write_protected = protected;
    }

    /// Returns the next sequence number to be assigned (total entries written).
    pub fn current_sequence_number(&self) -> u64 {
        self.sequence_counter
    }

    /// Returns the total number of entries written to the buffer.
    pub fn entry_count(&self) -> u64 {
        self.sequence_counter
    }

    /// Builds an AuditLogEntry with the current sequence number.
    fn create_audit_log_entry(
        &self,
        event_type: AuditEventType,
        capability_slot_index: u8,
        timestamp: u64,
    ) -> AuditLogEntry {
        AuditLogEntry {
            sequence_number: self.sequence_counter,
            timestamp,
            event_type,
            capability_slot_index,
            _padding: [0u8; 6],
        }
    }

    /// Writes the given entry at the current write head position.
    ///
    /// When write-protected, temporarily clears the protection flag, writes the
    /// entry, then restores the flag. The x86_64 PTE manipulation is handled
    /// externally by `audit_log_protection` when called from the boot sequence.
    fn write_entry_at_head(&mut self, entry: AuditLogEntry) {
        let was_protected = self.is_write_protected;
        self.is_write_protected = false;
        self.entries[self.write_head] = entry;
        self.is_write_protected = was_protected;
    }

    /// Advances write_head by one, wrapping at AUDIT_LOG_CAPACITY.
    ///
    /// # Safety of wrap arithmetic
    // #[allow(clippy::arithmetic_side_effects)] — write_head always < AUDIT_LOG_CAPACITY
    // by modulo operation; overflow is structurally impossible.
    fn advance_write_head(&mut self) {
        #[allow(clippy::arithmetic_side_effects)]
        // write_head always < AUDIT_LOG_CAPACITY by modulo operation
        {
            self.write_head = (self.write_head + 1) % AUDIT_LOG_CAPACITY;
        }
    }

    /// Increments the monotonic sequence counter.
    fn increment_sequence_counter(&mut self) {
        #[allow(clippy::arithmetic_side_effects)]
        // sequence_counter monotonically increases; u64 range is sufficient for all
        // practical kernel lifetimes (18.4 quintillion events before wrap)
        {
            self.sequence_counter += 1;
        }
    }
}
