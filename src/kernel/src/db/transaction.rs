//! Bounded, heap-free transaction undo log. Records prior row-slot values so
//! `abort` can restore them; `commit` simply discards the log.

use super::store::RowSlot;

pub const MAX_TX_OPS: usize = 256;

#[derive(Clone, Copy)]
pub(crate) struct TxEntry {
    pub(crate) slot_index: u32,
    pub(crate) previous: RowSlot,
}

impl TxEntry {
    pub(crate) const EMPTY: TxEntry = TxEntry {
        slot_index: 0,
        previous: RowSlot::EMPTY,
    };
}

pub(crate) struct TxLog {
    pub(crate) active: bool,
    pub(crate) entries: [TxEntry; MAX_TX_OPS],
    pub(crate) count: usize,
}

impl TxLog {
    pub(crate) const fn new() -> TxLog {
        TxLog {
            active: false,
            entries: [TxEntry::EMPTY; MAX_TX_OPS],
            count: 0,
        }
    }

    /// Records the prior value of a slot about to be mutated. Fails closed when
    /// the log is full so the caller can refuse the mutation.
    pub(crate) fn record(&mut self, slot_index: u32, previous: RowSlot) -> Result<(), ()> {
        if self.count >= MAX_TX_OPS {
            return Err(());
        }
        self.entries[self.count] = TxEntry {
            slot_index,
            previous,
        };
        self.count = self.count.saturating_add(1);
        Ok(())
    }

    pub(crate) fn clear(&mut self) {
        self.active = false;
        self.count = 0;
    }
}
