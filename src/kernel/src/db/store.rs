//! Fixed-pool table metadata and row arena.

use super::schema::{Schema, MAX_COLUMNS, MAX_ROWS, MAX_TABLES};
use super::value::Cell;

#[derive(Clone, Copy)]
pub(crate) struct TableMeta {
    pub(crate) schema: Schema,
    pub(crate) in_use: bool,
}

impl TableMeta {
    pub(crate) const EMPTY: TableMeta = TableMeta {
        schema: Schema::EMPTY,
        in_use: false,
    };
}

#[derive(Clone, Copy)]
pub(crate) struct RowSlot {
    /// Owning table index, or `u16::MAX` when the slot is free.
    pub(crate) table: u16,
    pub(crate) cells: [Cell; MAX_COLUMNS],
    pub(crate) live: bool,
}

impl RowSlot {
    pub(crate) const EMPTY: RowSlot = RowSlot {
        table: u16::MAX,
        cells: [Cell::Empty; MAX_COLUMNS],
        live: false,
    };
}

pub(crate) struct Tables {
    pub(crate) metas: [TableMeta; MAX_TABLES],
}

impl Tables {
    pub(crate) const fn new() -> Tables {
        Tables {
            metas: [TableMeta::EMPTY; MAX_TABLES],
        }
    }
}

pub(crate) struct Rows {
    pub(crate) slots: [RowSlot; MAX_ROWS],
}

impl Rows {
    pub(crate) const fn new() -> Rows {
        Rows {
            slots: [RowSlot::EMPTY; MAX_ROWS],
        }
    }
}
