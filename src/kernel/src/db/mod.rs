//! In-kernel fixed-pool relational store (sub-project A).
//!
//! Heap-free, `unsafe`-free, no external crates. The global runtime instance is
//! introduced in a later stage; this module is a pure, host-testable data type.

pub mod index;
pub mod schema;
pub mod store;
pub mod transaction;
pub mod value;

#[cfg(test)]
mod tests;

pub use schema::{ColumnId, ColumnType, RowId, Schema, TableId};
pub use value::Value;

use index::HashIndex;
use schema::{MAX_COLUMNS, MAX_ROWS, MAX_TABLES};
use store::{RowSlot, Rows, TableMeta, Tables};
use transaction::TxLog;
use value::Cell;

/// Every fallible outcome. There is no panic path on caller input.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DbError {
    TablePoolFull,
    RowPoolFull,
    IndexFull,
    TableNotFound,
    ColumnCountMismatch,
    ColumnTypeMismatch,
    TextTooLong,
    DuplicateKey,
    KeyNotFound,
    TxAlreadyActive,
    TxNotActive,
    TxLogFull,
}

pub struct Database {
    tables: Tables,
    rows: Rows,
    index: HashIndex,
    tx: TxLog,
}

impl Database {
    pub const fn new() -> Database {
        Database {
            tables: Tables::new(),
            rows: Rows::new(),
            index: HashIndex::new(),
            tx: TxLog::new(),
        }
    }

    /// Allocates a table from the fixed table pool. Fails closed when full.
    pub fn create_table(&mut self, schema: Schema) -> Result<TableId, DbError> {
        for index in 0..MAX_TABLES {
            if !self.tables.metas[index].in_use {
                self.tables.metas[index] = TableMeta {
                    schema,
                    in_use: true,
                };
                return Ok(TableId(index as u16));
            }
        }
        Err(DbError::TablePoolFull)
    }

    pub(crate) fn table_meta(&self, table: TableId) -> Result<&TableMeta, DbError> {
        let meta = self
            .tables
            .metas
            .get(table.0 as usize)
            .ok_or(DbError::TableNotFound)?;
        if !meta.in_use {
            return Err(DbError::TableNotFound);
        }
        Ok(meta)
    }

    /// Inserts a validated row into the shared row arena. Fails closed if the
    /// column count or any value type mismatches, or the row pool is full.
    pub fn insert(&mut self, table: TableId, row: &[Value]) -> Result<RowId, DbError> {
        let schema = self.table_meta(table)?.schema;
        if row.len() != schema.column_count() {
            return Err(DbError::ColumnCountMismatch);
        }
        let mut cells = [Cell::Empty; MAX_COLUMNS];
        for column in 0..row.len() {
            cells[column] = Cell::from_value(schema.types[column], &row[column])?;
        }
        for index in 0..MAX_ROWS {
            if !self.rows.slots[index].live {
                if self.tx.active {
                    let prior = self.rows.slots[index];
                    if self.tx.record(index as u32, prior).is_err() {
                        return Err(DbError::TxLogFull);
                    }
                }
                self.rows.slots[index] = RowSlot {
                    table: table.0,
                    cells,
                    live: true,
                };
                if self.index.covers(table.0, self.index.column) {
                    if let Cell::Integer(key) = cells[self.index.column] {
                        if let Err(error) = self.index.insert(key, index as u32) {
                            // Roll back the row write: the insert is refused.
                            self.rows.slots[index] = RowSlot::EMPTY;
                            return Err(error);
                        }
                    }
                }
                return Ok(RowId(index as u32));
            }
        }
        Err(DbError::RowPoolFull)
    }

    /// Returns a typed view of a live row owned by `table`.
    pub fn get(&self, table: TableId, row: RowId) -> Result<RowRef<'_>, DbError> {
        let slot = self
            .rows
            .slots
            .get(row.0 as usize)
            .ok_or(DbError::KeyNotFound)?;
        if !slot.live || slot.table != table.0 {
            return Err(DbError::KeyNotFound);
        }
        Ok(RowRef { slot })
    }

    /// Frees a live row owned by `table` (tombstone; slot becomes reusable).
    pub fn delete(&mut self, table: TableId, row: RowId) -> Result<(), DbError> {
        let slot_index = row.0 as usize;
        let slot = self
            .rows
            .slots
            .get(slot_index)
            .ok_or(DbError::KeyNotFound)?;
        if !slot.live || slot.table != table.0 {
            return Err(DbError::KeyNotFound);
        }
        if self.tx.active {
            let previous = self.rows.slots[slot_index];
            if self.tx.record(slot_index as u32, previous).is_err() {
                return Err(DbError::TxLogFull);
            }
        }
        let slot = &mut self.rows.slots[slot_index];
        slot.live = false;
        slot.table = u16::MAX;
        Ok(())
    }

    /// Iterates live rows owned by `table`, in row-slot order.
    pub fn scan(&self, table: TableId) -> RowScan<'_> {
        RowScan {
            database: self,
            table: table.0,
            next: 0,
        }
    }

    /// Builds a hash index on an Integer column by scanning existing rows.
    /// Fails closed if the column is not Integer or the index overflows.
    pub fn create_index(&mut self, table: TableId, column: ColumnId) -> Result<(), DbError> {
        let schema = self.table_meta(table)?.schema;
        if schema.types.get(column.0) != Some(&ColumnType::Integer) {
            return Err(DbError::ColumnTypeMismatch);
        }
        self.index.reset(table.0, column.0, false);
        for index in 0..MAX_ROWS {
            let slot = &self.rows.slots[index];
            if slot.live && slot.table == table.0 {
                if let Cell::Integer(key) = slot.cells[column.0] {
                    self.index.insert(key, index as u32)?;
                }
            }
        }
        Ok(())
    }

    /// Point lookup by Integer key. Uses the index when it covers the column,
    /// otherwise a linear scan. Fails closed with `KeyNotFound`.
    pub fn find_by(&self, table: TableId, column: ColumnId, key: i64) -> Result<RowId, DbError> {
        self.table_meta(table)?;
        if self.index.covers(table.0, column.0) {
            if let Some(candidate) = self.index.find(key) {
                let slot = self.rows.slots.get(candidate as usize);
                if slot.map(|s| s.live && s.table == table.0).unwrap_or(false) {
                    return Ok(RowId(candidate));
                }
            }
            // stale/dead/foreign index hit — fall through to the authoritative linear scan
        }
        for index in 0..MAX_ROWS {
            let slot = &self.rows.slots[index];
            if slot.live && slot.table == table.0 {
                if let Some(Cell::Integer(value)) = slot.cells.get(column.0).copied() {
                    if value == key {
                        return Ok(RowId(index as u32));
                    }
                }
            }
        }
        Err(DbError::KeyNotFound)
    }

    /// Like `create_index` but rejects duplicate keys on build and on insert.
    pub fn create_unique_index(&mut self, table: TableId, column: ColumnId) -> Result<(), DbError> {
        let schema = self.table_meta(table)?.schema;
        if schema.types.get(column.0) != Some(&ColumnType::Integer) {
            return Err(DbError::ColumnTypeMismatch);
        }
        self.index.reset(table.0, column.0, true);
        for index in 0..MAX_ROWS {
            let slot = &self.rows.slots[index];
            if slot.live && slot.table == table.0 {
                if let Cell::Integer(key) = slot.cells[column.0] {
                    self.index.insert(key, index as u32)?;
                }
            }
        }
        Ok(())
    }

    /// Starts a transaction. Only one may be active at a time.
    pub fn begin(&mut self) -> Result<(), DbError> {
        if self.tx.active {
            return Err(DbError::TxAlreadyActive);
        }
        self.tx.clear();
        self.tx.active = true;
        Ok(())
    }

    /// Commits the active transaction: changes persist, the undo log is dropped.
    pub fn commit(&mut self) -> Result<(), DbError> {
        if !self.tx.active {
            return Err(DbError::TxNotActive);
        }
        self.tx.clear();
        Ok(())
    }

    /// Aborts the active transaction: restores every recorded prior row slot in
    /// reverse, then deactivates the index (it must be rebuilt — same contract
    /// as a post-delete index).
    pub fn abort(&mut self) -> Result<(), DbError> {
        if !self.tx.active {
            return Err(DbError::TxNotActive);
        }
        let count = self.tx.count;
        let mut i = count;
        while i > 0 {
            i = i.saturating_sub(1);
            let entry = self.tx.entries[i];
            let slot_index = entry.slot_index as usize;
            if slot_index < MAX_ROWS {
                self.rows.slots[slot_index] = entry.previous;
            }
        }
        self.index.active = false;
        self.tx.clear();
        Ok(())
    }

    /// Bounded nested-loop equi-join: yields `(left_row, right_row)` pairs whose
    /// Integer `left_col` and `right_col` are equal. Non-Integer columns or
    /// out-of-range column ids simply yield no matches (fail-closed).
    pub fn join_eq(
        &self,
        left: TableId,
        left_col: ColumnId,
        right: TableId,
        right_col: ColumnId,
    ) -> JoinScan<'_> {
        JoinScan {
            database: self,
            left_table: left.0,
            left_col: left_col.0,
            right_table: right.0,
            right_col: right_col.0,
            outer: 0,
            inner: 0,
        }
    }

    /// Scans `table`, yielding live rows whose Integer `column` satisfies `pred`.
    /// `Range(low, high)` is inclusive on both ends.
    pub fn select_where(
        &self,
        table: TableId,
        column: ColumnId,
        pred: Predicate,
    ) -> PredicateScan<'_> {
        PredicateScan {
            database: self,
            table: table.0,
            column: column.0,
            pred,
            next: 0,
        }
    }
}

impl Default for Database {
    fn default() -> Database {
        Database::new()
    }
}

/// A borrowed, typed view of one stored row.
pub struct RowRef<'a> {
    slot: &'a RowSlot,
}

impl<'a> RowRef<'a> {
    pub fn integer(&self, column: ColumnId) -> Result<i64, DbError> {
        match self.slot.cells.get(column.0) {
            Some(Cell::Integer(number)) => Ok(*number),
            _ => Err(DbError::ColumnTypeMismatch),
        }
    }

    pub fn text(&self, column: ColumnId) -> Result<&[u8], DbError> {
        match self.slot.cells.get(column.0) {
            Some(Cell::Text { bytes, len: used }) => Ok(&bytes[..*used as usize]),
            _ => Err(DbError::ColumnTypeMismatch),
        }
    }
}

pub struct RowScan<'a> {
    database: &'a Database,
    table: u16,
    next: usize,
}

impl<'a> Iterator for RowScan<'a> {
    type Item = (RowId, RowRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < MAX_ROWS {
            let index = self.next;
            self.next = self.next.saturating_add(1);
            let slot = &self.database.rows.slots[index];
            if slot.live && slot.table == self.table {
                return Some((RowId(index as u32), RowRef { slot }));
            }
        }
        None
    }
}

#[derive(Clone, Copy)]
pub enum Predicate {
    Eq(i64),
    Lt(i64),
    Gt(i64),
    Range(i64, i64),
}

impl Predicate {
    fn matches(&self, value: i64) -> bool {
        match *self {
            Predicate::Eq(target) => value == target,
            Predicate::Lt(bound) => value < bound,
            Predicate::Gt(bound) => value > bound,
            Predicate::Range(low, high) => value >= low && value <= high,
        }
    }
}

pub struct PredicateScan<'a> {
    database: &'a Database,
    table: u16,
    column: usize,
    pred: Predicate,
    next: usize,
}

impl<'a> Iterator for PredicateScan<'a> {
    type Item = (RowId, RowRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.next < MAX_ROWS {
            let index = self.next;
            self.next = self.next.saturating_add(1);
            let slot = &self.database.rows.slots[index];
            if slot.live && slot.table == self.table {
                if let Some(Cell::Integer(value)) = slot.cells.get(self.column).copied() {
                    if self.pred.matches(value) {
                        return Some((RowId(index as u32), RowRef { slot }));
                    }
                }
            }
        }
        None
    }
}

pub struct JoinScan<'a> {
    database: &'a Database,
    left_table: u16,
    left_col: usize,
    right_table: u16,
    right_col: usize,
    outer: usize,
    inner: usize,
}

impl<'a> Iterator for JoinScan<'a> {
    type Item = (RowRef<'a>, RowRef<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.outer < MAX_ROWS {
            let left_slot = &self.database.rows.slots[self.outer];
            let Some(left_key) = integer_key(left_slot, self.left_table, self.left_col) else {
                self.advance_outer();
                continue;
            };
            while self.inner < MAX_ROWS {
                let right_index = self.inner;
                self.inner = self.inner.saturating_add(1);
                let right_slot = &self.database.rows.slots[right_index];
                if integer_key(right_slot, self.right_table, self.right_col) == Some(left_key) {
                    return Some((RowRef { slot: left_slot }, RowRef { slot: right_slot }));
                }
            }
            self.advance_outer();
        }
        None
    }
}

impl JoinScan<'_> {
    /// Moves to the next left row and restarts the inner scan.
    fn advance_outer(&mut self) {
        self.outer = self.outer.saturating_add(1);
        self.inner = 0;
    }
}

/// The integer key of `slot` for `column`, or `None` unless the row is live,
/// belongs to `table`, and holds an integer there.
///
/// Extracted so the join's two sides ask the same question the same way; both
/// used to spell it out inline, which is what pushed `next` past the complexity
/// bar and made the two conditions drift-prone.
fn integer_key(slot: &RowSlot, table: u16, column: usize) -> Option<i64> {
    if !(slot.live && slot.table == table) {
        return None;
    }
    match slot.cells.get(column).copied() {
        Some(Cell::Integer(key)) => Some(key),
        _ => None,
    }
}
