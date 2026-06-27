//! In-kernel fixed-pool relational store (sub-project A).
//!
//! Heap-free, `unsafe`-free, no external crates. The global runtime instance is
//! introduced in a later stage; this module is a pure, host-testable data type.

pub mod index;
pub mod schema;
pub mod store;
pub mod value;

#[cfg(test)]
mod tests;

pub use schema::{ColumnId, ColumnType, RowId, Schema, TableId};
pub use value::Value;

use index::HashIndex;
use schema::{MAX_COLUMNS, MAX_ROWS, MAX_TABLES};
use store::{RowSlot, Rows, TableMeta, Tables};
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
}

pub struct Database {
    tables: Tables,
    rows: Rows,
    index: HashIndex,
}

impl Database {
    pub const fn new() -> Database {
        Database {
            tables: Tables::new(),
            rows: Rows::new(),
            index: HashIndex::new(),
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
        let slot = self
            .rows
            .slots
            .get_mut(row.0 as usize)
            .ok_or(DbError::KeyNotFound)?;
        if !slot.live || slot.table != table.0 {
            return Err(DbError::KeyNotFound);
        }
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
            Some(Cell::Text { bytes, len }) => Ok(&bytes[..*len as usize]),
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
            self.next += 1;
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
            self.next += 1;
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
            if !(left_slot.live && left_slot.table == self.left_table) {
                self.outer += 1;
                self.inner = 0;
                continue;
            }
            let left_key = match left_slot.cells.get(self.left_col).copied() {
                Some(Cell::Integer(key)) => key,
                _ => {
                    self.outer += 1;
                    self.inner = 0;
                    continue;
                }
            };
            while self.inner < MAX_ROWS {
                let right_index = self.inner;
                self.inner += 1;
                let right_slot = &self.database.rows.slots[right_index];
                if right_slot.live && right_slot.table == self.right_table {
                    if let Some(Cell::Integer(right_key)) =
                        right_slot.cells.get(self.right_col).copied()
                    {
                        if right_key == left_key {
                            return Some((RowRef { slot: left_slot }, RowRef { slot: right_slot }));
                        }
                    }
                }
            }
            self.outer += 1;
            self.inner = 0;
        }
        None
    }
}
