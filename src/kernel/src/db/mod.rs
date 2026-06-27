//! In-kernel fixed-pool relational store (sub-project A).
//!
//! Heap-free, `unsafe`-free, no external crates. The global runtime instance is
//! introduced in a later stage; this module is a pure, host-testable data type.

pub mod schema;
pub mod store;
pub mod value;

#[cfg(test)]
mod tests;

pub use schema::{ColumnId, ColumnType, RowId, Schema, TableId};
pub use value::Value;

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
}

impl Database {
    pub const fn new() -> Database {
        Database {
            tables: Tables::new(),
            rows: Rows::new(),
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
