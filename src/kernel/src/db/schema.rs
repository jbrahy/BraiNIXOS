//! Fixed-arity schema and identifier types for the in-kernel relational store.

use super::DbError;

pub const MAX_TABLES: usize = 8;
pub const MAX_COLUMNS: usize = 8;
pub const MAX_TEXT_LEN: usize = 32;
pub const MAX_ROWS: usize = 1024;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ColumnType {
    Integer,
    Text,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableId(pub(crate) u16);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RowId(pub(crate) u32);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ColumnId(pub usize);

#[derive(Clone, Copy)]
pub struct Schema {
    pub(crate) types: [ColumnType; MAX_COLUMNS],
    pub(crate) len: usize,
}

impl Schema {
    pub(crate) const EMPTY: Schema = Schema {
        types: [ColumnType::Integer; MAX_COLUMNS],
        len: 0,
    };

    /// Builds a schema from a column-type list. Fails closed if the list is
    /// empty or wider than `MAX_COLUMNS`.
    pub fn new(column_types: &[ColumnType]) -> Result<Schema, DbError> {
        if column_types.is_empty() || column_types.len() > MAX_COLUMNS {
            return Err(DbError::ColumnCountMismatch);
        }
        let mut types = [ColumnType::Integer; MAX_COLUMNS];
        // Zip rather than index: the length was just bounds-checked above, and
        // copying by iterator removes the possibility of the two slices
        // disagreeing at all.
        for (slot, declared) in types.iter_mut().zip(column_types.iter()) {
            *slot = *declared;
        }
        Ok(Schema {
            types,
            len: column_types.len(),
        })
    }

    pub fn column_count(&self) -> usize {
        self.len
    }
}
