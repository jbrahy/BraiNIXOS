//! Input values and the fixed-width stored cell.

use super::schema::{ColumnType, MAX_TEXT_LEN};
use super::DbError;

/// A value supplied by a caller for insertion or comparison.
#[derive(Clone, Copy)]
pub enum Value<'a> {
    Integer(i64),
    Text(&'a [u8]),
}

/// A stored cell: fixed width, owns its bytes (no references, no allocation).
#[derive(Clone, Copy)]
pub(crate) enum Cell {
    Empty,
    Integer(i64),
    Text { bytes: [u8; MAX_TEXT_LEN], len: u8 },
}

impl Cell {
    /// Validates `value` against `column_type` and converts to a stored cell.
    /// Fails closed on type mismatch or over-long text.
    pub(crate) fn from_value(column_type: ColumnType, value: &Value) -> Result<Cell, DbError> {
        match (column_type, value) {
            (ColumnType::Integer, Value::Integer(number)) => Ok(Cell::Integer(*number)),
            (ColumnType::Text, Value::Text(input)) => {
                if input.len() > MAX_TEXT_LEN {
                    return Err(DbError::TextTooLong);
                }
                let mut bytes = [0u8; MAX_TEXT_LEN];
                bytes[..input.len()].copy_from_slice(input);
                Ok(Cell::Text {
                    bytes,
                    len: input.len() as u8,
                })
            }
            _ => Err(DbError::ColumnTypeMismatch),
        }
    }
}
