extern crate alloc;

use super::schema::MAX_TABLES;
use super::*;

fn fresh() -> alloc::boxed::Box<Database> {
    alloc::boxed::Box::new(Database::new())
}

#[test]
fn create_table_assigns_ids_then_fails_closed_when_full() {
    let mut db = fresh();
    let schema = Schema::new(&[ColumnType::Integer, ColumnType::Text]).unwrap();
    for _ in 0..MAX_TABLES {
        db.create_table(schema).unwrap();
    }
    assert_eq!(db.create_table(schema), Err(DbError::TablePoolFull));
}

#[test]
fn schema_rejects_empty_and_overwide() {
    assert_eq!(Schema::new(&[]).err(), Some(DbError::ColumnCountMismatch));
    let wide = [ColumnType::Integer; super::schema::MAX_COLUMNS + 1];
    assert_eq!(Schema::new(&wide).err(), Some(DbError::ColumnCountMismatch));
}

#[test]
fn insert_then_get_round_trips_integer_and_text() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer, ColumnType::Text]).unwrap())
        .unwrap();
    let r = db
        .insert(t, &[Value::Integer(42), Value::Text(b"hello")])
        .unwrap();
    let row = db.get(t, r).unwrap();
    assert_eq!(row.integer(ColumnId(0)).unwrap(), 42);
    assert_eq!(row.text(ColumnId(1)).unwrap(), b"hello");
}

#[test]
fn insert_validation_fails_closed() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer, ColumnType::Text]).unwrap())
        .unwrap();
    assert_eq!(
        db.insert(t, &[Value::Integer(1)]),
        Err(DbError::ColumnCountMismatch)
    );
    assert_eq!(
        db.insert(t, &[Value::Text(b"x"), Value::Text(b"y")]),
        Err(DbError::ColumnTypeMismatch)
    );
    let too_long = [b'a'; super::schema::MAX_TEXT_LEN + 1];
    assert_eq!(
        db.insert(t, &[Value::Integer(1), Value::Text(&too_long)]),
        Err(DbError::TextTooLong)
    );
}

#[test]
fn row_pool_fills_then_fails_closed_and_reuses_after_delete() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer]).unwrap())
        .unwrap();
    let mut last = RowId(0);
    for n in 0..super::schema::MAX_ROWS as i64 {
        last = db.insert(t, &[Value::Integer(n)]).unwrap();
    }
    assert_eq!(
        db.insert(t, &[Value::Integer(999)]),
        Err(DbError::RowPoolFull)
    );
    db.delete(t, last).unwrap();
    // The freed slot is reusable; no growth.
    let reused = db.insert(t, &[Value::Integer(1000)]).unwrap();
    assert_eq!(reused, last);
    // get on the deleted-then-reused id now returns the new row.
    assert_eq!(
        db.get(t, reused).unwrap().integer(ColumnId(0)).unwrap(),
        1000
    );
}

#[test]
fn get_or_delete_of_dead_or_foreign_row_fails_closed() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer]).unwrap())
        .unwrap();
    let r = db.insert(t, &[Value::Integer(7)]).unwrap();
    db.delete(t, r).unwrap();
    assert_eq!(db.get(t, r).err(), Some(DbError::KeyNotFound));
    assert_eq!(db.delete(t, r).err(), Some(DbError::KeyNotFound));
}

#[test]
fn scan_returns_only_live_rows_in_slot_order() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer]).unwrap())
        .unwrap();
    let a = db.insert(t, &[Value::Integer(10)]).unwrap();
    let _b = db.insert(t, &[Value::Integer(20)]).unwrap();
    let c = db.insert(t, &[Value::Integer(30)]).unwrap();
    db.delete(t, a).unwrap();

    let mut seen: alloc::vec::Vec<(RowId, i64)> = alloc::vec::Vec::new();
    for (id, row) in db.scan(t) {
        seen.push((id, row.integer(ColumnId(0)).unwrap()));
    }
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].1, 20);
    assert_eq!(seen[1], (c, 30));
}
