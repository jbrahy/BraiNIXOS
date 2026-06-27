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

#[test]
fn create_index_then_find_by_hits_and_misses() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer, ColumnType::Text]).unwrap())
        .unwrap();
    let r1 = db
        .insert(t, &[Value::Integer(100), Value::Text(b"a")])
        .unwrap();
    let _r2 = db
        .insert(t, &[Value::Integer(200), Value::Text(b"b")])
        .unwrap();
    db.create_index(t, ColumnId(0)).unwrap();
    assert_eq!(db.find_by(t, ColumnId(0), 100).unwrap(), r1);
    assert_eq!(
        db.find_by(t, ColumnId(0), 999).err(),
        Some(DbError::KeyNotFound)
    );
    // Inserts after index creation are indexed too.
    let r3 = db
        .insert(t, &[Value::Integer(300), Value::Text(b"c")])
        .unwrap();
    assert_eq!(db.find_by(t, ColumnId(0), 300).unwrap(), r3);
}

#[test]
fn unique_index_rejects_duplicates_and_stays_consistent() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer]).unwrap())
        .unwrap();
    let r1 = db.insert(t, &[Value::Integer(5)]).unwrap();
    db.create_unique_index(t, ColumnId(0)).unwrap();
    // Duplicate key is refused and the row is NOT inserted.
    assert_eq!(
        db.insert(t, &[Value::Integer(5)]),
        Err(DbError::DuplicateKey)
    );
    // Delete the holder, then the key is insertable again and findable.
    db.delete(t, r1).unwrap();
    db.create_unique_index(t, ColumnId(0)).unwrap(); // rebuild after delete
    let r2 = db.insert(t, &[Value::Integer(5)]).unwrap();
    assert_eq!(db.find_by(t, ColumnId(0), 5).unwrap(), r2);
}

#[test]
fn select_where_filters_on_integer_predicates() {
    let mut db = fresh();
    let t = db
        .create_table(Schema::new(&[ColumnType::Integer]).unwrap())
        .unwrap();
    for n in [1i64, 5, 10, 15, 20] {
        db.insert(t, &[Value::Integer(n)]).unwrap();
    }
    let collect = |db: &Database, p: Predicate| -> alloc::vec::Vec<i64> {
        db.select_where(t, ColumnId(0), p)
            .map(|(_, row)| row.integer(ColumnId(0)).unwrap())
            .collect()
    };
    assert_eq!(collect(&db, Predicate::Eq(10)), alloc::vec![10]);
    assert_eq!(collect(&db, Predicate::Lt(10)), alloc::vec![1, 5]);
    assert_eq!(collect(&db, Predicate::Gt(10)), alloc::vec![15, 20]);
    assert_eq!(
        collect(&db, Predicate::Range(5, 15)),
        alloc::vec![5, 10, 15]
    );
}
