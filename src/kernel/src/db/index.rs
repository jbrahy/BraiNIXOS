//! Fixed-capacity open-addressing hash index on one Integer column.
//! In-tree FNV-1a hash; no external crate.

use super::schema::MAX_ROWS;

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn hash_key(key: i64) -> usize {
    let mut hash = FNV_OFFSET;
    let bytes = (key as u64).to_le_bytes();
    let mut index = 0;
    while index < bytes.len() {
        hash ^= bytes[index] as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
        index += 1;
    }
    (hash % MAX_ROWS as u64) as usize
}

#[derive(Clone, Copy)]
struct Bucket {
    occupied: bool,
    key: i64,
    row: u32,
}

impl Bucket {
    const EMPTY: Bucket = Bucket {
        occupied: false,
        key: 0,
        row: 0,
    };
}

pub(crate) struct HashIndex {
    pub(crate) active: bool,
    pub(crate) table: u16,
    pub(crate) column: usize,
    pub(crate) unique: bool,
    buckets: [Bucket; MAX_ROWS],
    count: usize,
}

impl HashIndex {
    pub(crate) const fn new() -> HashIndex {
        HashIndex {
            active: false,
            table: u16::MAX,
            column: 0,
            unique: false,
            buckets: [Bucket::EMPTY; MAX_ROWS],
            count: 0,
        }
    }

    pub(crate) fn reset(&mut self, table: u16, column: usize, unique: bool) {
        self.active = true;
        self.table = table;
        self.column = column;
        self.unique = unique;
        self.buckets = [Bucket::EMPTY; MAX_ROWS];
        self.count = 0;
    }

    pub(crate) fn covers(&self, table: u16, column: usize) -> bool {
        self.active && self.table == table && self.column == column
    }

    /// Returns Err on a full index (`IndexFull`) or a duplicate when unique.
    pub(crate) fn insert(&mut self, key: i64, row: u32) -> Result<(), super::DbError> {
        if self.count >= MAX_ROWS {
            return Err(super::DbError::IndexFull);
        }
        let start = hash_key(key);
        let mut probe = 0;
        while probe < MAX_ROWS {
            let slot = (start + probe) % MAX_ROWS;
            if !self.buckets[slot].occupied {
                self.buckets[slot] = Bucket {
                    occupied: true,
                    key,
                    row,
                };
                self.count += 1;
                return Ok(());
            }
            if self.unique && self.buckets[slot].key == key {
                return Err(super::DbError::DuplicateKey);
            }
            probe += 1;
        }
        Err(super::DbError::IndexFull)
    }

    pub(crate) fn find(&self, key: i64) -> Option<u32> {
        let start = hash_key(key);
        let mut probe = 0;
        while probe < MAX_ROWS {
            let slot = (start + probe) % MAX_ROWS;
            if !self.buckets[slot].occupied {
                return None;
            }
            if self.buckets[slot].key == key {
                return Some(self.buckets[slot].row);
            }
            probe += 1;
        }
        None
    }
}
