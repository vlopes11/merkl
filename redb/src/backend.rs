use anyhow::Result;
use redb::{Database, ReadableDatabase, TableDefinition};

use merkl::KvsBackend;

#[cfg(not(feature = "multi-thread"))]
use std::rc::Rc as Shared;
#[cfg(feature = "multi-thread")]
use std::sync::Arc as Shared;

const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("merkl_tree");

/// A [`KvsBackend`] backed by a [`redb`] embedded database.
///
/// The inner [`Database`] is held behind an [`Rc`] (or [`Arc`] when the
/// `multi-thread` feature is enabled), so cloning is cheap and all clones
/// share the same on-disk store.
///
/// Each [`KvsBackend::set`] call opens, writes, and commits its own write
/// transaction.  For bulk tree construction — where many nodes are written in
/// a tight loop — wrapping a single [`redb::WriteTransaction`] yourself and
/// passing it through a custom backend will give better throughput.
///
/// [`Arc`]: std::sync::Arc
/// [`Rc`]: std::rc::Rc
pub struct RedbBackend {
    db: Shared<Database>,
}

impl RedbBackend {
    /// Wrap an existing [`Database`], creating the internal storage table if
    /// it does not yet exist.
    pub fn new(db: Database) -> Result<Self> {
        let tx = db.begin_write()?;
        tx.open_table(TABLE)?;
        tx.commit()?;
        Ok(Self {
            db: Shared::new(db),
        })
    }

    /// Create an in-memory database (data is lost when the backend is dropped).
    pub fn in_memory() -> Result<Self> {
        Self::new(Database::builder().create_with_backend(redb::backends::InMemoryBackend::new())?)
    }

    /// Open or create a file-backed database at `path`.
    pub fn create(path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::new(Database::create(path)?)
    }
}

impl Clone for RedbBackend {
    fn clone(&self) -> Self {
        Self {
            db: Shared::clone(&self.db),
        }
    }
}

impl KvsBackend for RedbBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(TABLE)?;
        match table.get(key)? {
            None => Ok(None),
            Some(guard) => {
                let bytes: &[u8] = guard.value();
                Ok(Some(bytes.to_vec()))
            }
        }
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let tx = self.db.begin_write()?;
        let old = {
            let mut table = tx.open_table(TABLE)?;
            match table.insert(key, value)? {
                None => None,
                Some(guard) => {
                    let bytes: &[u8] = guard.value();
                    Some(bytes.to_vec())
                }
            }
            // `table` dropped here, releasing the borrow on `tx`
        };
        tx.commit()?;
        Ok(old)
    }
}
