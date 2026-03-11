use anyhow::Result;
use redb::{Database, ReadableDatabase, TableDefinition};

use crate::{KvsBackend, MerkleTree};

pub use redb as current;

#[cfg(not(target_has_atomic = "ptr"))]
use std::rc::Rc as Shared;
#[cfg(target_has_atomic = "ptr")]
use std::sync::Arc as Shared;

/// Single redb table that holds all namespaces.
///
/// Keys are length-prefixed composites: `[ns_len: u32 LE][ns bytes][key bytes]`.
/// This is unambiguous for any namespace string and any binary key.
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("merkl");

fn composite_key(ns: &str, key: &[u8]) -> Vec<u8> {
    let ns_bytes = ns.as_bytes();
    let mut out = Vec::with_capacity(4 + ns_bytes.len() + key.len());
    out.extend_from_slice(&(ns_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(ns_bytes);
    out.extend_from_slice(key);
    out
}

/// A [`KvsBackend`] backed by a [`redb`] embedded database.
///
/// The inner [`Database`] is held behind an [`Arc`] (or [`Rc`] on targets
/// without atomics), so cloning is cheap and all clones share the same
/// on-disk store.
///
/// Each [`KvsBackend::set`] call opens, writes, and commits its own write
/// transaction. For bulk tree construction, wrapping a single
/// [`redb::WriteTransaction`] in a custom backend will give better throughput.
///
/// All namespaces are stored in a single redb table using length-prefixed
/// composite keys (`[ns_len: u32 LE][ns bytes][key bytes]`).
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
    type Get = Vec<u8>;

    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let composite = composite_key(ns, key);
        let tx = self.db.begin_read()?;
        let table = tx.open_table(TABLE)?;
        match table.get(composite.as_slice())? {
            None => Ok(None),
            Some(guard) => Ok(Some(guard.value().to_vec())),
        }
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> Result<bool> {
        let composite = composite_key(ns, key);
        let tx = self.db.begin_write()?;
        let replaced = {
            let mut table = tx.open_table(TABLE)?;
            table.insert(composite.as_slice(), value)?.is_some()
        };
        tx.commit()?;
        Ok(replaced)
    }
}

/// A [`MerkleTree`] whose nodes are persisted in a [`redb`] database.
///
/// The hash function `H` is the only free type parameter:
///
/// ```rust,no_run
/// # use merkl::{Hash, Hasher, redb::{RedbBackend, RedbMerkleTree}};
/// # struct H; impl Hasher for H { fn hash(_: &[u8]) -> Hash { [0u8; 32] } }
/// let backend = RedbBackend::in_memory().unwrap();
/// let tree: RedbMerkleTree<H> = RedbMerkleTree::new(backend);
/// ```
pub type RedbMerkleTree<H> = MerkleTree<RedbBackend, H>;
