//! A fjall KVS backend provider.

use std::{
    ops::{Deref, DerefMut},
    path::Path,
};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, UserValue};
use moka::sync::Cache;

use crate::KvsBackend;

pub use fjall as current;

/// A [`KvsBackend`] backed by a [fjall](https://crates.io/crates/fjall)
/// embedded database.
#[derive(Clone)]
pub struct FjallBackend {
    db: Database,
    ns: Cache<String, Keyspace>,
}

impl FjallBackend {
    /// Creates a new instance with the backend located at the provided directory.
    pub fn new<P: AsRef<Path>>(dir: P) -> anyhow::Result<Self> {
        let db = Database::builder(dir).open()?;

        Ok(Self::from(db))
    }

    /// Creates a new temporary backend located at the provided directory.
    ///
    /// Will remove the files once dropped.
    pub fn temporary<P: AsRef<Path>>(dir: P) -> anyhow::Result<Self> {
        let db = Database::builder(dir).temporary(true).open()?;

        Ok(Self::from(db))
    }

    /// Returns the keyspace of the provided argument.
    ///
    /// Internally, it has a LRU cache that will store the last used namespaces.
    pub fn ns(&self, name: &str) -> anyhow::Result<Keyspace> {
        let ns = self
            .ns
            .entry_by_ref(name)
            .or_try_insert_with(|| self.db.keyspace(name, KeyspaceCreateOptions::default))?
            .value()
            .clone();

        Ok(ns)
    }
}

impl From<Database> for FjallBackend {
    fn from(db: Database) -> Self {
        Self {
            db,
            ns: Cache::new(100),
        }
    }
}

impl Deref for FjallBackend {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.db
    }
}

impl DerefMut for FjallBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.db
    }
}

impl KvsBackend for FjallBackend {
    type Get = UserValue;

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Self::Get>> {
        let val = self.ns(ns)?.get(key)?;

        Ok(val)
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.ns(ns)?.insert(key, value)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use tempfile::TempDir;

    #[test]
    fn fjall_backend_works() {
        let dir = TempDir::new().unwrap();
        let data = FjallBackend::temporary(dir).unwrap();

        for ns in 0..50 {
            for val in 0..200 {
                let ns = format!("{ns}");
                let key = format!("{}", !val);
                let val = format!("{val}");

                data.set(&ns, key.as_bytes(), val.as_bytes()).unwrap();
            }
        }

        for ns in 0..50 {
            for val in 0..200 {
                let ns = format!("{ns}");
                let key = format!("{}", !val);
                let val = format!("{val}");
                let x = data.get(&ns, key.as_bytes()).unwrap().unwrap();

                assert_eq!(x, val);
            }
        }
    }
}
