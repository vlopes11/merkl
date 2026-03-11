use core::ops::{Deref, DerefMut};

use fjall::{Database, KeyspaceCreateOptions, UserValue};

use crate::KvsBackend;

pub use fjall as current;

/// A [`KvsBackend`] backed by a [fjall](https://crates.io/crates/fjall)
/// embedded database.
///
/// Each `ns` argument maps directly to a fjall keyspace, opened on demand with
/// default options. The underlying [`Database`] is accessible via `Deref` /
/// `DerefMut` for direct configuration or keyspace management.
///
/// # Note on `set` return value
///
/// Fjall's `insert` API does not indicate whether a previous value existed, so
/// [`KvsBackend::set`] always returns `Ok(false)` regardless of whether the key
/// was already present.
pub struct FjallBackend {
    db: Database,
}

impl From<Database> for FjallBackend {
    fn from(db: Database) -> Self {
        Self { db }
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
        let val = self
            .db
            .keyspace(ns, KeyspaceCreateOptions::default)?
            .get(key)?;

        Ok(val)
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<bool> {
        self.db
            .keyspace(ns, KeyspaceCreateOptions::default)?
            .insert(key, value)?;

        Ok(false)
    }
}
