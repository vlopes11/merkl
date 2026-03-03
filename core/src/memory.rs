use crate::backend::KvsBackend;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;

/// In-memory [`KvsBackend`] backed by a `BTreeMap` behind a `RefCell`.
///
/// Suitable for single-threaded use and testing. For multi-threaded
/// environments, provide your own implementation using a `Mutex` or similar.
pub struct MemoryBackend {
    store: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryBackend {
    pub fn new() -> Self {
        Self {
            store: RefCell::new(BTreeMap::new()),
        }
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KvsBackend for MemoryBackend {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.store.borrow().get(key).cloned())
    }

    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.store.borrow_mut().insert(key.to_vec(), value.to_vec()))
    }
}
