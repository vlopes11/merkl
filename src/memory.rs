//! An in-memory backend provider.

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::{cell::RefCell, ops::Deref as _, pin::Pin};

use crate::backend::{KvsBackend, Shared};

/// In-memory [`KvsBackend`] backed by a `BTreeMap` behind a `RefCell`.
///
/// Suitable for single-threaded use and testing. For multi-threaded
/// environments, provide your own implementation using a `Mutex` or similar.
#[derive(Clone)]
pub struct MemoryBackend {
    store: RefCell<BTreeMap<String, BTreeMap<Vec<u8>, Pin<Vec<u8>>>>>,
}

impl MemoryBackend {
    /// Create a new, empty in-memory backend.
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
    type Get = Shared;

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Shared>> {
        self.store
            .try_borrow()?
            .get(ns)
            .and_then(|m| m.get(key).map(|v| Ok(v.deref().into())))
            .transpose()
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.store
            .try_borrow_mut()?
            .entry(ns.into())
            .or_default()
            .insert(key.to_vec(), Pin::new(value.to_vec()));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_missing_key_returns_none() {
        let b = MemoryBackend::new();
        assert!(b.get("ns", b"k").unwrap().is_none());
    }

    #[test]
    fn set_then_get_returns_value() {
        let b = MemoryBackend::new();
        b.set("ns", b"k", b"v").unwrap();
        assert_eq!(&*b.get("ns", b"k").unwrap().unwrap(), b"v");
    }

    #[test]
    fn overwrite_replaces_value() {
        let b = MemoryBackend::new();
        b.set("ns", b"k", b"v1").unwrap();
        b.set("ns", b"k", b"v2").unwrap();
        assert_eq!(&*b.get("ns", b"k").unwrap().unwrap(), b"v2");
    }

    #[test]
    fn namespaces_are_isolated() {
        let b = MemoryBackend::new();
        b.set("ns1", b"k", b"v1").unwrap();
        b.set("ns2", b"k", b"v2").unwrap();
        assert_eq!(&*b.get("ns1", b"k").unwrap().unwrap(), b"v1");
        assert_eq!(&*b.get("ns2", b"k").unwrap().unwrap(), b"v2");
        assert!(b.get("ns3", b"k").unwrap().is_none());
    }

    #[test]
    fn keys_are_isolated_within_namespace() {
        let b = MemoryBackend::new();
        b.set("ns", b"k1", b"v1").unwrap();
        b.set("ns", b"k2", b"v2").unwrap();
        assert_eq!(&*b.get("ns", b"k1").unwrap().unwrap(), b"v1");
        assert_eq!(&*b.get("ns", b"k2").unwrap().unwrap(), b"v2");
    }
}
