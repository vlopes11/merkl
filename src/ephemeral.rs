//! A no-effect, ephemeral data backend.

use crate::{KvsBackend, MemoryBackend, backend::Shared};

/// A no-effect, ephemeral data backend.
///
/// The purpose of this struct is to allow user branch computation without mutating the data
/// backend.
#[derive(Clone)]
pub struct EphemeralBackend<'a, B: KvsBackend> {
    b: &'a B,
    s: MemoryBackend,
}

impl<'a, B: KvsBackend> EphemeralBackend<'a, B> {
    /// Creates a new ephemeral instance that will read data from the source, and have ephemeral,
    /// in-memory mutation.
    pub fn new(source: &'a B) -> Self {
        Self {
            b: source,
            s: MemoryBackend::default(),
        }
    }
}

impl<'a, B: KvsBackend> KvsBackend for EphemeralBackend<'a, B> {
    type Get = Shared;

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Self::Get>> {
        if let Some(d) = self.s.get(ns, key)? {
            return Ok(Some((*d).into()));
        }

        let data = self.b.get(ns, key)?;
        if let Some(d) = data.as_ref() {
            self.s.set(ns, key, d)?;
        }

        Ok(data.map(|d| (*d).into()))
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.s.set(ns, key, value)
    }
}
