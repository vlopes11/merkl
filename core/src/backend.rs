use alloc::vec::Vec;

/// A generic, immutable-interface key-value store over raw bytes.
///
/// Keys and values are untyped byte slices; callers are responsible for
/// serialising and deserialising their domain types.  All mutation is done
/// through `&self`; implementations must use interior mutability (e.g.
/// `RefCell`, `Mutex`) appropriate to their concurrency model.
pub trait KvsBackend {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<Option<Vec<u8>>>;
}
