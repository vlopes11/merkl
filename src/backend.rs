//! A data backend provider.

use alloc::vec::Vec;
use core::ops::Deref;

/// Shared byte-slice pointer — [`Arc`][alloc::sync::Arc]`<[u8]>` on targets
/// with atomic pointers, [`Rc`][alloc::rc::Rc]`<[u8]>` elsewhere.
#[cfg(not(target_has_atomic = "ptr"))]
pub type Shared = alloc::rc::Rc<[u8]>;
/// Shared byte-slice pointer — [`Arc`][alloc::sync::Arc]`<[u8]>` on targets
/// with atomic pointers, [`Rc`][alloc::rc::Rc]`<[u8]>` elsewhere.
#[cfg(target_has_atomic = "ptr")]
pub type Shared = alloc::sync::Arc<[u8]>;

/// A namespaced, immutable-interface key-value store over raw bytes.
///
/// All methods take `&self`; implementations must use interior mutability
/// (`RefCell`, `Mutex`, etc.) for the write path.
///
/// The `ns` (namespace) parameter lets the tree separate its node storage
/// (namespace `ns`) from its internal key-mapping namespace (`"{ns}-key"`).
/// Backends only need to use `ns` as an extra isolation scope — no special
/// handling is required.
///
/// # Implementing this trait
///
/// ```rust
/// use merkl::KvsBackend;
///
/// #[derive(Clone)]
/// struct MyBackend;
///
/// impl KvsBackend for MyBackend {
///     type Get = Vec<u8>;
///
///     fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
///         // Look up `key` in namespace `ns`.
///         Ok(None)
///     }
///
///     fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
///         // Store `value` under `key` in namespace `ns`.
///         Ok(())
///     }
/// }
/// ```
pub trait KvsBackend: Clone {
    /// The smart-pointer type returned by [`get`][Self::get].
    ///
    /// Must [`Deref`] to `[u8]`. Common choices: [`Vec<u8>`], [`Shared`],
    /// or any guard type that holds a lock over the underlying bytes.
    type Get: Deref<Target = [u8]>;

    /// Retrieve the value stored under `key` in namespace `ns`.
    ///
    /// Returns `Ok(None)` if the key is absent.
    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Self::Get>>;

    /// Store `value` under `key` in namespace `ns`.
    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()>;
}

impl KvsBackend for () {
    type Get = Vec<u8>;

    fn get(&self, _ns: &str, _key: &[u8]) -> anyhow::Result<Option<Self::Get>> {
        Ok(None)
    }

    fn set(&self, _ns: &str, _key: &[u8], _value: &[u8]) -> anyhow::Result<()> {
        Ok(())
    }
}
