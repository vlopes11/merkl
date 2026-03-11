/// A 32-byte hash value.
///
/// `Hash::default()` (`[0u8; 32]`) is the canonical sentinel for an empty tree
/// root or an empty child slot. The tree never writes the zero hash to the
/// backend, so backends may use an all-zero slot as an "empty" marker.
pub type Hash = [u8; 32];

/// Injectable hash function used by [`crate::MerkleTree`].
///
/// Implement this trait for any 32-byte-output hash function to use with the tree:
///
/// ```rust
/// use merkl::{Hash, Hasher};
///
/// struct IdentityHasher;
///
/// impl Hasher for IdentityHasher {
///     fn hash(data: &[u8]) -> Hash {
///         let mut out = [0u8; 32];
///         let len = data.len().min(32);
///         out[..len].copy_from_slice(&data[..len]);
///         out
///     }
/// }
/// ```
pub trait Hasher {
    /// Hash arbitrary bytes to a 32-byte digest.
    fn hash(data: &[u8]) -> Hash;

    /// Hash two child hashes together to produce a parent hash.
    ///
    /// Default: concatenate left || right and hash the 64-byte buffer.
    fn hash_pair(left: &Hash, right: &Hash) -> Hash {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(left);
        buf[32..].copy_from_slice(right);
        Self::hash(&buf)
    }
}
