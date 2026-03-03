/// A 32-byte hash value.
pub type Hash = [u8; 32];

/// Injectable hash function used by [`crate::MerkleTree`].
pub trait Hasher {
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
