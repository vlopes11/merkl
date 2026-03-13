//! A Sha256 hasher provider.

use crate::hash::{Hash, Hasher};
use crate::tree::MerkleTree;
use sha2::{Digest, Sha256};

/// A [`Hasher`] implementation backed by SHA-256.
#[derive(Clone)]
pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(data: &[u8]) -> Hash {
        Sha256::digest(data).into()
    }
}

/// A [`MerkleTree`] that uses SHA-256 as its hash function.
///
/// The storage backend `B` is the only remaining free parameter:
///
/// ```rust
/// use merkl::{Hash, MemoryBackend, Sha256MerkleTree};
///
/// let tree = Sha256MerkleTree::<MemoryBackend>::new(MemoryBackend::new());
/// let root = tree.insert("ns", Hash::default(), b"hello").unwrap();
/// ```
pub type Sha256MerkleTree<B> = MerkleTree<B, Sha256Hasher>;
