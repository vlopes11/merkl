//! A membership proof provider.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use crate::{
    Node,
    hash::{Hash, Hasher},
};

/// Recompute a Merkle root from `leaf_hash` upward through `siblings`.
///
/// The direction at each level is derived from `key`'s bits — never from the
/// proof itself — so a prover cannot forge a proof by manipulating directions.
///
/// `siblings` must be bottom-up (index 0 = leaf-level sibling, last = child
/// of root), as produced by [`MerkleTree::get_opening`] and
/// [`MerkleTree::get_indexed_opening`].
fn recompute_root<H: Hasher>(leaf_hash: Hash, key: &Hash, siblings: &[Hash]) -> Hash {
    let n = siblings.len();
    let mut current = leaf_hash;
    for (i, sibling) in siblings.iter().enumerate() {
        // siblings[i] was collected at this level during top-down traversal.
        let level = n - 1 - i;
        let bit = (key[level / 8] >> (7 - (level % 8))) & 1;
        current = if bit == 0 {
            // We went left at this level, so the sibling is on the right.
            H::hash_pair(&current, sibling)
        } else {
            // We went right at this level, so the sibling is on the left.
            H::hash_pair(sibling, &current)
        };
    }
    current
}

/// A Merkle opening for a path through the tree.
///
/// Siblings are ordered bottom-up: `siblings[0]` is the sibling of the leaf,
/// `siblings[last]` is the sibling of the child of the root. Only sibling
/// *hashes* are stored — traversal direction is recomputed from the key
/// derived from the caller's inputs at verification time, so the opening
/// cannot be forged by manipulating directions.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleOpening<H> {
    /// The siblings path that opens to the root.
    pub siblings: Vec<Hash>,
    _hasher: PhantomData<H>,
}

impl<H> PartialEq for MerkleOpening<H> {
    fn eq(&self, other: &Self) -> bool {
        self.siblings == other.siblings
    }
}

impl<H> Eq for MerkleOpening<H> {}

impl<H> fmt::Debug for MerkleOpening<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleOpening")
            .field("siblings", &self.siblings)
            .finish()
    }
}

impl<H> MerkleOpening<H> {
    pub(crate) fn new(siblings: Vec<Hash>) -> Self {
        Self {
            siblings,
            _hasher: PhantomData,
        }
    }
}

impl<H: Hasher> MerkleOpening<H> {
    /// Recompute the Merkle root for a member `leaf_data`.
    ///
    /// Key = `H::hash(leaf_data)`; leaf value = `H::hash(leaf_data)`.
    /// Compare the result against the known root to verify membership.
    pub fn leaf_root_data(&self, leaf_data: impl AsRef<[u8]>) -> Hash {
        let leaf_hash = H::hash(leaf_data.as_ref());
        self.leaf_root(leaf_hash)
    }

    /// Recompute the Merkle root for a member `leaf_data`.
    ///
    /// Key = `H::hash(leaf_data)`; leaf value = `H::hash(leaf_data)`.
    /// Compare the result against the known root to verify membership.
    pub fn leaf_root(&self, leaf: Hash) -> Hash {
        recompute_root::<H>(leaf, &leaf, &self.siblings)
    }

    /// Recompute the Merkle root for a member `leaf_data` at position `index`.
    ///
    /// Key = `H::hash(index.to_le_bytes())`; leaf value = `H::hash(leaf_data)`.
    /// Use this when the opening was produced by
    /// [`MerkleTree::get_indexed_opening`][crate::MerkleTree::get_indexed_opening].
    /// Compare the result against the known root to verify membership.
    pub fn leaf_indexed_root_data(
        &self,
        index: &[u8],
        leaf_data: impl AsRef<[u8]>,
    ) -> anyhow::Result<Hash> {
        let leaf_hash = H::hash(leaf_data.as_ref());

        self.leaf_indexed_root(index, leaf_hash)
    }

    /// Recompute the Merkle root for a member `leaf_data` at position `index`.
    ///
    /// Key = `H::hash(index.to_le_bytes())`; leaf value = `H::hash(leaf_data)`.
    /// Use this when the opening was produced by
    /// [`MerkleTree::get_indexed_opening`][crate::MerkleTree::get_indexed_opening].
    /// Compare the result against the known root to verify membership.
    pub fn leaf_indexed_root(&self, index: &[u8], leaf: Hash) -> anyhow::Result<Hash> {
        let key = Node::key_from_bytes(index)?;
        let root = recompute_root::<H>(leaf, &key, &self.siblings);

        Ok(root)
    }

    /// Recompute the Merkle root assuming `leaf_data`'s position is empty.
    ///
    /// Key = `H::hash(leaf_data)`; leaf value = `Hash::default()` (empty slot).
    /// Compare the result against the known root to verify non-membership.
    pub fn non_membership_leaf_root(&self, leaf_data: impl AsRef<[u8]>) -> Hash {
        let key = H::hash(leaf_data.as_ref());
        recompute_root::<H>(Hash::default(), &key, &self.siblings)
    }

    /// Recompute the Merkle root assuming position `index` is empty.
    ///
    /// Key = `H::hash(index.to_le_bytes())`; leaf value = `Hash::default()` (empty slot).
    /// Use this when the opening was produced by
    /// [`MerkleTree::get_indexed_opening`][crate::MerkleTree::get_indexed_opening].
    /// Compare the result against the known root to verify non-membership.
    pub fn non_membership_leaf_indexed_root(&self, index: &[u8]) -> anyhow::Result<Hash> {
        let key = Node::key_from_bytes(index)?;
        let root = recompute_root::<H>(Hash::default(), &key, &self.siblings);

        Ok(root)
    }

    /// Serializes the opening into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.siblings.iter().flatten().copied().collect()
    }

    /// Attempts to deserialize an opening from the provided bytes.
    ///
    /// They are expected to be constructed from [MerkleOpening::to_bytes].
    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len().is_multiple_of(32),
            "the bytes must be a collection of hashes"
        );

        let siblings = bytes
            .chunks_exact(32)
            .map(Hash::try_from)
            .collect::<Result<Vec<Hash>, _>>()?;

        Ok(Self {
            siblings,
            _hasher: PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        MerkleTree,
        hash::{Hash, Hasher},
        memory::MemoryBackend,
    };
    use sha2::{Digest, Sha256};

    struct Sha256Hasher;

    impl Hasher for Sha256Hasher {
        fn hash(data: &[u8]) -> Hash {
            Sha256::digest(data).into()
        }
    }

    fn new_tree() -> MerkleTree<MemoryBackend, Sha256Hasher> {
        MerkleTree::new(MemoryBackend::new())
    }

    #[test]
    fn to_from_bytes_works() {
        let tree = new_tree();
        let mut root = Hash::default();
        let cases = [
            ("ns", b"foo"),
            ("ns", b"bar"),
            ("ns", b"baz"),
            ("ns", b"xxx"),
        ];

        // assert empty openings works
        let opening = tree.get_opening("ns", root, b"foo").unwrap();
        let bytes = opening.to_bytes();
        assert_eq!(opening, MerkleOpening::try_from_bytes(&bytes).unwrap());

        for (ns, leaf) in cases {
            root = tree.insert(ns, root, leaf).unwrap();
            let opening = tree.get_opening("ns", root, leaf).unwrap();
            let bytes = opening.to_bytes();

            assert_eq!(opening, MerkleOpening::try_from_bytes(&bytes).unwrap());
        }
    }
}
