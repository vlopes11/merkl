use alloc::vec::Vec;
use core::marker::PhantomData;

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
#[derive(Debug, Clone)]
pub struct MerkleOpening<H> {
    pub siblings: Vec<Hash>,
    _hasher: PhantomData<H>,
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
    pub fn leaf_root(&self, leaf_data: impl AsRef<[u8]>) -> Hash {
        let leaf_hash = H::hash(leaf_data.as_ref());
        recompute_root::<H>(leaf_hash, &leaf_hash, &self.siblings)
    }

    /// Recompute the Merkle root for a member `leaf_data` at position `index`.
    ///
    /// Key = `H::hash(index.to_le_bytes())`; leaf value = `H::hash(leaf_data)`.
    /// Use this when the opening was produced by
    /// [`MerkleTree::get_indexed_opening`][crate::MerkleTree::get_indexed_opening].
    /// Compare the result against the known root to verify membership.
    pub fn leaf_indexed_root(
        &self,
        index: &[u8],
        leaf_data: impl AsRef<[u8]>,
    ) -> anyhow::Result<Hash> {
        let leaf_hash = H::hash(leaf_data.as_ref());
        let key = Node::key_from_bytes(index)?;
        let root = recompute_root::<H>(leaf_hash, &key, &self.siblings);

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
}
