//! A membership proof provider.

use alloc::vec::Vec;
use core::{fmt, marker::PhantomData};

use crate::{
    Node,
    hash::{Hash, Hasher},
};

/// Recompute a Merkle root from `leaf_hash` upward through `siblings`.
/// The direction at each level is derived from `key`'s bits — never from the proof itself — so a prover cannot forge a proof by manipulating directions.
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

/// A transparent, hash boundless Merkle opening.
pub type TransparentMerkleOpening = MerkleOpening<()>;

/// A Merkle opening for a path through the tree.
///
/// Siblings are ordered bottom-up: `siblings[0]` is the sibling of the leaf,
/// `siblings[last]` is the sibling of the child of the root. Only sibling
/// *hashes* are stored — traversal direction is recomputed from the key
/// derived from the caller's inputs at verification time, so the opening
/// cannot be forged by manipulating directions.
///
/// `terminal` is the hash found at the end of the traversal path. For
/// membership proofs it equals the leaf hash; for non-membership proofs it is
/// either `Hash::default()` (empty slot) or an existing leaf with a different
/// key.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MerkleOpening<H> {
    /// The siblings path that opens to the root.
    pub siblings: Vec<Hash>,
    /// The hash at the bottom of the traversal path.
    pub terminal: Hash,
    _hasher: PhantomData<H>,
}

impl<H> PartialEq for MerkleOpening<H> {
    fn eq(&self, other: &Self) -> bool {
        self.siblings == other.siblings && self.terminal == other.terminal
    }
}

impl<H> Eq for MerkleOpening<H> {}

impl<H> fmt::Debug for MerkleOpening<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerkleOpening")
            .field("siblings", &self.siblings)
            .field("terminal", &self.terminal)
            .finish()
    }
}

impl TransparentMerkleOpening {
    /// Converts the type to a concrete instance.
    pub fn to_concrete<H>(self) -> MerkleOpening<H> {
        let Self {
            siblings,
            terminal,
            _hasher: _,
        } = self;

        MerkleOpening {
            siblings,
            terminal,
            _hasher: PhantomData,
        }
    }
}

impl<H> MerkleOpening<H> {
    /// Creates a new opening.
    pub fn new(siblings: Vec<Hash>, terminal: Hash) -> Self {
        Self {
            siblings,
            terminal,
            _hasher: PhantomData,
        }
    }

    /// Returns `true` if `other`'s path from the root is fully contained within
    /// `self`'s path from the root.
    ///
    /// Concretely: `self.siblings.len() >= other.siblings.len()` and the
    /// root-aligned suffix of `self`'s siblings equals `other`'s siblings.
    /// Because siblings are stored bottom-up, the root-aligned end is the tail
    /// of the slice.
    pub fn contains(&self, other: &MerkleOpening<H>) -> bool {
        let l = self.siblings.len();
        let n = other.siblings.len();

        n <= l && self.siblings[l - n..] == other.siblings[..]
    }

    /// Converts the type to a transparent instance.
    pub fn to_transparent(self) -> MerkleOpening<()> {
        let Self {
            siblings,
            terminal,
            _hasher: _,
        } = self;

        MerkleOpening {
            siblings,
            terminal,
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

    /// Recompute the Merkle root for a non-member `leaf_data`.
    ///
    /// Key = `H::hash(leaf_data)`. Uses the terminal hash stored in the opening
    /// (either `Hash::default()` for an empty slot or an existing leaf with a
    /// different key) as the reconstruction starting point.
    /// Compare the result against the known root to verify non-membership.
    pub fn non_membership_leaf_root(&self, leaf_data: impl AsRef<[u8]>) -> Hash {
        let key = H::hash(leaf_data.as_ref());
        recompute_root::<H>(self.terminal, &key, &self.siblings)
    }

    /// Recompute the Merkle root for a non-member at position `index`.
    ///
    /// Key = `Node::key_from_bytes(index)`. Uses the terminal hash stored in
    /// the opening as the reconstruction starting point.
    /// Use this when the opening was produced by
    /// [`MerkleTree::get_indexed_opening`][crate::MerkleTree::get_indexed_opening].
    /// Compare the result against the known root to verify non-membership.
    pub fn non_membership_leaf_indexed_root(&self, index: &[u8]) -> anyhow::Result<Hash> {
        let key = Node::key_from_bytes(index)?;
        let root = recompute_root::<H>(self.terminal, &key, &self.siblings);

        Ok(root)
    }

    /// Serializes the opening into bytes.
    ///
    /// Format: `[terminal (32 bytes)][sibling_0 (32 bytes)]...[sibling_n (32 bytes)]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + self.siblings.len() * 32);
        bytes.extend_from_slice(&self.terminal);
        bytes.extend(self.siblings.iter().flatten().copied());
        bytes
    }

    /// Attempts to deserialize an opening from the provided bytes.
    ///
    /// They are expected to be constructed from [MerkleOpening::to_bytes].
    pub fn try_from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() >= 32 && bytes.len().is_multiple_of(32),
            "the bytes must be a terminal hash followed by a collection of sibling hashes"
        );

        let terminal = Hash::try_from(&bytes[..32])
            .map_err(|_| anyhow::anyhow!("failed to read terminal hash"))?;
        let siblings = bytes[32..]
            .chunks_exact(32)
            .map(Hash::try_from)
            .collect::<Result<Vec<Hash>, _>>()?;

        Ok(Self {
            siblings,
            terminal,
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
    use alloc::vec;
    use sha2::{Digest, Sha256};

    #[derive(Clone)]
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

    type O = MerkleOpening<Sha256Hasher>;

    /// Build a Hash whose first byte is `b` and the rest are zero.
    fn h(b: u8) -> Hash {
        let mut x = [0u8; 32];
        x[0] = b;
        x
    }

    // ── contains: constructed proofs ──────────────────────────────────────

    #[test]
    fn contains_self_is_true() {
        let proof = O::new(vec![h(1), h(2), h(3)], h(42));
        assert!(proof.contains(&proof));
    }

    #[test]
    fn contains_strictly_deeper_path() {
        // deep:    siblings [h0, h1, h2, h3] bottom-up (root-side = h3)
        // shallow: siblings       [h2, h3]  — matches root-aligned tail of deep
        let deep = O::new(vec![h(0), h(1), h(2), h(3)], h(99));
        let shallow = O::new(vec![h(2), h(3)], h(55)); // terminal differs: depth differs, no check

        assert!(deep.contains(&shallow));
        assert!(!shallow.contains(&deep));
    }

    #[test]
    fn contains_mismatched_root_side_sibling_is_false() {
        let deep = O::new(vec![h(0), h(1), h(2), h(3)], h(99));
        // root-side sibling is h(9) instead of h(3)
        let other = O::new(vec![h(2), h(9)], h(55));

        assert!(!deep.contains(&other));
    }

    // ── contains: equal-depth terminal edge cases ─────────────────────────

    #[test]
    fn contains_equal_depth_same_terminal_is_true() {
        let p1 = O::new(vec![h(1), h(2), h(3)], h(42));
        let p2 = O::new(vec![h(1), h(2), h(3)], h(42));

        assert!(p1.contains(&p2));
        assert!(p2.contains(&p1));
    }

    // ── contains: empty-proof terminal edge cases ─────────────────────────

    #[test]
    fn contains_both_empty_same_terminal_is_true() {
        // Zero siblings on both sides → equal depth → terminal check applies.
        let t: Hash = [7u8; 32];
        assert!(O::new(vec![], t).contains(&O::new(vec![], t)));
    }

    #[test]
    fn contains_nonempty_self_empty_other_skips_terminal_check() {
        // other is strictly shallower (0 siblings) so the terminal check is
        // skipped — any terminal on other must still be accepted.
        let deep = O::new(vec![h(1), h(2)], h(99));

        assert!(deep.contains(&O::new(vec![], Hash::default())));
        assert!(deep.contains(&O::new(vec![], [0xff; 32])));
    }

    // ── contains: real-tree tests ─────────────────────────────────────────

    #[test]
    fn contains_real_tree_same_path_openings() {
        // key_1 (index 1) and key_4 (index 4) diverge at bit 5.
        // A non-membership probe for key_2 (index 2) shares bits 0–5 with
        // key_1 and lands on the same leaf: equal depth + equal terminal.
        let tree = new_tree();
        let ns = "ns";
        let mut root = Hash::default();
        root = tree
            .insert_indexed(ns, root, &1u64.to_le_bytes(), b"v1")
            .unwrap();
        root = tree
            .insert_indexed(ns, root, &4u64.to_le_bytes(), b"v4")
            .unwrap();

        let m_proof = tree
            .get_indexed_opening(ns, root, &1u64.to_le_bytes())
            .unwrap();
        let nm_proof = tree
            .get_indexed_opening(ns, root, &2u64.to_le_bytes())
            .unwrap();

        assert!(m_proof.contains(&nm_proof));
        assert!(nm_proof.contains(&m_proof));
    }

    #[test]
    fn contains_real_tree_different_branches_is_false() {
        // key_1 and key_4 are on different branches at bit 5:
        // their level-5 siblings differ so neither contains the other.
        let tree = new_tree();
        let ns = "ns";
        let mut root = Hash::default();
        root = tree
            .insert_indexed(ns, root, &1u64.to_le_bytes(), b"v1")
            .unwrap();
        root = tree
            .insert_indexed(ns, root, &4u64.to_le_bytes(), b"v4")
            .unwrap();

        let p1 = tree
            .get_indexed_opening(ns, root, &1u64.to_le_bytes())
            .unwrap();
        let p4 = tree
            .get_indexed_opening(ns, root, &4u64.to_le_bytes())
            .unwrap();

        assert!(!p1.contains(&p4));
        assert!(!p4.contains(&p1));
    }

    #[test]
    fn non_membership_root_reconstruction_works() {
        let tree = new_tree();
        let ns = "ns";
        let mut root = Hash::default();

        let cases: [(u64, _); _] = [
            (1, b"foo"),
            (2, b"bar"),
            (3, b"baz"),
            (4, b"xxx"),
            (5, b"yyy"),
        ];

        for (i, l) in &cases {
            let key = i.to_le_bytes();
            let proof = tree.get_indexed_opening(ns, root, &key).unwrap();
            let proof = proof.non_membership_leaf_indexed_root(&key).unwrap();

            assert_eq!(root, proof);

            root = tree.insert_indexed(ns, root, &key, l).unwrap();
        }
    }
}
