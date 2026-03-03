use crate::backend::KvsBackend;
use crate::hash::{Hash, Hasher};
use crate::node::Node;
use crate::proof::{ProofSibling, ProofSide};
use anyhow::Result;
use core::marker::PhantomData;

/// Returns the bit at `level` of `key`, MSB-first.
/// level 0 → MSB of byte 0; level 255 → LSB of byte 31.
#[inline]
fn get_bit(key: &Hash, level: usize) -> u8 {
    (key[level / 8] >> (7 - (level % 8))) & 1
}

/// A sparse Merkle tree whose nodes are stored in a [`KvsBackend`].
///
/// Each leaf is addressed by the hash of its data (the *key*). At every level,
/// one bit of the key determines whether to descend left (0) or right (1).
///
/// The backend stores each internal-node hash (as key bytes) mapped to its
/// serialised [`Node`] (left and right child hashes, 64 bytes). Leaf nodes are
/// terminal and carry no backend entry.
/// An all-zero [`Hash`] marks an empty slot and serves as the canonical empty
/// root — the caller is responsible for storing and threading the root hash
/// between calls, which also allows working with sub-trees directly.
///
/// # Type parameters
/// - `B` — storage backend implementing [`KvsBackend`]
/// - `H` — hash function: [`Hasher`]
///
/// # Stack usage
/// [`insert`][Self::insert] and [`get`][Self::get] recurse up to 256 levels
/// (one per hash bit).  On embedded targets with limited stack space, ensure
/// at least ~256 × (frame size) bytes are available before calling these
/// methods.
pub struct MerkleTree<B, H> {
    backend: B,
    _hasher: PhantomData<H>,
}

impl<B, H> MerkleTree<B, H>
where
    B: KvsBackend,
    H: Hasher,
{
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            _hasher: PhantomData,
        }
    }

    /// Insert a leaf whose key is `H::hash(leaf_data)` into the tree identified
    /// by `root`, returning the new root hash.
    ///
    /// Pass [`Hash::default`] as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct keys share all 256 bits
    /// (i.e. a hash collision in `H`).
    pub fn insert(&self, root: Hash, leaf_data: impl AsRef<[u8]>) -> Result<Hash> {
        let leaf_hash = H::hash(leaf_data.as_ref());
        self.insert_at(root, leaf_hash, 0)
    }

    /// Return `true` if `leaf_data` is present in the tree identified by `root`.
    ///
    /// Equivalent to `get(root, leaf_data)? == Some(H::hash(leaf_data))`.
    pub fn contains(&self, root: Hash, leaf_data: impl AsRef<[u8]>) -> Result<bool> {
        let leaf = leaf_data.as_ref();
        Ok(self.get(root, leaf)? == Some(H::hash(leaf)))
    }

    /// Return the terminal hash at the key-bit path of `H::hash(leaf_data)`,
    /// or `None` if the path ends in an empty slot.
    ///
    /// **Note:** a `Some` result does not imply membership. In a sparse Merkle
    /// tree every non-empty path terminates at a leaf — which may be a
    /// *different* leaf that happens to share key-bit prefix with `leaf_data`.
    /// To test membership use [`Self::contains`] or compare the returned hash
    /// against `H::hash(leaf_data)` yourself.
    ///
    /// Traversal follows the same key-bit path used by [`Self::insert`]:
    /// bit 0 of the key selects left (0) or right (1) at the root, bit 1 at
    /// the next level, and so on.  The first terminal node encountered — one
    /// with no backend entry — is returned.
    pub fn get(&self, root: Hash, leaf_data: impl AsRef<[u8]>) -> Result<Option<Hash>> {
        let key = H::hash(leaf_data.as_ref());
        let mut current = root;
        let mut level = 0usize;
        loop {
            if current == Hash::default() {
                return Ok(None);
            }
            match self.backend.get(&current[..])? {
                None => return Ok(Some(current)),
                Some(bytes) => {
                    anyhow::ensure!(level < 256, "tree depth exceeded 256 levels");
                    let node = Node::from_bytes(&bytes)?;
                    current = if get_bit(&key, level) == 0 {
                        node.left
                    } else {
                        node.right
                    };
                    level += 1;
                }
            }
        }
    }

    /// Check whether `leaf_data` is a member of the tree identified by `root`,
    /// given the sibling list `siblings`.
    ///
    /// Recomputes the root by hashing `H::hash(leaf_data)` upward through
    /// `siblings` (expected bottom-up: index 0 is the leaf-level sibling,
    /// last index is the sibling just below the root) and compares the result
    /// against `root`.
    ///
    /// Does not access the backend — verification is a pure hash computation.
    pub fn verify(
        &self,
        root: Hash,
        siblings: &[ProofSibling],
        leaf_data: impl AsRef<[u8]>,
    ) -> bool {
        let mut current = H::hash(leaf_data.as_ref());
        for sibling in siblings {
            current = match sibling.side {
                ProofSide::Left => H::hash_pair(&sibling.hash, &current),
                ProofSide::Right => H::hash_pair(&current, &sibling.hash),
            };
        }
        current == root
    }

    /// Recursively insert `leaf_hash` into the subtree rooted at `current`,
    /// returning the new subtree root hash.
    fn insert_at(&self, current: Hash, leaf_hash: Hash, level: usize) -> Result<Hash> {
        if current == Hash::default() {
            return Ok(leaf_hash);
        }

        match self.backend.get(&current[..])? {
            None => {
                if current == leaf_hash {
                    return Ok(leaf_hash); // already present — idempotent
                }
                self.push_down(current, leaf_hash, level)
            }
            Some(bytes) => {
                let node = Node::from_bytes(&bytes)?;
                let (new_left, new_right) = if get_bit(&leaf_hash, level) == 0 {
                    (self.insert_at(node.left, leaf_hash, level + 1)?, node.right)
                } else {
                    (node.left, self.insert_at(node.right, leaf_hash, level + 1)?)
                };
                // If neither child changed the subtree is unchanged — skip the write.
                if new_left == node.left && new_right == node.right {
                    return Ok(current);
                }
                let parent = H::hash_pair(&new_left, &new_right);
                self.backend.set(
                    &parent[..],
                    &Node { left: new_left, right: new_right }.to_bytes(),
                )?;
                Ok(parent)
            }
        }
    }

    /// Resolve a collision between an `existing` leaf and `new_leaf` by
    /// descending level by level until their key bits diverge.
    fn push_down(&self, existing: Hash, new_leaf: Hash, level: usize) -> Result<Hash> {
        anyhow::ensure!(level < 256, "key collision: all 256 key bits are identical");

        let new_bit = get_bit(&new_leaf, level);
        let (left, right) = if new_bit != get_bit(&existing, level) {
            if new_bit == 0 { (new_leaf, existing) } else { (existing, new_leaf) }
        } else {
            let child = self.push_down(existing, new_leaf, level + 1)?;
            if new_bit == 0 { (child, Hash::default()) } else { (Hash::default(), child) }
        };

        let parent = H::hash_pair(&left, &right);
        self.backend
            .set(&parent[..], &Node { left, right }.to_bytes())?;
        Ok(parent)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Hash, Hasher};
    use crate::memory::MemoryBackend;
    use crate::node::Node;
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

    fn insert_all(leaves: &[&[u8]]) -> (MerkleTree<MemoryBackend, Sha256Hasher>, Hash) {
        let tree = new_tree();
        let root = leaves.iter().fold(Hash::default(), |root, leaf| {
            tree.insert(root, leaf).unwrap()
        });
        (tree, root)
    }

    fn collect_siblings(
        tree: &MerkleTree<MemoryBackend, Sha256Hasher>,
        root: Hash,
        leaf_data: &[u8],
    ) -> alloc::vec::Vec<ProofSibling> {
        let key = Sha256Hasher::hash(leaf_data);
        let mut current = root;
        let mut level = 0usize;
        let mut siblings = alloc::vec::Vec::new();
        loop {
            match tree.backend.get(&current[..]).unwrap() {
                None => break,
                Some(bytes) => {
                    let node = Node::from_bytes(&bytes).unwrap();
                    if get_bit(&key, level) == 0 {
                        siblings.push(ProofSibling {
                            hash: node.right,
                            side: ProofSide::Right,
                        });
                        current = node.left;
                    } else {
                        siblings.push(ProofSibling {
                            hash: node.left,
                            side: ProofSide::Left,
                        });
                        current = node.right;
                    }
                    level += 1;
                }
            }
        }
        siblings.reverse();
        siblings
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let tree = new_tree();
        let root = tree.insert(Hash::default(), b"hello").unwrap();
        assert_eq!(root, Sha256Hasher::hash(b"hello"));
    }

    #[test]
    fn root_is_deterministic() {
        let leaves: &[&[u8]] = &[b"a", b"b", b"c"];
        let (_, r1) = insert_all(leaves);
        let (_, r2) = insert_all(leaves);
        assert_eq!(r1, r2);
    }

    #[test]
    fn insert_order_does_not_matter() {
        let (_, r1) = insert_all(&[b"a", b"b", b"c"]);
        let (_, r2) = insert_all(&[b"c", b"a", b"b"]);
        assert_eq!(r1, r2);
    }

    #[test]
    fn insert_is_idempotent() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        assert_eq!(tree.insert(root, b"a").unwrap(), root);
    }

    #[test]
    fn distinct_leaf_sets_produce_distinct_roots() {
        let (_, r1) = insert_all(&[b"a", b"b"]);
        let (_, r2) = insert_all(&[b"a", b"c"]);
        assert_ne!(r1, r2);
    }

    /// Find two u64 inputs (serialised as little-endian bytes) whose SHA-256
    /// hashes share the same top-3-bit prefix (bits 0–2 in MSB-first order).
    fn find_3bit_prefix_pair() -> ([u8; 8], [u8; 8]) {
        use alloc::collections::BTreeMap;
        let mut first_by_prefix: BTreeMap<u8, u64> = BTreeMap::new();
        for i in 0u64.. {
            let h = Sha256Hasher::hash(&i.to_le_bytes());
            let prefix = h[0] >> 5; // bits 0, 1, 2
            if let Some(&prev) = first_by_prefix.get(&prefix) {
                return (prev.to_le_bytes(), i.to_le_bytes());
            }
            first_by_prefix.insert(prefix, i);
        }
        unreachable!()
    }

    #[test]
    fn push_down_handles_3_bit_prefix_collision() {
        let (a, b) = find_3bit_prefix_pair();
        let ha = Sha256Hasher::hash(&a);
        let hb = Sha256Hasher::hash(&b);

        assert_eq!(ha[0] >> 5, hb[0] >> 5, "top 3 bits must match");
        assert_ne!(ha, hb, "full hashes must be distinct");

        let tree = new_tree();
        let root_a = tree.insert(Hash::default(), &a).unwrap();
        let root_ab = tree.insert(root_a, &b).unwrap();

        assert_eq!(root_a, ha);
        assert_ne!(root_ab, ha);
        assert_ne!(root_ab, hb);

        assert_eq!(tree.get(root_ab, &a).unwrap(), Some(ha));
        assert_eq!(tree.get(root_ab, &b).unwrap(), Some(hb));

        let root_b = tree.insert(Hash::default(), &b).unwrap();
        let root_ba = tree.insert(root_b, &a).unwrap();
        assert_eq!(root_ab, root_ba);

        assert_eq!(tree.get(root_ba, &a).unwrap(), Some(ha));
        assert_eq!(tree.get(root_ba, &b).unwrap(), Some(hb));
    }

    #[test]
    fn verify_single_leaf_no_siblings() {
        let (tree, root) = insert_all(&[b"hello"]);
        assert!(tree.verify(root, &[], b"hello"));
    }

    #[test]
    fn verify_accepts_correct_proof() {
        let (tree, root) = insert_all(&[b"a", b"b", b"c"]);
        for leaf in [b"a" as &[u8], b"b", b"c"] {
            let siblings = collect_siblings(&tree, root, leaf);
            assert!(tree.verify(root, &siblings, leaf));
        }
    }

    #[test]
    fn verify_rejects_wrong_leaf() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        let siblings = collect_siblings(&tree, root, b"a");
        assert!(!tree.verify(root, &siblings, b"b"));
    }

    #[test]
    fn verify_rejects_tampered_sibling() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        let mut siblings = collect_siblings(&tree, root, b"a");
        if let Some(s) = siblings.first_mut() {
            s.hash[0] ^= 0xff;
        }
        assert!(!tree.verify(root, &siblings, b"a"));
    }

    #[test]
    fn verify_rejects_wrong_root() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        let siblings = collect_siblings(&tree, root, b"a");
        let bad_root = Sha256Hasher::hash(b"not a root");
        assert!(!tree.verify(bad_root, &siblings, b"a"));
    }

    #[test]
    fn verify_with_3_bit_prefix_collision() {
        let (a, b) = find_3bit_prefix_pair();
        let tree = new_tree();
        let root = tree.insert(Hash::default(), &a).unwrap();
        let root = tree.insert(root, &b).unwrap();

        let siblings_a = collect_siblings(&tree, root, &a);
        let siblings_b = collect_siblings(&tree, root, &b);

        assert!(tree.verify(root, &siblings_a, &a));
        assert!(tree.verify(root, &siblings_b, &b));

        assert!(!tree.verify(root, &siblings_a, &b));
        assert!(!tree.verify(root, &siblings_b, &a));
    }
}
