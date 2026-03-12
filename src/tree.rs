//! A Merkle tree, backend wrapper.

use alloc::format;
use alloc::vec::Vec;

use crate::backend::KvsBackend;
use crate::hash::{Hash, Hasher};
use crate::node::Node;
use crate::proof::MerkleOpening;
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
/// Each leaf is addressed by a caller-supplied **key** (a [`tyalias@Hash`]-sized value
/// whose bits determine the path through the tree). The leaf's *content* is
/// stored as `H::hash(leaf_data)` at the terminal node. A separate namespace
/// `"{ns}-key"` in the backend holds a `leaf_hash → key` mapping so that
/// its internal code can look up the traversal key for existing leaves when resolving collisions.
///
/// An all-zero [`tyalias@Hash`] marks an empty slot and serves as the canonical empty
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

/// A dummy Merkle tree implementation with no hasher or backend.
pub type MerkleTreeDummy = MerkleTree<(), ()>;

impl Default for MerkleTreeDummy {
    fn default() -> Self {
        Self {
            backend: (),
            _hasher: PhantomData,
        }
    }
}

impl<B, H> MerkleTree<B, H>
where
    B: KvsBackend,
    H: Hasher,
{
    /// Creates a new instance of the MerkleTree from the provided backend.
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            _hasher: PhantomData,
        }
    }

    /// Returns the inner backend.
    pub const fn inner(&self) -> &B {
        &self.backend
    }

    /// Returns the inner backend as mut.
    pub const fn inner_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Returns the inner backend.
    pub fn into_inner(self) -> B {
        self.backend
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// Uses `H::hash(leaf_data)` as the traversal key.
    ///
    /// Pass `Hash::default` as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct keys share all 256 bits
    /// (a hash collision in `H`).
    pub fn insert(&self, ns: &str, root: Hash, leaf_data: impl AsRef<[u8]>) -> Result<Hash> {
        let leaf = H::hash(leaf_data.as_ref());
        self.insert_leaf(ns, root, leaf)
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// # Errors
    /// Returns an error only if two distinct keys share all 256 bits
    /// (a hash collision in `H`).
    pub fn insert_leaf(&self, ns: &str, root: Hash, leaf: Hash) -> Result<Hash> {
        self.insert_keyed(ns, root, leaf, leaf)
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// The traversal key is `H::hash(index.to_le_bytes())`, giving each
    /// integer index a stable, uniformly-distributed position in the tree.
    ///
    /// Pass `Hash::default` as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct indices hash to identical 256-bit
    /// keys (a collision in `H`).
    pub fn insert_indexed(
        &self,
        ns: &str,
        root: Hash,
        index: &[u8],
        leaf_data: impl AsRef<[u8]>,
    ) -> Result<Hash> {
        let leaf = H::hash(leaf_data.as_ref());
        self.insert_indexed_leaf(ns, root, index, leaf)
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// The traversal key is `H::hash(index.to_le_bytes())`, giving each
    /// integer index a stable, uniformly-distributed position in the tree.
    ///
    /// Pass `Hash::default` as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct indices hash to identical 256-bit
    /// keys (a collision in `H`).
    pub fn insert_indexed_leaf(
        &self,
        ns: &str,
        root: Hash,
        index: &[u8],
        leaf: Hash,
    ) -> Result<Hash> {
        let key = Node::key_from_bytes(index)?;
        self.insert_keyed(ns, root, key, leaf)
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// `key` determines the leaf's position in the tree (its bits are read
    /// MSB-first to navigate left/right at each level). `leaf_data` is the
    /// payload; `H::hash(leaf_data)` is stored as the terminal node value.
    ///
    /// The mapping `H::hash(leaf_data) → key` is persisted in the
    /// `"{ns}-key"` backend namespace so that collision resolution
    /// ([`push_down`][Self::push_down]) can retrieve the key for any existing
    /// leaf.
    ///
    /// Pass [`Hash::default`] as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct keys share all 256 bits
    /// (a hash collision in the key space).
    fn insert_keyed(&self, ns: &str, root: Hash, key: Hash, leaf: Hash) -> Result<Hash> {
        // Store the leaf→key mapping so push_down can resolve existing leaves.
        self.backend
            .set(&format!("{ns}-key"), &leaf[..], &key[..])?;
        self.insert_at(ns, root, key, leaf, 0)
    }

    /// Return `true` if `leaf_data` is stored at position `key` in the tree
    /// identified by `root`.
    ///
    /// Equivalent to `get(ns, root, key)? == Some(H::hash(leaf_data))`.
    pub fn contains(
        &self,
        ns: &str,
        root: Hash,
        key: Hash,
        leaf_data: impl AsRef<[u8]>,
    ) -> Result<bool> {
        let leaf = H::hash(leaf_data.as_ref());
        self.contains_leaf(ns, root, key, leaf)
    }

    /// Return `true` if `leaf_data` is stored at position `key` in the tree
    /// identified by `root`.
    ///
    /// Equivalent to `get(ns, root, key)? == Some(leaf)`.
    pub fn contains_leaf(&self, ns: &str, root: Hash, key: Hash, leaf: Hash) -> Result<bool> {
        Ok(self.get(ns, root, key)? == Some(leaf))
    }

    /// Return the terminal hash at the position identified by `key`, or
    /// `None` if the path ends in an empty slot.
    ///
    /// **Note:** a `Some` result does not imply membership of a particular
    /// leaf. In a sparse Merkle tree every non-empty path terminates at a
    /// leaf — which may be a *different* leaf if `key` was never inserted.
    /// Use [`Self::contains`] to test membership.
    ///
    /// Traversal follows the same key-bit path used by [`Self::insert`]:
    /// bit 0 of `key` selects left (0) or right (1) at the root, bit 1 at
    /// the next level, and so on.
    pub fn get(&self, ns: &str, root: Hash, key: Hash) -> Result<Option<Hash>> {
        let mut current = root;
        let mut level = 0usize;
        loop {
            if current == Hash::default() {
                return Ok(None);
            }
            match self.backend.get(ns, &current[..])? {
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

    /// Return the terminal hash at the position indexed by `index`, or
    /// `None` if the path ends in an empty slot.
    pub fn get_indexed(&self, ns: &str, root: Hash, index: &[u8]) -> Result<Option<Hash>> {
        let key = Node::key_from_bytes(index)?;
        self.get(ns, root, key)
    }

    /// Build a Merkle opening proof for `leaf_data` in the tree identified by
    /// `root`.
    ///
    /// The traversal key is `H::hash(leaf_data)`, matching [`Self::insert`].
    /// Call [`MerkleOpening::leaf_root`] on the returned opening and compare
    /// against `root` to verify membership.
    pub fn get_opening(
        &self,
        ns: &str,
        root: Hash,
        leaf_data: impl AsRef<[u8]>,
    ) -> Result<MerkleOpening<H>> {
        let leaf = H::hash(leaf_data.as_ref());
        self.get_opening_leaf(ns, root, leaf)
    }

    /// Build a Merkle opening proof for `leaf_data` in the tree identified by
    /// `root`.
    ///
    /// The traversal key is `H::hash(leaf_data)`, matching [`Self::insert`].
    /// Call [`MerkleOpening::leaf_root`] on the returned opening and compare
    /// against `root` to verify membership.
    pub fn get_opening_leaf(&self, ns: &str, root: Hash, leaf: Hash) -> Result<MerkleOpening<H>> {
        let siblings = self.collect_proof(ns, root, leaf)?;
        Ok(MerkleOpening::new(siblings))
    }

    /// Build a Merkle opening proof for `leaf_data` inserted at position
    /// `index` in the tree identified by `root`.
    ///
    /// The traversal key is `H::hash(index.to_le_bytes())`, matching
    /// [`Self::insert_indexed`].
    /// Call [`MerkleOpening::leaf_indexed_root`] on the returned opening and
    /// compare against `root` to verify membership.
    pub fn get_indexed_opening(
        &self,
        ns: &str,
        root: Hash,
        index: &[u8],
    ) -> Result<MerkleOpening<H>> {
        let key = Node::key_from_bytes(index)?;
        let siblings = self.collect_proof(ns, root, key)?;
        Ok(MerkleOpening::new(siblings))
    }

    /// Traverse the tree from `root` along `key`'s bit path, collecting
    /// sibling hashes bottom-up (leaf-level first).
    fn collect_proof(&self, ns: &str, root: Hash, key: Hash) -> Result<Vec<Hash>> {
        let mut current = root;
        let mut level = 0usize;
        let mut siblings: Vec<Hash> = Vec::new();
        loop {
            if current == Hash::default() {
                break;
            }
            match self.backend.get(ns, &current[..])? {
                None => break,
                Some(bytes) => {
                    anyhow::ensure!(level < 256, "tree depth exceeded 256 levels");
                    let node = Node::from_bytes(&bytes)?;
                    if get_bit(&key, level) == 0 {
                        siblings.push(node.right);
                        current = node.left;
                    } else {
                        siblings.push(node.left);
                        current = node.right;
                    }
                    level += 1;
                }
            }
        }
        siblings.reverse(); // bottom-up: siblings[0] = leaf-level sibling
        Ok(siblings)
    }

    /// Recursively insert `leaf_hash` at the position determined by `key`
    /// into the subtree rooted at `current`, returning the new subtree root.
    fn insert_at(
        &self,
        ns: &str,
        current: Hash,
        key: Hash,
        leaf_hash: Hash,
        level: usize,
    ) -> Result<Hash> {
        if current == Hash::default() {
            return Ok(leaf_hash);
        }

        match self.backend.get(ns, &current[..])? {
            None => {
                // `current` is an existing leaf terminal.
                if current == leaf_hash {
                    return Ok(leaf_hash); // already present — idempotent
                }
                self.push_down(ns, current, key, leaf_hash, level)
            }
            Some(bytes) => {
                let node = Node::from_bytes(&bytes)?;
                let (new_left, new_right) = if get_bit(&key, level) == 0 {
                    (
                        self.insert_at(ns, node.left, key, leaf_hash, level + 1)?,
                        node.right,
                    )
                } else {
                    (
                        node.left,
                        self.insert_at(ns, node.right, key, leaf_hash, level + 1)?,
                    )
                };
                // If neither child changed the subtree is unchanged — skip the write.
                if new_left == node.left && new_right == node.right {
                    return Ok(current);
                }
                let parent = H::hash_pair(&new_left, &new_right);
                self.backend.set(
                    ns,
                    &parent[..],
                    &Node {
                        left: new_left,
                        right: new_right,
                    }
                    .to_bytes(),
                )?;
                Ok(parent)
            }
        }
    }

    /// Resolve a collision between `existing_leaf_hash` (already in the tree)
    /// and `new_leaf_hash` (being inserted at `new_key`) by descending level
    /// by level until their key bits diverge.
    ///
    /// The traversal key for `existing_leaf_hash` is looked up from the
    /// `"{ns}-key"` backend namespace.
    fn push_down(
        &self,
        ns: &str,
        existing_leaf_hash: Hash,
        new_key: Hash,
        new_leaf_hash: Hash,
        level: usize,
    ) -> Result<Hash> {
        anyhow::ensure!(level < 256, "key collision: all 256 key bits are identical");

        // Retrieve the traversal key that was stored for the existing leaf.
        let key_ns = format!("{ns}-key");
        let existing_key_bytes = self
            .backend
            .get(&key_ns, &existing_leaf_hash[..])?
            .ok_or_else(|| anyhow::anyhow!("missing key mapping for existing leaf"))?;
        anyhow::ensure!(
            existing_key_bytes.len() == 32,
            "invalid key mapping length: expected 32, got {}",
            existing_key_bytes.len()
        );
        let existing_key: Hash = existing_key_bytes[..].try_into().unwrap();

        // Same key: the new leaf replaces the existing one (override).
        if existing_key == new_key {
            return Ok(new_leaf_hash);
        }

        let new_bit = get_bit(&new_key, level);
        let (left, right) = if new_bit != get_bit(&existing_key, level) {
            if new_bit == 0 {
                (new_leaf_hash, existing_leaf_hash)
            } else {
                (existing_leaf_hash, new_leaf_hash)
            }
        } else {
            let child =
                self.push_down(ns, existing_leaf_hash, new_key, new_leaf_hash, level + 1)?;
            if new_bit == 0 {
                (child, Hash::default())
            } else {
                (Hash::default(), child)
            }
        };

        let parent = H::hash_pair(&left, &right);
        self.backend
            .set(ns, &parent[..], &Node { left, right }.to_bytes())?;
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
    use alloc::string::ToString;
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
            tree.insert("ns", root, leaf).unwrap()
        });
        (tree, root)
    }

    #[test]
    fn single_leaf_root_equals_leaf_hash() {
        let tree = new_tree();
        let root = tree.insert("ns", Hash::default(), b"hello").unwrap();
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
        assert_eq!(tree.insert("ns", root, b"a").unwrap(), root);
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
        let root_a = tree.insert("ns", Hash::default(), &a).unwrap();
        let root_ab = tree.insert("ns", root_a, &b).unwrap();

        assert_eq!(root_a, ha);
        assert_ne!(root_ab, ha);
        assert_ne!(root_ab, hb);

        assert_eq!(tree.get("ns", root_ab, ha).unwrap(), Some(ha));
        assert_eq!(tree.get("ns", root_ab, hb).unwrap(), Some(hb));

        let root_b = tree.insert("ns", Hash::default(), &b).unwrap();
        let root_ba = tree.insert("ns", root_b, &a).unwrap();
        assert_eq!(root_ab, root_ba);

        assert_eq!(tree.get("ns", root_ba, ha).unwrap(), Some(ha));
        assert_eq!(tree.get("ns", root_ba, hb).unwrap(), Some(hb));
    }

    #[test]
    fn get_opening_all_leaves() {
        let (tree, root) = insert_all(&[b"a", b"b", b"c"]);
        for leaf in [b"a" as &[u8], b"b", b"c"] {
            let proof = tree.get_opening("ns", root, leaf).unwrap();
            assert_eq!(proof.leaf_root(Sha256Hasher::hash(leaf)), root);
        }
    }

    #[test]
    fn get_opening_rejects_wrong_root() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        let _ = root;
        let bad_root = Sha256Hasher::hash(b"not a root");
        let proof = tree.get_opening("ns", bad_root, b"a").unwrap();
        assert_ne!(
            proof.leaf_root(Sha256Hasher::hash(b"a")),
            Sha256Hasher::hash(b"a root")
        );
    }

    #[test]
    fn get_opening_with_3_bit_prefix_collision() {
        let (a, b) = find_3bit_prefix_pair();
        let tree = new_tree();
        let root = tree.insert("ns", Hash::default(), &a).unwrap();
        let root = tree.insert("ns", root, &b).unwrap();

        let proof_a = tree.get_opening("ns", root, &a).unwrap();
        let proof_b = tree.get_opening("ns", root, &b).unwrap();

        assert_eq!(proof_a.leaf_root(Sha256Hasher::hash(&a)), root);
        assert_eq!(proof_b.leaf_root(Sha256Hasher::hash(&b)), root);

        assert_ne!(proof_a.leaf_root(Sha256Hasher::hash(&b)), root);
        assert_ne!(proof_b.leaf_root(Sha256Hasher::hash(&a)), root);
    }

    #[test]
    fn get_indexed_empty_tree_returns_none() {
        let tree = new_tree();
        assert_eq!(
            tree.get_indexed("ns", Hash::default(), &0u64.to_le_bytes())
                .unwrap(),
            None
        );
    }

    #[test]
    fn get_indexed_after_insert_indexed_returns_leaf_hash() {
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"first")
            .unwrap();
        let expected = Sha256Hasher::hash(b"first");
        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(expected)
        );
    }

    #[test]
    fn get_indexed_missing_index_not_contained() {
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"first")
            .unwrap();
        // get_indexed is a raw traversal and may return Some(other_leaf) when the
        // path ends at a different leaf. Use contains_leaf to check membership.
        let key1 = Node::key_from_bytes(&1u64.to_le_bytes()).unwrap();
        assert!(
            !tree
                .contains_leaf("ns", root, key1, Sha256Hasher::hash(b"second"))
                .unwrap()
        );
    }

    #[test]
    fn get_indexed_multiple_indices_retrieve_correct_values() {
        let tree = new_tree();
        let root = (0u64..4).fold(Hash::default(), |r, i| {
            let data = (i as u8).to_string();
            tree.insert_indexed("ns", r, &i.to_le_bytes(), data.as_bytes())
                .unwrap()
        });
        for i in 0u64..4 {
            let data = (i as u8).to_string();
            let expected = Sha256Hasher::hash(data.as_bytes());
            assert_eq!(
                tree.get_indexed("ns", root, &i.to_le_bytes()).unwrap(),
                Some(expected),
                "index {i}"
            );
        }
    }

    #[test]
    fn get_indexed_historical_root_isolation() {
        let tree = new_tree();
        let root1 = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root2 = tree
            .insert_indexed("ns", root1, &1u64.to_le_bytes(), b"b")
            .unwrap();

        // Historical root1 does not contain index 1 — verified via contains_leaf
        // because get_indexed is a raw traversal that may hit a different leaf.
        let key1 = Node::key_from_bytes(&1u64.to_le_bytes()).unwrap();
        assert!(
            !tree
                .contains_leaf("ns", root1, key1, Sha256Hasher::hash(b"b"))
                .unwrap()
        );
        // Current root2 returns the correct leaf hash for both indices.
        assert_eq!(
            tree.get_indexed("ns", root2, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"a"))
        );
        assert_eq!(
            tree.get_indexed("ns", root2, &1u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"b"))
        );
    }

    #[test]
    fn insert_indexed_same_index_overrides_leaf() {
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"first")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"second")
            .unwrap();
        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"second"))
        );
    }

    #[test]
    fn insert_indexed_override_does_not_affect_other_indices() {
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"a-updated")
            .unwrap();
        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"a-updated"))
        );
        assert_eq!(
            tree.get_indexed("ns", root, &1u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"b"))
        );
    }

    #[test]
    fn insert_indexed_override_with_same_data_is_idempotent() {
        // Re-inserting the same data at the same index must not change the root.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"value")
            .unwrap();
        let root2 = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"value")
            .unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn insert_indexed_override_changes_root() {
        // Overriding with different data must produce a different root.
        let tree = new_tree();
        let root_before = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"old")
            .unwrap();
        let root_after = tree
            .insert_indexed("ns", root_before, &0u64.to_le_bytes(), b"new")
            .unwrap();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn insert_indexed_override_back_reverts_root() {
        // Overriding A→B then B→A must restore the exact original root.
        let tree = new_tree();
        let root_a = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root_b = tree
            .insert_indexed("ns", root_a, &0u64.to_le_bytes(), b"b")
            .unwrap();
        let root_reverted = tree
            .insert_indexed("ns", root_b, &0u64.to_le_bytes(), b"a")
            .unwrap();
        assert_eq!(root_a, root_reverted);
    }

    #[test]
    fn insert_indexed_sequential_overrides_only_last_value_persists() {
        // Override the same index five times; only the last value should be visible.
        let tree = new_tree();
        let values: &[&[u8]] = &[b"v0", b"v1", b"v2", b"v3", b"v4"];
        let root = values
            .iter()
            .enumerate()
            .fold(Hash::default(), |r, (i, v)| {
                // index stays 0 for all iterations; data changes each time
                let _ = i;
                tree.insert_indexed("ns", r, &0u64.to_le_bytes(), v)
                    .unwrap()
            });
        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"v4"))
        );
        for v in &values[..4] {
            let key0 = Node::key_from_bytes(&0u64.to_le_bytes()).unwrap();
            assert!(
                !tree
                    .contains_leaf("ns", root, key0, Sha256Hasher::hash(v))
                    .unwrap(),
                "stale value {:?} should not be contained",
                v
            );
        }
    }

    #[test]
    fn insert_indexed_historical_root_preserves_old_value_after_override() {
        // root_old was computed before the override — it must still resolve to
        // the original value, regardless of what happened afterwards.
        let tree = new_tree();
        let root_old = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"old")
            .unwrap();
        let root_new = tree
            .insert_indexed("ns", root_old, &0u64.to_le_bytes(), b"new")
            .unwrap();

        assert_eq!(
            tree.get_indexed("ns", root_old, &0u64.to_le_bytes())
                .unwrap(),
            Some(Sha256Hasher::hash(b"old")),
            "historical root must still see old value"
        );
        assert_eq!(
            tree.get_indexed("ns", root_new, &0u64.to_le_bytes())
                .unwrap(),
            Some(Sha256Hasher::hash(b"new")),
            "new root must see updated value"
        );
    }

    #[test]
    fn insert_indexed_override_in_large_tree_leaves_others_intact() {
        // Build a tree with 16 consecutive indices, override index 7,
        // then verify every index still resolves correctly.
        let tree = new_tree();
        let n = 16u64;
        let root = (0..n).fold(Hash::default(), |r, i| {
            let data = alloc::format!("leaf-{i}");
            tree.insert_indexed("ns", r, &i.to_le_bytes(), data.as_bytes())
                .unwrap()
        });

        let root = tree
            .insert_indexed("ns", root, &7u64.to_le_bytes(), b"leaf-7-updated")
            .unwrap();

        for i in 0..n {
            let expected = if i == 7 {
                Sha256Hasher::hash(b"leaf-7-updated")
            } else {
                let data = alloc::format!("leaf-{i}");
                Sha256Hasher::hash(data.as_bytes())
            };
            assert_eq!(
                tree.get_indexed("ns", root, &i.to_le_bytes()).unwrap(),
                Some(expected),
                "wrong value at index {i}"
            );
        }
    }

    #[test]
    fn insert_indexed_override_old_value_not_contained_afterwards() {
        // After an override the old value must not pass contains_leaf at
        // that index's key.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"old")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"new")
            .unwrap();

        let key0 = Node::key_from_bytes(&0u64.to_le_bytes()).unwrap();
        assert!(
            !tree
                .contains_leaf("ns", root, key0, Sha256Hasher::hash(b"old"))
                .unwrap(),
            "old value must not be contained after override"
        );
        assert!(
            tree.contains_leaf("ns", root, key0, Sha256Hasher::hash(b"new"))
                .unwrap(),
            "new value must be contained after override"
        );
    }

    #[test]
    fn insert_indexed_override_of_collision_pair_member() {
        // Indices 0 and 1 have keys that share a 7-bit prefix (both start with
        // 0000_000x in MSB-first order).  Override index 0 after both are
        // inserted; index 1 must be unaffected.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"a-new")
            .unwrap();

        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"a-new")),
            "overridden index 0 must hold new value"
        );
        assert_eq!(
            tree.get_indexed("ns", root, &1u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"b")),
            "index 1 must be unchanged"
        );

        let key0 = Node::key_from_bytes(&0u64.to_le_bytes()).unwrap();
        assert!(
            !tree
                .contains_leaf("ns", root, key0, Sha256Hasher::hash(b"a"))
                .unwrap(),
            "old value of index 0 must no longer be contained"
        );
    }

    #[test]
    fn insert_indexed_override_proof_valid_for_new_value() {
        // get_indexed_opening must produce a valid proof for the new value
        // after an override.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"old")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"other")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"new")
            .unwrap();

        let proof = tree
            .get_indexed_opening("ns", root, &0u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            proof
                .leaf_indexed_root(&0u64.to_le_bytes(), Sha256Hasher::hash(b"new"))
                .unwrap(),
            root,
            "proof must verify for new value"
        );
        assert_ne!(
            proof
                .leaf_indexed_root(&0u64.to_le_bytes(), Sha256Hasher::hash(b"old"))
                .unwrap(),
            root,
            "proof must not verify for old value"
        );
    }

    #[test]
    fn insert_indexed_override_proof_valid_for_sibling_unchanged() {
        // After overriding index 0, the proof for index 1 must still be valid.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"a-new")
            .unwrap();

        let proof1 = tree
            .get_indexed_opening("ns", root, &1u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            proof1
                .leaf_indexed_root(&1u64.to_le_bytes(), Sha256Hasher::hash(b"b"))
                .unwrap(),
            root,
            "sibling proof must still be valid after override"
        );
    }

    #[test]
    fn insert_indexed_override_then_insert_new_index() {
        // After an override, inserting a brand-new index must still work
        // and not disturb the overridden or older leaves.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"a-new")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();

        assert_eq!(
            tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"a-new"))
        );
        assert_eq!(
            tree.get_indexed("ns", root, &1u64.to_le_bytes()).unwrap(),
            Some(Sha256Hasher::hash(b"b"))
        );
    }

    // -----------------------------------------------------------------------
    // Combined get_indexed + contains_leaf cross-contamination tests
    //
    // These tests assert that for every *inserted* index, get_indexed returns
    // exactly the hash of the data that was inserted at that index — never the
    // hash produced by inserting different data, whether at another index or as
    // a previous override at the same index.
    //
    // Note: for indices that were *never* inserted, get_indexed may return a
    // hash that belongs to another leaf whose traversal path happens to share a
    // prefix with the queried key.  That is a well-documented property of
    // sparse Merkle trees and is tested separately at the bottom of this block.
    // -----------------------------------------------------------------------

    /// Helper: assert `get_indexed(root, i)` == Some(H::hash(data)) and
    /// `contains_leaf(root, key_i, H::hash(data))` is true.
    fn assert_indexed_contains(
        tree: &MerkleTree<MemoryBackend, Sha256Hasher>,
        root: Hash,
        index: u64,
        data: &[u8],
    ) {
        let expected = Sha256Hasher::hash(data);
        assert_eq!(
            tree.get_indexed("ns", root, &index.to_le_bytes()).unwrap(),
            Some(expected),
            "get_indexed mismatch at index {index}"
        );
        let key = Node::key_from_bytes(&index.to_le_bytes()).unwrap();
        assert!(
            tree.contains_leaf("ns", root, key, expected).unwrap(),
            "contains_leaf false at index {index}"
        );
    }

    /// Helper: assert `contains_leaf(root, key_i, H::hash(foreign_data))` is
    /// false — the foreign leaf must not be reachable via key_i.
    fn assert_not_contaminated(
        tree: &MerkleTree<MemoryBackend, Sha256Hasher>,
        root: Hash,
        queried_index: u64,
        foreign_data: &[u8],
    ) {
        let foreign_leaf = Sha256Hasher::hash(foreign_data);
        let key = Node::key_from_bytes(&queried_index.to_le_bytes()).unwrap();
        assert!(
            !tree.contains_leaf("ns", root, key, foreign_leaf).unwrap(),
            "index {queried_index} is contaminated with data {:?}",
            foreign_data
        );
    }

    #[test]
    fn get_indexed_and_contains_leaf_agree_for_all_inserted_indices() {
        // For N inserted indices, every get_indexed returns its own leaf hash
        // and contains_leaf confirms it.
        let tree = new_tree();
        let n = 8u64;
        let root = (0..n).fold(Hash::default(), |r, i| {
            let data = alloc::format!("data-{i}");
            tree.insert_indexed("ns", r, &i.to_le_bytes(), data.as_bytes())
                .unwrap()
        });
        for i in 0..n {
            let data = alloc::format!("data-{i}");
            assert_indexed_contains(&tree, root, i, data.as_bytes());
        }
    }

    #[test]
    fn contains_leaf_cross_index_never_true_for_foreign_data() {
        // For every pair (i, j) with i != j, the data inserted at index j must
        // not be reachable via index i's key.
        let tree = new_tree();
        let n = 8u64;
        let root = (0..n).fold(Hash::default(), |r, i| {
            let data = alloc::format!("data-{i}");
            tree.insert_indexed("ns", r, &i.to_le_bytes(), data.as_bytes())
                .unwrap()
        });
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let foreign = alloc::format!("data-{j}");
                assert_not_contaminated(&tree, root, i, foreign.as_bytes());
            }
        }
    }

    #[test]
    fn get_indexed_returns_own_data_for_collision_prefix_pair() {
        // Indices 0 and 1 have keys that share a 7-bit prefix (bits 0-6 = 0,
        // diverge only at bit 7).  Each must still return its own data.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"alpha")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"beta")
            .unwrap();

        assert_indexed_contains(&tree, root, 0, b"alpha");
        assert_indexed_contains(&tree, root, 1, b"beta");
        assert_not_contaminated(&tree, root, 0, b"beta");
        assert_not_contaminated(&tree, root, 1, b"alpha");
    }

    #[test]
    fn get_indexed_returns_own_data_after_override_no_cross_contamination() {
        // After overriding index 0, get_indexed must return the new value and
        // contains_leaf must confirm it; the old value and every other index's
        // data must not be reachable via key_0.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"old")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &2u64.to_le_bytes(), b"c")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &0u64.to_le_bytes(), b"new")
            .unwrap();

        assert_indexed_contains(&tree, root, 0, b"new");
        assert_not_contaminated(&tree, root, 0, b"old"); // old value gone
        assert_not_contaminated(&tree, root, 0, b"b");
        assert_not_contaminated(&tree, root, 0, b"c");

        // Siblings are also unaffected.
        assert_indexed_contains(&tree, root, 1, b"b");
        assert_indexed_contains(&tree, root, 2, b"c");
    }

    #[test]
    fn get_indexed_large_tree_no_cross_contamination() {
        // Build a 16-leaf tree; for every (i, j) pair with i != j assert that
        // the data at j is not reachable via i's key.
        let tree = new_tree();
        let n = 16u64;
        let root = (0..n).fold(Hash::default(), |r, i| {
            let data = alloc::format!("leaf-{i:03}");
            tree.insert_indexed("ns", r, &i.to_le_bytes(), data.as_bytes())
                .unwrap()
        });
        for i in 0..n {
            let own = alloc::format!("leaf-{i:03}");
            assert_indexed_contains(&tree, root, i, own.as_bytes());
            for j in 0..n {
                if i == j {
                    continue;
                }
                let foreign = alloc::format!("leaf-{j:03}");
                assert_not_contaminated(&tree, root, i, foreign.as_bytes());
            }
        }
    }

    #[test]
    fn get_indexed_uninserted_index_false_positive_documented() {
        // This test documents the known sparse-Merkle-tree property:
        // an *uninserted* index whose key shares a traversal path with an
        // inserted leaf will return that leaf's hash from get_indexed.
        //
        // After inserting indices 0 ([0x00,0,...]) and 1 ([0x01,0,...]),
        // the two keys diverge only at bit 7 (the LSB of byte 0).  Any
        // uninserted index whose key also starts with byte 0x01 follows the
        // exact same path and terminates at leaf_1.
        //
        // Index 257 has to_le_bytes() = [0x01, 0x01, 0, ...].  Its key shares
        // all 8 bits of byte 0 with key_1, so traversal lands on leaf_1 even
        // though index 257 was never inserted.
        //
        // NOTE: contains_leaf cannot distinguish this case — it performs the
        // same traversal and returns true for both key_1 and key_257.  This is
        // a well-documented limitation of sparse Merkle trees for uninserted
        // positions.  The inserted indices (0 and 1) are always correct.
        let tree = new_tree();
        let root = tree
            .insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"a")
            .unwrap();
        let root = tree
            .insert_indexed("ns", root, &1u64.to_le_bytes(), b"b")
            .unwrap();

        let leaf_1 = Sha256Hasher::hash(b"b");

        // Uninserted index 257 (key starts with 0x01) lands on index 1's leaf.
        assert_eq!(
            tree.get_indexed("ns", root, &257u64.to_le_bytes()).unwrap(),
            Some(leaf_1),
            "index 257 (uninserted) is expected to land on index 1's leaf"
        );

        // Inserted indices are never affected — they always return their own data.
        assert_indexed_contains(&tree, root, 0, b"a");
        assert_indexed_contains(&tree, root, 1, b"b");
        assert_not_contaminated(&tree, root, 0, b"b");
        assert_not_contaminated(&tree, root, 1, b"a");
    }

    #[test]
    fn arbitrary_key_independent_of_leaf_hash() {
        // Insert two leaves whose hashes share a long prefix, but use
        // completely different (non-colliding) keys. The tree should place
        // them at the positions dictated by the keys, not by their hashes.
        let tree = new_tree();

        // Arbitrary distinct keys that diverge at bit 0.
        let key_a: Hash = {
            let mut k = [0u8; 32];
            k[0] = 0b0000_0000; // bit 0 = 0 → left
            k
        };
        let key_b: Hash = {
            let mut k = [0u8; 32];
            k[0] = 0b1000_0000; // bit 0 = 1 → right
            k
        };

        let root = tree
            .insert_keyed("ns", Hash::default(), key_a, Sha256Hasher::hash(b"leaf-a"))
            .unwrap();
        let root = tree
            .insert_keyed("ns", root, key_b, Sha256Hasher::hash(b"leaf-b"))
            .unwrap();

        let ha = Sha256Hasher::hash(b"leaf-a");
        let hb = Sha256Hasher::hash(b"leaf-b");

        assert_eq!(tree.get("ns", root, key_a).unwrap(), Some(ha));
        assert_eq!(tree.get("ns", root, key_b).unwrap(), Some(hb));
        assert!(tree.contains("ns", root, key_a, b"leaf-a").unwrap());
        assert!(tree.contains("ns", root, key_b, b"leaf-b").unwrap());
        // Cross-check: wrong key returns the wrong (or no) leaf.
        assert_ne!(tree.get("ns", root, key_a).unwrap(), Some(hb));
    }
}
