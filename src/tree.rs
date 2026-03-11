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
/// Each leaf is addressed by a caller-supplied **key** (a [`Hash`]-sized value
/// whose bits determine the path through the tree). The leaf's *content* is
/// stored as `H::hash(leaf_data)` at the terminal node. A separate namespace
/// `"{ns}-key"` in the backend holds a `leaf_hash → key` mapping so that
/// [`push_down`][Self::push_down] can look up the traversal key for existing
/// leaves when resolving collisions.
///
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

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// Uses `H::hash(leaf_data)` as the traversal key. For a custom key use
    /// [`Self::insert_keyed`].
    ///
    /// Pass [`Hash::default`] as `root` for an empty tree.
    ///
    /// # Errors
    /// Returns an error only if two distinct keys share all 256 bits
    /// (a hash collision in `H`).
    pub fn insert(&self, ns: &str, root: Hash, leaf_data: impl AsRef<[u8]>) -> Result<Hash> {
        let leaf = leaf_data.as_ref();
        self.insert_keyed(ns, root, H::hash(leaf), leaf)
    }

    /// Insert a leaf into the tree identified by `root`, returning the new
    /// root hash.
    ///
    /// The traversal key is `H::hash(index.to_le_bytes())`, giving each
    /// integer index a stable, uniformly-distributed position in the tree.
    ///
    /// Pass [`Hash::default`] as `root` for an empty tree.
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
        let key = Node::key_from_bytes(index)?;
        self.insert_keyed(ns, root, key, leaf_data)
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
    fn insert_keyed(
        &self,
        ns: &str,
        root: Hash,
        key: Hash,
        leaf_data: impl AsRef<[u8]>,
    ) -> Result<Hash> {
        let leaf_hash = H::hash(leaf_data.as_ref());
        // Store the leaf→key mapping so push_down can resolve existing leaves.
        self.backend
            .set(&format!("{ns}-key"), &leaf_hash[..], &key[..])?;
        self.insert_at(ns, root, key, leaf_hash, 0)
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
        Ok(self.get(ns, root, key)? == Some(H::hash(leaf_data.as_ref())))
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
        let key = H::hash(leaf_data.as_ref());
        let siblings = self.collect_proof(ns, root, key)?;
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
        leaf_data: impl AsRef<[u8]>,
    ) -> Result<MerkleOpening<H>> {
        let _ = leaf_data; // leaf hash is computed inside MerkleOpening::leaf_indexed_root
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
            assert_eq!(proof.leaf_root(leaf), root);
        }
    }

    #[test]
    fn get_opening_rejects_wrong_root() {
        let (tree, root) = insert_all(&[b"a", b"b"]);
        let _ = root;
        let bad_root = Sha256Hasher::hash(b"not a root");
        let proof = tree.get_opening("ns", bad_root, b"a").unwrap();
        assert_ne!(proof.leaf_root(b"a"), Sha256Hasher::hash(b"a root"));
    }

    #[test]
    fn get_opening_with_3_bit_prefix_collision() {
        let (a, b) = find_3bit_prefix_pair();
        let tree = new_tree();
        let root = tree.insert("ns", Hash::default(), &a).unwrap();
        let root = tree.insert("ns", root, &b).unwrap();

        let proof_a = tree.get_opening("ns", root, &a).unwrap();
        let proof_b = tree.get_opening("ns", root, &b).unwrap();

        assert_eq!(proof_a.leaf_root(&a), root);
        assert_eq!(proof_b.leaf_root(&b), root);

        assert_ne!(proof_a.leaf_root(&b), root);
        assert_ne!(proof_b.leaf_root(&a), root);
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
            .insert_keyed("ns", Hash::default(), key_a, b"leaf-a")
            .unwrap();
        let root = tree.insert_keyed("ns", root, key_b, b"leaf-b").unwrap();

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
