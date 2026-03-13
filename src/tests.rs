//! Demonstrations of the `merkl` public API.
//!
//! Each test illustrates a distinct usage pattern or API contract.
//! Read these as executable examples before writing integration code.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::{Hash, Hasher, KvsBackend, MemoryBackend, MerkleTree};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Shared hasher and helpers
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn hash(data: &[u8]) -> Hash {
        Sha256::digest(data).into()
    }
}

fn simple_tree() -> MerkleTree<MemoryBackend, Sha256Hasher> {
    MerkleTree::new(MemoryBackend::new())
}

fn shared_tree() -> (MerkleTree<SharedBackend, Sha256Hasher>, SharedBackend) {
    let backend = SharedBackend::new();
    (MerkleTree::new(backend.clone()), backend)
}

// ---------------------------------------------------------------------------
// SharedBackend — demonstrates implementing a custom KvsBackend
//
// All clones share the same underlying storage via `Rc<RefCell<…>>`.
// Keeping a clone outside `MerkleTree` lets callers inspect the backend
// directly — useful for proof generation, auditing, or debugging.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SharedBackend(Rc<RefCell<BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>>>);

impl SharedBackend {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(BTreeMap::new())))
    }
}

impl KvsBackend for SharedBackend {
    type Get = Vec<u8>;

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(ns).and_then(|m| m.get(key)).cloned())
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        self.0
            .borrow_mut()
            .entry(ns.into())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CountingBackend — demonstrates intercepting every read and write
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CountingBackend {
    store: Rc<RefCell<BTreeMap<String, BTreeMap<Vec<u8>, Vec<u8>>>>>,
    reads: Rc<RefCell<usize>>,
    writes: Rc<RefCell<usize>>,
}

impl CountingBackend {
    fn new() -> Self {
        Self {
            store: Rc::new(RefCell::new(BTreeMap::new())),
            reads: Rc::new(RefCell::new(0)),
            writes: Rc::new(RefCell::new(0)),
        }
    }

    fn reads(&self) -> usize {
        *self.reads.borrow()
    }

    fn writes(&self) -> usize {
        *self.writes.borrow()
    }
}

impl KvsBackend for CountingBackend {
    type Get = Vec<u8>;

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        *self.reads.borrow_mut() += 1;
        Ok(self
            .store
            .borrow()
            .get(ns)
            .and_then(|m| m.get(key))
            .cloned())
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        *self.writes.borrow_mut() += 1;
        self.store
            .borrow_mut()
            .entry(ns.into())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Basic operations
// ---------------------------------------------------------------------------

#[test]
fn empty_tree_root_is_zero() {
    assert_eq!(Hash::default(), [0u8; 32]);
}

#[test]
fn single_insert_root_equals_leaf_hash() {
    let tree = simple_tree();
    let root = tree.insert("ns", Hash::default(), b"hello").unwrap();
    assert_eq!(root, Sha256Hasher::hash(b"hello"));
}

#[test]
fn all_inserted_leaves_are_retrievable() {
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"alice", b"bob", b"carol", b"dave"];
    let root = leaves
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    for leaf in leaves {
        assert_eq!(
            tree.get("ns", root, Sha256Hasher::hash(leaf)).unwrap(),
            Some(Sha256Hasher::hash(leaf))
        );
    }
}

#[test]
fn get_returns_the_terminal_hash_at_the_key_position() {
    let tree = simple_tree();
    let root = tree.insert("ns", Hash::default(), b"alpha").unwrap();

    assert_eq!(
        tree.get("ns", root, Sha256Hasher::hash(b"alpha")).unwrap(),
        Some(Sha256Hasher::hash(b"alpha")),
    );

    // In a one-leaf tree every key path leads to the same sole leaf.
    let terminal = tree.get("ns", root, Sha256Hasher::hash(b"beta")).unwrap();
    assert!(terminal.is_some());
    assert_ne!(terminal.unwrap(), Sha256Hasher::hash(b"beta"));
}

#[test]
fn contains_distinguishes_members_from_non_members() {
    let tree = simple_tree();
    let root = [b"alice" as &[u8], b"bob"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    assert!(
        tree.contains("ns", root, Sha256Hasher::hash(b"alice"), b"alice")
            .unwrap()
    );
    assert!(
        tree.contains("ns", root, Sha256Hasher::hash(b"bob"), b"bob")
            .unwrap()
    );
    // "carol" is absent — get() would still return Some(...) pointing at
    // whichever leaf terminates along carol's path, but contains() is false.
    assert!(
        !tree
            .contains("ns", root, Sha256Hasher::hash(b"carol"), b"carol")
            .unwrap()
    );
}

// ---------------------------------------------------------------------------
// Root properties: determinism and idempotency
// ---------------------------------------------------------------------------

#[test]
fn root_is_independent_of_insertion_order() {
    let insert = |order: &[&[u8]]| {
        let tree = simple_tree();
        order
            .iter()
            .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap())
    };

    let r1 = insert(&[b"a", b"b", b"c"]);
    let r2 = insert(&[b"c", b"a", b"b"]);
    let r3 = insert(&[b"b", b"c", b"a"]);
    assert_eq!(r1, r2);
    assert_eq!(r2, r3);
}

#[test]
fn inserting_existing_leaf_is_idempotent() {
    let tree = simple_tree();
    let root = [b"x" as &[u8], b"y"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    assert_eq!(tree.insert("ns", root, b"x").unwrap(), root);
    assert_eq!(tree.insert("ns", root, b"y").unwrap(), root);
}

// ---------------------------------------------------------------------------
// Sub-trees and historical roots
// ---------------------------------------------------------------------------

#[test]
fn same_backend_holds_multiple_independent_subtrees() {
    let tree = simple_tree();

    let root_a = tree.insert("ns", Hash::default(), b"only in A").unwrap();
    let root_b = tree.insert("ns", Hash::default(), b"only in B").unwrap();

    let proof = tree.get_opening("ns", root_a, b"only in A").unwrap();
    assert_eq!(proof.leaf_root(Sha256Hasher::hash(b"only in A")), root_a);
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(b"only in B")), root_a);

    let proof = tree.get_opening("ns", root_b, b"only in B").unwrap();
    assert_eq!(proof.leaf_root(Sha256Hasher::hash(b"only in B")), root_b);
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(b"only in A")), root_b);
}

#[test]
fn every_past_root_is_a_stable_snapshot() {
    let tree = simple_tree();
    let root_v1 = tree.insert("ns", Hash::default(), b"first").unwrap();
    let root_v2 = tree.insert("ns", root_v1, b"second").unwrap();

    assert_ne!(root_v1, root_v2);

    let proof = tree.get_opening("ns", root_v1, b"first").unwrap();
    assert_eq!(proof.leaf_root(Sha256Hasher::hash(b"first")), root_v1);
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(b"second")), root_v1);

    assert_eq!(
        tree.get("ns", root_v2, Sha256Hasher::hash(b"first"))
            .unwrap(),
        Some(Sha256Hasher::hash(b"first")),
    );
    assert_eq!(
        tree.get("ns", root_v2, Sha256Hasher::hash(b"second"))
            .unwrap(),
        Some(Sha256Hasher::hash(b"second")),
    );
}

// ---------------------------------------------------------------------------
// Membership proofs
// ---------------------------------------------------------------------------

#[test]
fn get_opening_root_matches_tree_root() {
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"alpha", b"beta", b"gamma"];
    let root = leaves
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    for leaf in leaves {
        let proof = tree.get_opening("ns", root, leaf).unwrap();
        assert_eq!(proof.leaf_root(Sha256Hasher::hash(leaf)), root);
    }
}

#[test]
fn get_opening_wrong_leaf_does_not_match_root() {
    let tree = simple_tree();
    let root = [b"a" as &[u8], b"b"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    let proof = tree.get_opening("ns", root, b"a").unwrap();
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(b"b")), root);
}

#[test]
fn get_opening_tampered_sibling_does_not_match_root() {
    let tree = simple_tree();
    let root = [b"x" as &[u8], b"y"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    let mut proof = tree.get_opening("ns", root, b"x").unwrap();
    if let Some(h) = proof.siblings.first_mut() {
        h[0] ^= 0xff;
    }
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(b"x")), root);
}

#[test]
fn get_indexed_opening_root_matches_tree_root() {
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"first", b"second", b"third"];
    let root = leaves
        .iter()
        .enumerate()
        .fold(Hash::default(), |r, (i, l)| {
            tree.insert_indexed("ns", r, &i.to_le_bytes(), l).unwrap()
        });

    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree
            .get_indexed_opening("ns", root, &i.to_le_bytes())
            .unwrap();
        assert_eq!(
            proof
                .leaf_indexed_root(&i.to_le_bytes(), Sha256Hasher::hash(leaf))
                .unwrap(),
            root
        );
    }
}

#[test]
fn get_indexed_opening_wrong_leaf_does_not_match_root() {
    let tree = simple_tree();
    let root = tree
        .insert_indexed("ns", Hash::default(), &[], b"payload")
        .unwrap();

    let proof = tree.get_indexed_opening("ns", root, &[]).unwrap();
    assert_ne!(
        proof
            .leaf_indexed_root(&[], Sha256Hasher::hash(b"wrong payload"))
            .unwrap(),
        root
    );
}

// ---------------------------------------------------------------------------
// Non-membership proofs
// ---------------------------------------------------------------------------

/// Return the first index (skipping `skip`) whose SHA-256 key has the given
/// bit-0 value. Terminates in ≤ 2 tries on average (50 % per candidate).
fn find_index_with_key_bit0(target_bit: u8, skip: &[u64]) -> u64 {
    let xor = skip.iter().copied().fold(0u64, |acc, x| acc ^ !x);
    let xor = xor & 0b01111111;
    let xor = xor | ((target_bit as u64) << 7);

    xor
}

#[test]
fn non_membership_leaf_root_empty_tree() {
    // In an empty tree the root is Hash::default(). Every path is empty, so
    // non_membership_leaf_root must equal Hash::default() for any leaf.
    let tree = simple_tree();
    let proof = tree
        .get_opening("ns", Hash::default(), b"anything")
        .unwrap();
    assert_eq!(proof.non_membership_leaf_root(b"anything"), Hash::default());
}

#[test]
fn non_membership_leaf_indexed_root_empty_tree() {
    let tree = simple_tree();
    let proof = tree
        .get_indexed_opening("ns", Hash::default(), &[7])
        .unwrap();
    assert_eq!(
        proof.non_membership_leaf_indexed_root(&[7]).unwrap(),
        Hash::default()
    );
}

#[test]
fn non_membership_leaf_root_rejects_present_leaf() {
    // For a leaf that IS in the tree, proof.terminal == H::hash(leaf), which
    // reveals membership.  A verifier proves non-membership by checking that
    // the root reconstruction holds AND terminal != expected_leaf_hash.
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"alice", b"bob", b"carol"];
    let root = leaves
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    for leaf in leaves {
        let leaf_hash = Sha256Hasher::hash(leaf);
        let proof = tree.get_opening("ns", root, leaf).unwrap();
        assert_eq!(proof.leaf_root(leaf_hash), root); // sanity: membership holds
        // Reconstruction succeeds (terminal = leaf_hash), but terminal == leaf_hash
        // reveals this is a membership proof, not non-membership.
        assert_eq!(proof.non_membership_leaf_root(leaf), root);
        assert_eq!(proof.terminal, leaf_hash); // proves presence, not absence
    }
}

#[test]
fn non_membership_leaf_indexed_root_rejects_present_index() {
    // For an index that IS in the tree, proof.terminal == H::hash(leaf).
    // A verifier distinguishes non-membership by checking terminal == Hash::default()
    // (empty slot) or terminal != expected_leaf_hash (different occupant).
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"first", b"second", b"third"];
    let root = leaves
        .iter()
        .enumerate()
        .fold(Hash::default(), |r, (i, l)| {
            tree.insert_indexed("ns", r, &i.to_le_bytes(), l).unwrap()
        });

    for (i, leaf) in leaves.iter().enumerate() {
        let leaf_hash = Sha256Hasher::hash(leaf);
        let proof = tree
            .get_indexed_opening("ns", root, &i.to_le_bytes())
            .unwrap();
        assert_eq!(
            proof
                .leaf_indexed_root(&i.to_le_bytes(), leaf_hash)
                .unwrap(),
            root
        ); // sanity
        // Reconstruction succeeds, but terminal == leaf_hash reveals presence.
        assert_eq!(
            proof
                .non_membership_leaf_indexed_root(&i.to_le_bytes())
                .unwrap(),
            root
        );
        assert_eq!(proof.terminal, leaf_hash); // proves presence, not absence
    }
}

#[test]
fn non_membership_leaf_indexed_root_validates_empty_slot() {
    // Strategy: find two indices whose key hashes share bit-0.  By pigeonhole
    // this takes at most 3 candidates.  Inserting only those two leaves the
    // entire opposite-bit-0 branch empty at the root.  Any absent index with
    // the opposite bit-0 therefore reaches that empty slot immediately.
    let tree = simple_tree();

    let i = find_index_with_key_bit0(0, &[]);
    let j = find_index_with_key_bit0(0, &[i]);
    let root = tree
        .insert_indexed("ns", Hash::default(), &i.to_le_bytes(), &i.to_le_bytes())
        .unwrap();
    let root = tree
        .insert_indexed("ns", root, &j.to_le_bytes(), &j.to_le_bytes())
        .unwrap();

    let absent = find_index_with_key_bit0(1, &[i, j]);
    let proof = tree
        .get_indexed_opening("ns", root, &absent.to_le_bytes())
        .unwrap();

    assert_eq!(
        proof
            .non_membership_leaf_indexed_root(&absent.to_le_bytes())
            .unwrap(),
        root
    );
    assert_ne!(
        proof
            .leaf_indexed_root(&absent.to_le_bytes(), Sha256Hasher::hash(b"irrelevant"))
            .unwrap(),
        root
    );
}

#[test]
fn non_membership_leaf_root_validates_empty_slot() {
    // Same strategy: use i.to_le_bytes() as leaf data so that the traversal
    // key (H::hash of the leaf data) matches the indexed-key helper above.
    let tree = simple_tree();

    let i = find_index_with_key_bit0(0, &[]);
    let j = find_index_with_key_bit0(0, &[i]);
    let leaf_a = i.to_le_bytes();
    let leaf_b = j.to_le_bytes();
    let root = tree
        .insert("ns", Hash::default(), leaf_a.as_slice())
        .unwrap();
    let root = tree.insert("ns", root, leaf_b.as_slice()).unwrap();

    let absent_i = find_index_with_key_bit0(1, &[i, j]);
    let absent = absent_i.to_le_bytes();

    let proof = tree.get_opening("ns", root, absent.as_slice()).unwrap();
    assert_eq!(proof.non_membership_leaf_root(absent), root);
    assert_ne!(proof.leaf_root(Sha256Hasher::hash(&absent)), root);
}

// ---------------------------------------------------------------------------
// Custom backends
// ---------------------------------------------------------------------------

#[test]
fn custom_backend_intercepts_all_reads_and_writes() {
    let backend = CountingBackend::new();
    let tree = MerkleTree::<_, Sha256Hasher>::new(backend.clone());

    // Single insert into an empty tree: one write for the key mapping,
    // no reads (the empty root is detected without a backend lookup).
    let root = tree.insert("ns", Hash::default(), b"first").unwrap();
    assert_eq!(backend.reads(), 0);
    assert_eq!(backend.writes(), 1);

    // Second insert: one write for the key mapping, then a read to discover
    // the existing leaf terminal, a read to retrieve its key mapping for
    // push_down, and a write for the new internal node.
    tree.insert("ns", root, b"second").unwrap();
    assert_eq!(backend.reads(), 2);
    assert_eq!(backend.writes(), 3);
}

#[test]
fn custom_backend_with_shared_storage_enables_external_inspection() {
    let (tree, backend) = shared_tree();
    let root = [b"x" as &[u8], b"y", b"z"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert("ns", r, l).unwrap());

    let node_count = backend.0.borrow().get("ns").map_or(0, |m| m.len());
    assert!(node_count > 0, "internal nodes must have been stored");

    let proof = tree.get_opening("ns", root, b"x").unwrap();
    assert_eq!(proof.leaf_root(Sha256Hasher::hash(b"x")), root);
}

// ---------------------------------------------------------------------------
// EphemeralBackend integration with MerkleTree
//
// Ephemeral trees are created via MerkleTree::to_ephemeral(), which borrows
// the source tree's backend.  All mutations are isolated — they never touch
// the source backend.
// ---------------------------------------------------------------------------

#[test]
fn ephemeral_tree_inserts_do_not_reach_source_backend() {
    let source_tree = simple_tree();
    let source_root = source_tree
        .insert("ns", Hash::default(), b"base_leaf")
        .unwrap();

    let ephemeral_tree = source_tree.to_ephemeral();
    let ephemeral_root = ephemeral_tree
        .insert("ns", source_root, b"forked_leaf")
        .unwrap();

    // The ephemeral root has both leaves.
    assert!(
        ephemeral_tree
            .contains(
                "ns",
                ephemeral_root,
                Sha256Hasher::hash(b"base_leaf"),
                b"base_leaf"
            )
            .unwrap()
    );
    assert!(
        ephemeral_tree
            .contains(
                "ns",
                ephemeral_root,
                Sha256Hasher::hash(b"forked_leaf"),
                b"forked_leaf"
            )
            .unwrap()
    );

    // The source root is unchanged; the forked leaf is absent.
    assert!(
        source_tree
            .contains(
                "ns",
                source_root,
                Sha256Hasher::hash(b"base_leaf"),
                b"base_leaf"
            )
            .unwrap()
    );
    assert!(
        !source_tree
            .contains(
                "ns",
                source_root,
                Sha256Hasher::hash(b"forked_leaf"),
                b"forked_leaf"
            )
            .unwrap()
    );
}

#[test]
fn ephemeral_tree_reads_source_leaves() {
    let source_tree = simple_tree();
    let leaves: &[&[u8]] = &[b"alice", b"bob", b"carol"];
    let root = leaves.iter().fold(Hash::default(), |r, l| {
        source_tree.insert("ns", r, l).unwrap()
    });

    let ephemeral_tree = source_tree.to_ephemeral();

    for leaf in leaves {
        assert!(
            ephemeral_tree
                .contains("ns", root, Sha256Hasher::hash(leaf), leaf)
                .unwrap(),
            "leaf {:?} should be readable through ephemeral",
            leaf
        );
    }
}

#[test]
fn ephemeral_root_diverges_from_source_root_after_insert() {
    let source_tree = simple_tree();
    let root = source_tree
        .insert("ns", Hash::default(), b"shared")
        .unwrap();

    let ephemeral_tree = source_tree.to_ephemeral();
    let ephemeral_root = ephemeral_tree.insert("ns", root, b"extra").unwrap();

    assert_ne!(root, ephemeral_root);
}

#[test]
fn multiple_ephemeral_forks_from_same_source_are_independent() {
    let source_tree = simple_tree();
    let base_root = source_tree
        .insert("ns", Hash::default(), b"common")
        .unwrap();

    let tree_a = source_tree.to_ephemeral();
    let root_a = tree_a.insert("ns", base_root, b"only_in_a").unwrap();

    let tree_b = source_tree.to_ephemeral();
    let root_b = tree_b.insert("ns", base_root, b"only_in_b").unwrap();

    // Each fork has its own leaf but not the other's.
    assert!(
        tree_a
            .contains("ns", root_a, Sha256Hasher::hash(b"only_in_a"), b"only_in_a")
            .unwrap()
    );
    assert!(
        !tree_a
            .contains("ns", root_a, Sha256Hasher::hash(b"only_in_b"), b"only_in_b")
            .unwrap()
    );
    assert!(
        tree_b
            .contains("ns", root_b, Sha256Hasher::hash(b"only_in_b"), b"only_in_b")
            .unwrap()
    );
    assert!(
        !tree_b
            .contains("ns", root_b, Sha256Hasher::hash(b"only_in_a"), b"only_in_a")
            .unwrap()
    );

    // Source tree still has only the common leaf.
    assert!(
        source_tree
            .contains("ns", base_root, Sha256Hasher::hash(b"common"), b"common")
            .unwrap()
    );
    assert!(
        !source_tree
            .contains(
                "ns",
                base_root,
                Sha256Hasher::hash(b"only_in_a"),
                b"only_in_a"
            )
            .unwrap()
    );
}

#[test]
fn ephemeral_tree_on_empty_source_contains_nothing() {
    let source_tree = simple_tree();
    let eph_tree = source_tree.to_ephemeral();

    assert!(
        !eph_tree
            .contains(
                "ns",
                Hash::default(),
                Sha256Hasher::hash(b"ghost"),
                b"ghost"
            )
            .unwrap()
    );
}

#[test]
fn ephemeral_tree_namespace_isolation() {
    let source_tree = simple_tree();
    let root_ns1 = source_tree.insert("ns1", Hash::default(), b"leaf").unwrap();

    let eph_tree = source_tree.to_ephemeral();
    // Insert two distinct leaves into "ns2" to force internal nodes (a
    // single-leaf root equals the leaf hash and appears in every namespace).
    let r = eph_tree.insert("ns2", Hash::default(), b"leaf_a").unwrap();
    let root_ns2 = eph_tree.insert("ns2", r, b"leaf_b").unwrap();

    // Ephemeral tree reads the source's "ns1" leaf.
    assert!(
        eph_tree
            .contains("ns1", root_ns1, Sha256Hasher::hash(b"leaf"), b"leaf")
            .unwrap()
    );
    // Ephemeral tree's "ns2" leaves are both visible.
    assert!(
        eph_tree
            .contains("ns2", root_ns2, Sha256Hasher::hash(b"leaf_a"), b"leaf_a")
            .unwrap()
    );
    assert!(
        eph_tree
            .contains("ns2", root_ns2, Sha256Hasher::hash(b"leaf_b"), b"leaf_b")
            .unwrap()
    );
    // Source tree has no internal "ns2" nodes, so "leaf_a" is not reachable at root_ns2.
    assert!(
        !source_tree
            .contains("ns2", root_ns2, Sha256Hasher::hash(b"leaf_a"), b"leaf_a")
            .unwrap()
    );
}

#[test]
fn ephemeral_indexed_overwrite_keeps_latest_and_leaves_source_intact() {
    let source_tree = simple_tree();
    let source_root = source_tree.insert("ns", Hash::default(), b"base").unwrap();

    let eph_tree = source_tree.to_ephemeral();
    let r1 = eph_tree
        .insert_indexed("ns", source_root, &[0u8], b"v1")
        .unwrap();
    let r2 = eph_tree.insert_indexed("ns", r1, &[0u8], b"v2").unwrap();

    // Only the last value is stored at index 0 in the ephemeral tree.
    assert_eq!(
        eph_tree.get_indexed("ns", r2, &[0u8]).unwrap(),
        Some(Sha256Hasher::hash(b"v2"))
    );
    assert_ne!(
        eph_tree.get_indexed("ns", r2, &[0u8]).unwrap(),
        Some(Sha256Hasher::hash(b"v1"))
    );

    // Source tree is unchanged: it has "base" and not the indexed values.
    assert!(
        source_tree
            .contains("ns", source_root, Sha256Hasher::hash(b"base"), b"base")
            .unwrap()
    );
    assert!(
        !source_tree
            .contains("ns", source_root, Sha256Hasher::hash(b"v2"), b"v2")
            .unwrap()
    );
    assert!(
        !source_tree
            .contains("ns", source_root, Sha256Hasher::hash(b"v1"), b"v1")
            .unwrap()
    );
}
