//! Demonstrations of the `merkl` public API.
//!
//! Each test illustrates a distinct usage pattern or API contract.
//! Read these as executable examples before writing integration code.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::{Hash, Hasher, KvsBackend, MemoryBackend, MerkleTree, Node, ProofSibling, ProofSide};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Shared hasher and helpers
// ---------------------------------------------------------------------------

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
struct SharedBackend(Rc<RefCell<BTreeMap<Vec<u8>, Vec<u8>>>>);

impl SharedBackend {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(BTreeMap::new())))
    }

    /// Walk the backend from `root` following the key-bit path of `leaf_hash`
    /// and return siblings ordered bottom-up, ready for `MerkleTree::verify`.
    fn collect_proof(&self, root: Hash, leaf_hash: Hash) -> Vec<ProofSibling> {
        let store = self.0.borrow();
        let mut current = root;
        let mut level = 0usize;
        let mut siblings = Vec::new();
        loop {
            match store.get(&current[..]) {
                None => break,
                Some(bytes) => {
                    let node = Node::from_bytes(bytes).expect("corrupt node");
                    let bit = (leaf_hash[level / 8] >> (7 - (level % 8))) & 1;
                    if bit == 0 {
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
}

impl KvsBackend for SharedBackend {
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow().get(key).cloned())
    }

    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.0.borrow_mut().insert(key.to_vec(), value.to_vec()))
    }
}

// ---------------------------------------------------------------------------
// CountingBackend — demonstrates intercepting every read and write
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct CountingBackend {
    store: Rc<RefCell<BTreeMap<Vec<u8>, Vec<u8>>>>,
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
    fn get(&self, key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        *self.reads.borrow_mut() += 1;
        Ok(self.store.borrow().get(key).cloned())
    }

    fn set(&self, key: &[u8], value: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        *self.writes.borrow_mut() += 1;
        Ok(self.store.borrow_mut().insert(key.to_vec(), value.to_vec()))
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
    let root = tree.insert(Hash::default(), b"hello").unwrap();
    assert_eq!(root, Sha256Hasher::hash(b"hello"));
}

#[test]
fn all_inserted_leaves_are_retrievable() {
    let tree = simple_tree();
    let leaves: &[&[u8]] = &[b"alice", b"bob", b"carol", b"dave"];
    let root = leaves
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    for leaf in leaves {
        assert_eq!(
            tree.get(root, leaf).unwrap(),
            Some(Sha256Hasher::hash(leaf))
        );
    }
}

#[test]
fn get_returns_the_terminal_hash_at_the_key_position() {
    let tree = simple_tree();
    let root = tree.insert(Hash::default(), b"alpha").unwrap();

    assert_eq!(
        tree.get(root, b"alpha").unwrap(),
        Some(Sha256Hasher::hash(b"alpha")),
    );

    // In a one-leaf tree every key path leads to the same sole leaf.
    let terminal = tree.get(root, b"beta").unwrap();
    assert!(terminal.is_some());
    assert_ne!(terminal.unwrap(), Sha256Hasher::hash(b"beta"));
}

#[test]
fn contains_distinguishes_members_from_non_members() {
    let tree = simple_tree();
    let root = [b"alice" as &[u8], b"bob"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    assert!(tree.contains(root, b"alice").unwrap());
    assert!(tree.contains(root, b"bob").unwrap());
    // "carol" is absent — get() would still return Some(...) pointing at
    // whichever leaf terminates along carol's path, but contains() is false.
    assert!(!tree.contains(root, b"carol").unwrap());
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
            .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap())
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
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    assert_eq!(tree.insert(root, b"x").unwrap(), root);
    assert_eq!(tree.insert(root, b"y").unwrap(), root);
}

// ---------------------------------------------------------------------------
// Sub-trees and historical roots
// ---------------------------------------------------------------------------

#[test]
fn same_backend_holds_multiple_independent_subtrees() {
    let tree = simple_tree();

    let root_a = tree.insert(Hash::default(), b"only in A").unwrap();
    let root_b = tree.insert(Hash::default(), b"only in B").unwrap();

    assert!(tree.verify(root_a, &[], b"only in A"));
    assert!(!tree.verify(root_a, &[], b"only in B"));

    assert!(tree.verify(root_b, &[], b"only in B"));
    assert!(!tree.verify(root_b, &[], b"only in A"));
}

#[test]
fn every_past_root_is_a_stable_snapshot() {
    let tree = simple_tree();
    let root_v1 = tree.insert(Hash::default(), b"first").unwrap();
    let root_v2 = tree.insert(root_v1, b"second").unwrap();

    assert_ne!(root_v1, root_v2);

    assert!(tree.verify(root_v1, &[], b"first"));
    assert!(!tree.verify(root_v1, &[], b"second"));

    assert_eq!(
        tree.get(root_v2, b"first").unwrap(),
        Some(Sha256Hasher::hash(b"first")),
    );
    assert_eq!(
        tree.get(root_v2, b"second").unwrap(),
        Some(Sha256Hasher::hash(b"second")),
    );
}

// ---------------------------------------------------------------------------
// Inclusion proofs
// ---------------------------------------------------------------------------

#[test]
fn verify_single_leaf_requires_no_siblings() {
    let tree = simple_tree();
    let root = tree.insert(Hash::default(), b"sole leaf").unwrap();

    assert!(tree.verify(root, &[], b"sole leaf"));
    assert!(!tree.verify(root, &[], b"wrong leaf"));
}

#[test]
fn verify_accepts_valid_proof_for_every_leaf() {
    let (tree, backend) = shared_tree();
    let leaves: &[&[u8]] = &[b"alpha", b"beta", b"gamma", b"delta"];
    let root = leaves
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    for leaf in leaves {
        let proof = backend.collect_proof(root, Sha256Hasher::hash(leaf));
        assert!(tree.verify(root, &proof, leaf));
    }
}

#[test]
fn verify_rejects_wrong_leaf_data() {
    let (tree, backend) = shared_tree();
    let root = [b"foo" as &[u8], b"bar"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    let proof_for_foo = backend.collect_proof(root, Sha256Hasher::hash(b"foo"));
    assert!(!tree.verify(root, &proof_for_foo, b"bar"));
}

#[test]
fn verify_rejects_tampered_sibling() {
    let (tree, backend) = shared_tree();
    let root = [b"left" as &[u8], b"right"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    let mut proof = backend.collect_proof(root, Sha256Hasher::hash(b"left"));
    if let Some(s) = proof.first_mut() {
        s.hash[0] ^= 0xff;
    }
    assert!(!tree.verify(root, &proof, b"left"));
}

#[test]
fn verify_rejects_stale_root() {
    let (tree, backend) = shared_tree();
    let root = [b"p" as &[u8], b"q"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    let proof = backend.collect_proof(root, Sha256Hasher::hash(b"p"));
    let stale = Sha256Hasher::hash(b"not the real root");
    assert!(!tree.verify(stale, &proof, b"p"));
}

// ---------------------------------------------------------------------------
// Custom backends
// ---------------------------------------------------------------------------

#[test]
fn custom_backend_intercepts_all_reads_and_writes() {
    let backend = CountingBackend::new();
    let tree = MerkleTree::<_, Sha256Hasher>::new(backend.clone());

    let root = tree.insert(Hash::default(), b"first").unwrap();
    assert_eq!(backend.reads(), 0);
    assert_eq!(backend.writes(), 0);

    tree.insert(root, b"second").unwrap();
    assert_eq!(backend.reads(), 1);
    assert_eq!(backend.writes(), 1);
}

#[test]
fn custom_backend_with_shared_storage_enables_external_inspection() {
    let (tree, backend) = shared_tree();
    let root = [b"x" as &[u8], b"y", b"z"]
        .iter()
        .fold(Hash::default(), |r, l| tree.insert(r, l).unwrap());

    let node_count = backend.0.borrow().len();
    assert!(node_count > 0, "internal nodes must have been stored");

    let proof = backend.collect_proof(root, Sha256Hasher::hash(b"x"));
    assert!(tree.verify(root, &proof, b"x"));
}
