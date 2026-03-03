# merkl

[![crates.io](https://img.shields.io/crates/v/merkl?label=latest)](https://crates.io/crates/merkl)
[![Documentation](https://docs.rs/merkl/badge.svg)](https://docs.rs/merkl/)
[![License](https://img.shields.io/crates/l/merkl.svg)]()

A `no_std` + `alloc` sparse Merkle tree with a pluggable key-value storage backend.

## How it works

Each leaf is addressed by the hash of its data. The hash bits (MSB-first) determine
the path from the root: bit 0 selects left (0) or right (1) at depth 0, bit 1 at
depth 1, and so on. Internal nodes are stored in the backend, keyed by their own hash
and holding the 64-byte serialised `Node` (left ‖ right child hashes).

**The root lives outside the tree.** `MerkleTree` holds no state beyond its backend
and hash-function marker. Every operation receives a root `Hash` and returns a new
root — making historical roots and independent sub-trees free.

```
root ──► Node{ left, right }
              │          │
          Node{…}    leaf_hash   ← terminal: no backend entry
              │
          leaf_hash   ← terminal
```

An all-zero `Hash` (`Hash::default()`) is the canonical empty root.

## Quick start

### In-memory tree with a custom hasher

```rust
use merkl::{Hash, Hasher, MemoryBackend, MerkleTree};

struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash(data: &[u8]) -> Hash {
        blake3::hash(data).into()
    }
}

let tree = MerkleTree::<MemoryBackend, Blake3Hasher>::new(MemoryBackend::new());

// An empty tree starts from the zero root.
let root0 = Hash::default();

// Insert leaves; each call returns a new root without mutating the old one.
let root1 = tree.insert(root0, b"alice").unwrap();
let root2 = tree.insert(root1, b"bob").unwrap();

// Retrieve the stored leaf hash.
assert_eq!(
    tree.get(root2, b"alice").unwrap(),
    Some(Blake3Hasher::hash(b"alice")),
);

// root1 is still valid and does not contain "bob".
assert_eq!(tree.get(root1, b"bob").unwrap(), None);

// Insertion is order-independent.
let root_ba = {
    let t = MerkleTree::<MemoryBackend, Blake3Hasher>::new(MemoryBackend::new());
    let r = t.insert(Hash::default(), b"bob").unwrap();
    t.insert(r, b"alice").unwrap()
};
assert_eq!(root2, root_ba);
```

### With the built-in SHA-256 hasher (`sha2` feature)

```rust
use merkl::{Hash, MemoryBackend, Sha256MerkleTree};

let tree = Sha256MerkleTree::<MemoryBackend>::new(MemoryBackend::new());

let root = [b"alpha" as &[u8], b"beta", b"gamma"]
    .iter()
    .fold(Hash::default(), |r, leaf| tree.insert(r, leaf).unwrap());
```

### Inclusion proofs

`verify` is a pure hash computation — it does not access the backend:

```rust
use merkl::{Hash, ProofSide, ProofSibling};

// Build siblings bottom-up (leaf-level first, root-level last):
let siblings: Vec<ProofSibling> = collect_proof(&backend, root, leaf_hash);

assert!(tree.verify(root, &siblings, b"alice"));
```

`ProofSibling` carries the sibling's hash and its `ProofSide` (Left / Right).

## merkl-redb

`merkl-redb` provides `RedbBackend`, a [`redb`](https://crates.io/crates/redb)-backed
`KvsBackend`.

```toml
[dependencies]
merkl-redb = { path = "redb", features = ["sha2"] }
```

```rust
use merkl::Hash;
use merkl_redb::{RedbBackend, Sha256RedbMerkleTree};

// Ephemeral in-memory database — no files created.
let tree = Sha256RedbMerkleTree::new(RedbBackend::in_memory().unwrap());

let root = tree.insert(Hash::default(), b"hello").unwrap();
assert_eq!(tree.get(root, b"hello").unwrap(), Some(merkl::Sha256Hasher::hash(b"hello")));
```

For a persistent file-backed database (requires the `std` feature, which is on by default):

```rust
let backend = merkl_redb::RedbBackend::create("my_tree.redb").unwrap();
```

Cloning a `RedbBackend` is cheap — all clones share the same underlying `Database`
via `Rc` (or `Arc` with the `multi-thread` feature).

## Feature flags

### `merkl`

| Feature | Default | Description |
|---------|---------|-------------|
| `sha2`  | no      | Enables `Sha256Hasher` and the `Sha256MerkleTree<B>` alias. |

### `merkl-redb`

`merkl-redb` always requires std (redb 3.x does not support `no_std`).

| Feature        | Default | Description |
|----------------|---------|-------------|
| `sha2`         | no      | Re-exports `Sha256Hasher` and the `Sha256RedbMerkleTree` alias. |
| `multi-thread` | no      | Wraps the database in `Arc` instead of `Rc`, making `RedbBackend` `Send + Sync`. |

## Implementing KvsBackend for bare-metal targets

`merkl` is `no_std + alloc`, so a global allocator is required.
The backend trait is intentionally simple: `get` and `set` operate on raw byte slices,
and `set` returns the previous value (if any) as an owned `Vec<u8>`.

All keys are 32-byte parent hashes; all values are 64-byte serialised `Node`s.
The tree never calls the backend with the zero key, so you may safely use an
all-zero slot as the "empty" sentinel.

```rust
use core::cell::RefCell;
use alloc::vec::Vec;
use anyhow::Result;
use merkl::KvsBackend;

/// Fixed-capacity store backed by a statically allocated array.
/// Each slot holds a 32-byte key followed by a 64-byte value (96 bytes total).
/// An all-zero key marks an unused slot.
pub struct StaticBackend {
    slots: RefCell<[[u8; 96]; 512]>,
}

impl StaticBackend {
    pub const fn new() -> Self {
        Self { slots: RefCell::new([[0u8; 96]; 512]) }
    }
}

impl KvsBackend for StaticBackend {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let slots = self.slots.borrow();
        for slot in slots.iter() {
            if slot[..32] == *key {
                return Ok(Some(slot[32..].to_vec()));
            }
        }
        Ok(None)
    }

    fn set(&self, key: &[u8], value: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut slots = self.slots.borrow_mut();
        // Update existing entry.
        for slot in slots.iter_mut() {
            if slot[..32] == *key {
                let old = Some(slot[32..].to_vec());
                slot[32..].copy_from_slice(value);
                return Ok(old);
            }
        }
        // Insert into the first empty slot.
        for slot in slots.iter_mut() {
            if slot[..32] == [0u8; 32] {
                slot[..32].copy_from_slice(key);
                slot[32..].copy_from_slice(value);
                return Ok(None);
            }
        }
        anyhow::bail!("storage full")
    }
}
```

For interrupt-driven or multi-core embedded targets, replace `RefCell` with a
`critical_section::Mutex` or a hardware-specific primitive that provides the same
interior-mutability guarantee.

To back the store with external flash, replace the `RefCell<[[u8; 96]; N]>` body
with reads and writes to your flash driver, taking care to erase pages before
writing and to handle wear-levelling as needed by your device.

## License

MIT — see [LICENSE](LICENSE).
