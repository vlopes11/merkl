# merkl

[![crates.io](https://img.shields.io/crates/v/merkl?label=latest)](https://crates.io/crates/merkl)
[![Documentation](https://docs.rs/merkl/badge.svg)](https://docs.rs/merkl/)
[![License](https://img.shields.io/crates/l/merkl.svg)]()

A `no_std` + `alloc` sparse Merkle tree with a pluggable, namespaced key-value storage backend.

The initial version of this crate was vibe coded. Check it out on [YouTube](https://youtu.be/wRpRFM6dpuc?si=bmU2JDMc0Q27tZZ0).

## How it works

Each leaf is addressed by a **key** (a 32-byte hash). The key's bits, read MSB-first,
determine the path from root to leaf: bit 0 selects left (0) or right (1) at the root,
bit 1 at the next level, and so on. Internal nodes are stored in the backend keyed by
their own hash, holding a 64-byte serialised `Node` (left ‖ right child hashes).

**The root lives outside the tree.** `MerkleTree` holds no state beyond its backend and
hash-function marker. Every operation receives a root `Hash` and returns a new root —
making historical roots and independent sub-trees free.

```ascii
root ──► Node{ left, right }
              │          │
          Node{…}    leaf_hash   ← terminal: no backend entry
              │
          leaf_hash   ← terminal
```

An all-zero `Hash` (`Hash::default()`) is the canonical empty root.

Four ways to insert a leaf:

| Method | Key derivation | Use when |
|--------|---------------|----------|
| `insert(ns, root, data)` | `H::hash(data)` | Natural content-addressing |
| `insert_leaf(ns, root, leaf_hash)` | `leaf_hash` (key = value) | Pre-hashed leaf |
| `insert_indexed(ns, root, index, data)` | `index` bytes zero-padded to 32 bytes | Array-like stable positions |
| `insert_indexed_leaf(ns, root, index, leaf_hash)` | `index` bytes zero-padded to 32 bytes | Pre-hashed leaf at index |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | yes     | Enables `std`-backed errors and the `sha2` crate's `std` feature. Disable for `no_std` targets. |
| `sha2`  | no      | Enables `Sha256Hasher` and the `Sha256MerkleTree<B>` alias. |
| `serde` | no      | Derives `Serialize`/`Deserialize` for `Node` and `MerkleOpening`. |
| `redb`  | no      | Enables `RedbBackend` and `RedbMerkleTree<H>` backed by [redb](https://crates.io/crates/redb) (requires `std`). |
| `fjall` | no      | Enables `FjallBackend` backed by [fjall](https://crates.io/crates/fjall) (requires `std`). |

## Quick start

### SHA-256 hasher (`sha2` feature)

```toml
[dependencies]
merkl = { version = "1.0", features = ["sha2"] }
```

```rust
#[cfg(feature = "sha2")] {
use merkl::{Hash, MemoryBackend, Sha256MerkleTree};

let tree = Sha256MerkleTree::<MemoryBackend>::new(MemoryBackend::new());
let root = [b"alpha" as &[u8], b"beta", b"gamma"]
    .iter()
    .fold(Hash::default(), |r, leaf| tree.insert("ns", r, leaf).unwrap());
}
```

### Index-keyed inserts

Useful for append-like structures where each element has a stable numeric position.
The `index` parameter is raw bytes (up to 32) zero-padded into a 32-byte key:

```rust
use merkl::{Hash, tree::MerkleTreeDummy};
let tree = MerkleTreeDummy::default();
// Use little-endian encoded integers as the index bytes.
let root = tree.insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"first").unwrap();
let root = tree.insert_indexed("ns", root, &1u64.to_le_bytes(), b"second").unwrap();
```

The key for `index` is the raw bytes copied into a 32-byte zero-padded buffer, giving
each index a fixed, deterministic position in the tree.

## Ephemeral forks

`to_ephemeral()` creates a short-lived view of a tree that reads from the
original backend but writes only into a temporary in-memory overlay. The
original backend is never mutated:

```rust
use merkl::{Hash, tree::MerkleTreeDummy};

let tree = MerkleTreeDummy::default();
let root = tree.insert("ns", Hash::default(), b"committed").unwrap();

// Fork: all inserts go to the ephemeral overlay only.
let ephemeral = tree.to_ephemeral();
let _fork_root = ephemeral.insert("ns", root, b"speculative").unwrap();
// The original backend is never modified by the ephemeral fork.
```

## redb backend (`redb` feature)

```toml
[dependencies]
merkl = { version = "1.0", features = ["redb", "sha2"] }
```

```rust,ignore
#[cfg(all(feature = "redb", feature = "sha2"))] {
use merkl::{Hash, Sha256Hasher, redb::{RedbBackend, RedbMerkleTree}};

// Ephemeral in-memory database — no files created.
let backend = RedbBackend::in_memory().unwrap();
let tree = RedbMerkleTree::<Sha256Hasher>::new(backend);
let root = tree.insert("ns", Hash::default(), b"hello").unwrap();
}
```

For a persistent file-backed database:

```rust,ignore
#[cfg(feature = "redb")] {
let backend = merkl::redb::RedbBackend::create("my_tree.redb").unwrap();
}
```

Cloning a `RedbBackend` is cheap — all clones share the same underlying `Database`
via `Arc` (or `Rc` on targets without atomics).

Each `set` call opens, writes, and commits its own write transaction. For bulk
tree construction, wrapping a single `redb::WriteTransaction` in a custom backend
will give better throughput.

## fjall backend (`fjall` feature)

```toml
[dependencies]
merkl = { version = "1.0", features = ["fjall"] }
```

```rust,ignore
#[cfg(feature = "fjall")] {
use merkl::fjall::FjallBackend;
let backend = FjallBackend::new("my_tree").unwrap();
}
```

## Membership proofs

`get_opening` / `get_opening_leaf` / `get_indexed_opening` collect sibling
hashes bottom-up. Verification is a pure hash computation — it never touches
the backend:

```rust
use merkl::{Hash, tree::MerkleTreeDummy};
let tree = MerkleTreeDummy::default();
let root = tree.insert("ns", Hash::default(), b"alice").unwrap();

// Verify membership by leaf data (convenience — hashes data internally).
let proof = tree.get_opening("ns", root, b"alice").unwrap();
assert_eq!(proof.leaf_root_data(b"alice"), root);

// Or supply the leaf hash directly.
assert_eq!(proof.leaf_root(<() as merkl::Hasher>::hash(b"alice")), root);
```

For indexed inserts, use `get_indexed_opening` and `get_indexed`:

```rust
use merkl::{Hash, tree::MerkleTreeDummy};
let tree = MerkleTreeDummy::default();
let root = tree.insert_indexed("ns", Hash::default(), &0u64.to_le_bytes(), b"first").unwrap();

// Retrieve the stored leaf hash by index.
let leaf = tree.get_indexed("ns", root, &0u64.to_le_bytes()).unwrap();

// Build and verify an indexed opening.
let proof = tree.get_indexed_opening("ns", root, &0u64.to_le_bytes()).unwrap();
assert_eq!(
    proof.leaf_indexed_root(&0u64.to_le_bytes(), <() as merkl::Hasher>::hash(b"first")).unwrap(),
    root
);
```

### Non-membership proofs

A sparse Merkle tree can also prove that a position is empty:

```rust
use merkl::{Hash, tree::MerkleTreeDummy};
let (tree, root) = (MerkleTreeDummy::default(), Hash::default());

// "carol" was never inserted; the path leads to an empty slot.
let proof = tree.get_opening("ns", root, b"carol").unwrap();
assert_eq!(proof.non_membership_leaf_root(b"carol"), root);

// Non-membership at an index position.
let proof = tree.get_indexed_opening("ns", root, &99u64.to_le_bytes()).unwrap();
assert_eq!(proof.non_membership_leaf_indexed_root(&99u64.to_le_bytes()).unwrap(), root);
```

Traversal directions are derived from the key at verification time — never
stored in the proof — so the proof cannot be forged by manipulating direction
bits.

### Path containment

`MerkleOpening::contains` checks whether one proof's path is a suffix of
another's — useful for verifying that a leaf proof lives inside a known
sub-tree proof:

```rust
use merkl::{Hash, MerkleOpening};
// A deeper proof contains a shallower proof when their root-aligned
// siblings match.
let deep: MerkleOpening<()> = MerkleOpening::new(vec![[1u8;32], [2u8;32]], [0u8;32]);
let shallow: MerkleOpening<()> = MerkleOpening::new(vec![[2u8;32]], [0u8;32]);
assert!(deep.contains(&shallow));
```

## Implementing `KvsBackend`

The `KvsBackend` trait is the only integration point:

```rust
use merkl::KvsBackend;
use anyhow::Result;

#[derive(Clone)]
struct MyBackend { /* … */ }

impl KvsBackend for MyBackend {
    // `Get` must deref to `[u8]`. Use `Vec<u8>` for the simplest case.
    type Get = Vec<u8>;

    fn get(&self, ns: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        // Look up `key` in namespace `ns`.
        todo!()
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> Result<()> {
        // Store `value` under `key` in namespace `ns`.
        todo!()
    }
}
```

Key facts:

- All methods take `&self` — use interior mutability (`RefCell`, `Mutex`, etc.) for the write path.
- `ns` is used by the tree to separate node storage (`ns`) from its internal key-mapping
  namespace (`"{ns}-key"`). Your backend only needs to use it as an extra scope for isolation.
- Tree node keys are 32-byte parent hashes; values are 64-byte `Node` encodings (`left ‖ right`).

For bare-metal targets, wrap your store in `RefCell` (single-core) or a
`critical_section::Mutex` (multi-core / interrupt-driven):

## License

MIT — see [LICENSE](./LICENSE).
