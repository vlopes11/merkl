# merkl

[![crates.io](https://img.shields.io/crates/v/merkl?label=latest)](https://crates.io/crates/merkl)
[![Documentation](https://docs.rs/merkl/badge.svg)](https://docs.rs/merkl/)
[![License](https://img.shields.io/crates/l/merkl.svg)]()

A `no_std` + `alloc` sparse Merkle tree with a pluggable, namespaced key-value storage backend.

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

Three ways to insert a leaf:

| Method | Key derivation | Use when |
|--------|---------------|----------|
| `insert(ns, root, data)` | `H::hash(data)` | Natural content-addressing |
| `insert_indexed(ns, root, i, data)` | `H::hash(i.to_le_bytes())` | Array-like stable positions |
| `insert_keyed(ns, root, key, data)` | caller-supplied key | Complete control |

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std`   | yes     | Enables `std`-backed errors and the `sha2` crate's `std` feature. Disable for `no_std` targets. |
| `sha2`  | no      | Enables `Sha256Hasher` and the `Sha256MerkleTree<B>` alias. |
| `redb`  | no      | Enables `RedbBackend` and `RedbMerkleTree<H>` backed by [redb](https://crates.io/crates/redb) (requires `std`). |
| `fjall` | no      | Enables `FjallBackend` backed by [fjall](https://crates.io/crates/fjall) (requires `std`). |

## Quick start

### Custom hasher, in-memory backend

```rust,ignore
use merkl::{Hash, Hasher, MemoryBackend, MerkleTree};

struct Blake3Hasher;
impl Hasher for Blake3Hasher {
    fn hash(data: &[u8]) -> Hash { blake3::hash(data).into() }
}

let tree = MerkleTree::<MemoryBackend, Blake3Hasher>::new(MemoryBackend::new());

// Insert leaves — each call returns a new root without mutating the old one.
let root1 = tree.insert("ns", Hash::default(), b"alice").unwrap();
let root2 = tree.insert("ns", root1, b"bob").unwrap();

// Retrieve the stored leaf hash (key = H::hash(data) for plain insert).
let key_alice = Blake3Hasher::hash(b"alice");
assert_eq!(tree.get("ns", root2, key_alice).unwrap(), Some(key_alice));

// root1 is still valid and does not contain "bob".
let key_bob = Blake3Hasher::hash(b"bob");
assert_eq!(tree.get("ns", root1, key_bob).unwrap(), None);

// Insertion order does not affect the root.
let tree2 = MerkleTree::<MemoryBackend, Blake3Hasher>::new(MemoryBackend::new());
let r = tree2.insert("ns", Hash::default(), b"bob").unwrap();
let root_ba = tree2.insert("ns", r, b"alice").unwrap();
assert_eq!(root2, root_ba);
```

### SHA-256 hasher (`sha2` feature)

```toml
[dependencies]
merkl = { version = "0.2", features = ["sha2"] }
```

```rust,ignore
use merkl::{Hash, MemoryBackend, Sha256MerkleTree};

let tree = Sha256MerkleTree::<MemoryBackend>::new(MemoryBackend::new());
let root = [b"alpha" as &[u8], b"beta", b"gamma"]
    .iter()
    .fold(Hash::default(), |r, leaf| tree.insert("ns", r, leaf).unwrap());
```

### Index-keyed inserts

Useful for append-like structures where each element has a stable numeric position:

```rust,ignore
let root = tree.insert_indexed("ns", Hash::default(), 0, b"first").unwrap();
let root = tree.insert_indexed("ns", root, 1, b"second").unwrap();
```

The key for index `i` is `H::hash(i.to_le_bytes())`, giving each index a
stable, uniformly-distributed position in the tree.

## redb backend (`redb` feature)

```toml
[dependencies]
merkl = { version = "0.2", features = ["redb", "sha2"] }
```

```rust,ignore
use merkl::{Hash, Sha256Hasher, redb::{RedbBackend, RedbMerkleTree}};

// Ephemeral in-memory database — no files created.
let backend = RedbBackend::in_memory().unwrap();
let tree = RedbMerkleTree::<Sha256Hasher>::new(backend);
let root = tree.insert("ns", Hash::default(), b"hello").unwrap();
```

For a persistent file-backed database:

```rust,ignore
let backend = merkl::redb::RedbBackend::create("my_tree.redb").unwrap();
```

Cloning a `RedbBackend` is cheap — all clones share the same underlying `Database`
via `Arc` (or `Rc` on targets without atomics).

Each `set` call opens, writes, and commits its own write transaction. For bulk
tree construction, wrapping a single `redb::WriteTransaction` in a custom backend
will give better throughput.

## fjall backend (`fjall` feature)

```toml
[dependencies]
merkl = { version = "0.2", features = ["fjall"] }
```

```rust,ignore
use merkl::fjall::FjallBackend;

let db = fjall::Config::new("my_tree").open().unwrap();
let backend = FjallBackend::from(db);
```

## Membership proofs

`get_opening` collects sibling hashes bottom-up. Verification is a pure hash
computation — it never touches the backend:

```rust,ignore
let proof = tree.get_opening("ns", root, b"alice").unwrap();
assert_eq!(proof.leaf_root(b"alice"), root); // membership verified

// For indexed inserts:
let proof = tree.get_indexed_opening("ns", root, 0, b"first").unwrap();
assert_eq!(proof.leaf_indexed_root(0, b"first"), root);
```

### Non-membership proofs

A sparse Merkle tree can also prove that a position is empty:

```rust,ignore
// "carol" was never inserted; the path leads to an empty slot.
let proof = tree.get_opening("ns", root, b"carol").unwrap();
assert_eq!(proof.non_membership_leaf_root(b"carol"), root); // non-membership verified
```

Traversal directions are derived from the key at verification time — never stored
in the proof — so the proof cannot be forged by manipulating direction bits.

## Implementing `KvsBackend`

The `KvsBackend` trait is the only integration point:

```rust
use merkl::KvsBackend;
use anyhow::Result;

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

```rust,ignore
use core::cell::RefCell;
use merkl::KvsBackend;

/// Fixed-capacity store backed by a statically allocated array.
/// Each slot: 4 bytes ns_len + ns bytes + 32-byte key + 64-byte value.
/// For simplicity this example uses a flat linear scan.
pub struct StaticBackend {
    store: RefCell<heapless::LinearMap<([u8; 32], u8), [u8; 64], 512>>,
}

impl KvsBackend for StaticBackend {
    type Get = [u8; 64];

    fn get(&self, ns: &str, key: &[u8]) -> anyhow::Result<Option<[u8; 64]>> {
        // implementation omitted
        todo!()
    }

    fn set(&self, ns: &str, key: &[u8], value: &[u8]) -> anyhow::Result<()> {
        // implementation omitted
        todo!()
    }
}
```

## `no_std` usage

Disable the default `std` feature and ensure a global allocator is provided:

```toml
[dependencies]
merkl = { version = "0.2", default-features = false }
```

The `redb` and `fjall` backend features always require `std`.

## License

MIT — see [LICENSE](LICENSE).
