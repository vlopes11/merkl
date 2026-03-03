# merkl-redb

[![crates.io](https://img.shields.io/crates/v/merkl-redb?label=latest)](https://crates.io/crates/merkl-redb)
[![Documentation](https://docs.rs/merkl-redb/badge.svg)](https://docs.rs/merkl-redb/)
[![License](https://img.shields.io/crates/l/merkl-redb.svg)]()

A persistent [`redb`](https://crates.io/crates/redb)-backed storage backend for the
[`merkl`](https://crates.io/crates/merkl) sparse Merkle tree.

All tree logic lives in `merkl`. This crate provides exactly one thing: `RedbBackend`, a
`KvsBackend` implementation that stores Merkle nodes in an embedded redb database — either
on disk or fully in-memory.

## Add to your project

```toml
[dependencies]
merkl-redb = "0.1"
```

With the SHA-256 convenience alias:

```toml
[dependencies]
merkl-redb = { version = "0.1", features = ["sha2"] }
```

## Quick start

### In-memory (ephemeral)

```rust
use merkl::Hash;
use merkl_redb::{RedbBackend, Sha256RedbMerkleTree};

let tree = Sha256RedbMerkleTree::new(RedbBackend::in_memory()?);

let root0 = Hash::default(); // empty tree
let root1 = tree.insert(root0, b"alice")?;
let root2 = tree.insert(root1, b"bob")?;

assert!(tree.contains(root2, b"alice")?);
assert!(tree.contains(root2, b"bob")?);

// Old roots remain valid — the tree is persistent.
assert!(!tree.contains(root1, b"bob")?);
# Ok::<(), anyhow::Error>(())
```

### File-backed (persistent across restarts)

```rust
use merkl::Hash;
use merkl_redb::{RedbBackend, Sha256RedbMerkleTree};

let backend = RedbBackend::create("my_tree.redb")?;
let tree = Sha256RedbMerkleTree::new(backend);

let root = tree.insert(Hash::default(), b"hello")?;
// Persist `root` yourself (e.g. in the same redb database, a config file, etc.).
// On the next run, pass the saved root back to `insert` / `get` / `verify`.
# Ok::<(), anyhow::Error>(())
```

### Bring your own `Database`

If you already manage a `redb::Database`, hand it to `RedbBackend::new`. The constructor
creates the `"merkl_tree"` table if it does not exist yet and wraps the database in a
cheap reference-counted handle.

```rust
use redb::Database;
use merkl_redb::RedbBackend;

let db = Database::create("app.redb")?;
let backend = RedbBackend::new(db)?;
# Ok::<(), anyhow::Error>(())
```

### Custom hasher

Use `RedbMerkleTree<H>` when you want a hash function other than SHA-256:

```rust
use merkl::{Hash, Hasher, MerkleTree};
use merkl_redb::{RedbBackend, RedbMerkleTree};

struct Blake3Hasher;

impl Hasher for Blake3Hasher {
    fn hash(data: &[u8]) -> Hash {
        *blake3::hash(data).as_bytes()
    }
}

let tree: RedbMerkleTree<Blake3Hasher> =
    RedbMerkleTree::new(RedbBackend::in_memory()?);

let root = tree.insert(Hash::default(), b"leaf")?;
# Ok::<(), anyhow::Error>(())
```

## Cloning

Cloning a `RedbBackend` is cheap. All clones share the same underlying `Database`
through a reference-counted pointer:

- Without `multi-thread`: `Rc<Database>` — single-threaded only.
- With `multi-thread`: `Arc<Database>` — `RedbBackend` becomes `Send + Sync`.

```rust
let b1 = RedbBackend::in_memory()?;
let b2 = b1.clone(); // same database, no copy
# Ok::<(), anyhow::Error>(())
```

## Transaction model

Every `KvsBackend::set` call opens, writes, and commits its **own** write transaction.
This is safe and correct for interactive or low-frequency inserts.

For bulk tree construction — inserting many leaves in a tight loop — the per-call
transaction overhead adds up. In that case, implement your own `KvsBackend` wrapper
that batches writes inside a single `redb::WriteTransaction` and commit it once at the
end.

## Feature flags

| Feature        | Default | Description |
|----------------|:-------:|-------------|
| `sha2`         | no      | Enables `Sha256Hasher` and the `Sha256RedbMerkleTree` type alias. |
| `multi-thread` | no      | Wraps the `Database` in `Arc` instead of `Rc`, making `RedbBackend: Send + Sync`. |

The two features are independent and may be combined.

## Relationship to `merkl`

```
merkl-redb
├── RedbBackend          implements KvsBackend (from merkl)
├── RedbMerkleTree<H>    = MerkleTree<RedbBackend, H>  (from merkl)
└── Sha256RedbMerkleTree = RedbMerkleTree<Sha256Hasher> (sha2 feature)
```

All tree operations (`insert`, `get`, `contains`, `verify`, …) are provided by `merkl`.
See the [`merkl` documentation](https://docs.rs/merkl/) for the full API.

## License

MIT — see [LICENSE](LICENSE).
