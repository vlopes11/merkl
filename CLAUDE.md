# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Build
cargo build

# Test all
cargo test

# Test a single test by name
cargo test <test_name>

# Test with output visible
cargo test -- --nocapture

# Lint
cargo clippy

# Check without building
cargo check
```

All commands should be run from the workspace root (`merkl/`).

## Architecture

This is a `no_std` + `alloc` Rust workspace. The single crate `merkl-core` implements a **sparse Merkle tree** decoupled from its storage backend.

### Key design decisions

**Root is caller-owned.** `MerkleTree` holds no root hash. Every operation (`insert`, `get`) takes a `root: Hash` parameter and returns a new root. `Hash::default()` (`[0u8; 32]`) is the canonical empty root. This lets callers work with sub-trees by passing any intermediate node hash as a root.

**Content-addressed, parent-keyed storage.** The backend maps `parent_hash → Node { left, right }`. Leaf nodes are terminal — they have *no* backend entry. An all-zero hash marks an empty slot. Traversal always starts at the root and descends.

**Key-bit addressing.** Each leaf's position is determined by the bits of `H::hash(leaf_data)`, read MSB-first (bit 0 = MSB of byte 0, bit 255 = LSB of byte 31). Bit 0 selects left (0) or right (1) at the root, bit 1 at the next level, etc. This makes `insert` and `get` follow the same deterministic path for the same data.

**`KvsBackend` is immutable-interface.** All methods take `&self`; implementations use interior mutability (`RefCell`, `Mutex`, etc.). The tree never holds `&mut backend`. `set` returns `Option<OldValue>` (displaced value, like `BTreeMap::insert`).

**`push_down` handles leaf–leaf collisions.** When `insert` reaches an existing leaf at the target path, `push_down` recursively descends until the two keys' bits diverge, then places each leaf on its correct side. Empty slots (`Hash::default()`) fill the non-matching branches. Errors only on a true 256-bit hash collision.

### Module responsibilities

| Module | Purpose |
|--------|---------|
| `backend` | `KvsBackend` trait — generic `Key`/`Value`, `&self` get/set |
| `hash` | `Hash = [u8; 32]`, `Hasher` trait with default `hash_pair` (left \|\| right) |
| `node` | `Node { left: Hash, right: Hash }` — the value type stored in the backend |
| `memory` | `MemoryBackend<K, V>` — `RefCell<BTreeMap>`, single-threaded, `Error = Infallible` |
| `tree` | `MerkleTree<B, H>` — `insert`, `get`, `insert_at`, `push_down` |
| `proof` | `MerkleProof`, `ProofSibling`, `ProofSide`, `verify` — siblings bottom-up |

### Dependencies

- `anyhow` (`default-features = false`) — all fallible operations return `anyhow::Result`. No custom error types.
- `sha2` — dev-dependency only, used in tests as the concrete `Hasher` impl.
- Everything else comes from `core` and `alloc`.

### Implementing a custom backend

Implement `KvsBackend` with `Key = Hash` and `Value = Node`, using interior mutability for the write path. The `Error` type is gone — all errors surface as `anyhow::Error` directly from the trait methods.
