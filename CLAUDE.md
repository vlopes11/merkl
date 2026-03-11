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

This is a `no_std` + `alloc` Rust crate. The single crate `merkl` implements a **sparse Merkle tree** decoupled from its storage backend.

### Key design decisions

**Root is caller-owned.** `MerkleTree` holds no root hash. Every operation (`insert`, `get`) takes a `root: Hash` parameter and returns a new root. `Hash::default()` (`[0u8; 32]`) is the canonical empty root. This lets callers work with sub-trees by passing any intermediate node hash as a root.

**Content-addressed, parent-keyed storage.** The backend maps `parent_hash → Node { left, right }`. Leaf nodes are terminal — they have *no* backend entry. An all-zero hash marks an empty slot. Traversal always starts at the root and descends.

**Key-bit addressing.** Each leaf's position is determined by its **key** (a 32-byte hash), read MSB-first (bit 0 = MSB of byte 0, bit 255 = LSB of byte 31). Bit 0 selects left (0) or right (1) at the root, bit 1 at the next level, etc. For `insert`, the key is `H::hash(leaf_data)`; for `insert_indexed`, the key is `Node::key_from_bytes(index)` (raw bytes zero-padded to 32).

**`KvsBackend` is immutable-interface.** All methods take `&self`; implementations use interior mutability (`RefCell`, `Mutex`, etc.). The tree never holds `&mut backend`. `set` returns `anyhow::Result<()>`.

**`push_down` handles leaf–leaf collisions.** When `insert` reaches an existing leaf at the target path, `push_down` recursively descends until the two keys' bits diverge, then places each leaf on its correct side. Empty slots (`Hash::default()`) fill the non-matching branches. Errors only on a true 256-bit hash collision.

**Namespaced storage.** The tree uses `ns` for node storage and `"{ns}-key"` for the leaf_hash → key mapping needed by `push_down`.

### Module responsibilities

| Module | Purpose |
|--------|---------|
| `backend` | `KvsBackend` trait — bytes-only, `&self` get/set; `Shared` type alias |
| `hash` | `Hash = [u8; 32]`, `Hasher` trait with default `hash_pair` (left \|\| right) |
| `node` | `Node { left: Hash, right: Hash }` — stored in backend; `key_from_bytes` helper |
| `memory` | `MemoryBackend` — `RefCell<BTreeMap>`, single-threaded |
| `tree` | `MerkleTree<B, H>` — `insert`, `insert_leaf`, `insert_indexed`, `insert_indexed_leaf`, `get`, `get_indexed`, `contains`, `contains_leaf`, `get_opening`, `get_opening_leaf`, `get_indexed_opening` |
| `proof` | `MerkleOpening<H>` — membership + non-membership proofs; `to_bytes`/`try_from_bytes` |
| `sha256` | `Sha256Hasher`, `Sha256MerkleTree<B>` (feature: `sha2`) |
| `redb` | `RedbBackend`, `RedbMerkleTree<H>` (feature: `redb`) |
| `fjall` | `FjallBackend` (feature: `fjall`) |

### Dependencies

- `anyhow` (`default-features = false`) — all fallible operations return `anyhow::Result`. No custom error types.
- `sha2` — optional feature; also a dev-dependency for tests.
- `serde` — optional feature; derives `Serialize`/`Deserialize` for `Node` and `MerkleOpening`.
- `redb`, `fjall` — optional features for persistent backends.
- Everything else comes from `core` and `alloc`.

### Implementing a custom backend

Implement `KvsBackend` with `type Get: Deref<Target = [u8]>`, using interior mutability for the write path. All errors surface as `anyhow::Error`.
