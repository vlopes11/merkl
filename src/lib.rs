#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

pub mod backend;
pub mod hash;
pub mod memory;
pub mod node;
pub mod proof;
pub mod tree;

#[cfg(feature = "sha2")]
pub mod sha256;

pub use backend::KvsBackend;
pub use hash::{Hash, Hasher};
pub use memory::MemoryBackend;
pub use node::Node;
pub use proof::MerkleOpening;
pub use tree::MerkleTree;

#[cfg(feature = "sha2")]
pub use sha256::{Sha256Hasher, Sha256MerkleTree};

#[cfg(test)]
mod tests;

#[cfg(feature = "fjall")]
pub mod fjall;

#[cfg(feature = "redb")]
pub mod redb;
