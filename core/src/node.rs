use crate::hash::Hash;

/// The two children of an internal Merkle tree node.
///
/// Stored in the backend keyed by the parent's hash, enabling root-first
/// traversal: given any node hash, the backend yields its children.
/// Leaf nodes are terminal and have no entry in the backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub left: Hash,
    pub right: Hash,
}

impl Node {
    /// Serialise the node to a 64-byte array: left hash followed by right hash.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.left);
        buf[32..].copy_from_slice(&self.right);
        buf
    }

    /// Deserialise a node from a 64-byte slice.
    ///
    /// # Errors
    /// Returns an error if `bytes` is not exactly 64 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() == 64,
            "corrupt node: expected 64 bytes, got {}",
            bytes.len()
        );
        Ok(Self {
            left: bytes[..32].try_into().unwrap(),
            right: bytes[32..].try_into().unwrap(),
        })
    }
}
