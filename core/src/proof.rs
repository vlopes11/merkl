use crate::hash::Hash;

/// Whether the sibling node sits to the left or right of the current node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofSide {
    Left,
    Right,
}

/// A single sibling entry in a Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSibling {
    pub hash: Hash,
    pub side: ProofSide,
}
