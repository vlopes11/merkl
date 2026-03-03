mod backend;

pub use backend::RedbBackend;
pub use merkl::{Hash, Hasher, MerkleTree, Node, ProofSibling, ProofSide};

/// A [`MerkleTree`] whose nodes are persisted in a [`redb`] database.
///
/// The hash function `H` is the only free type parameter:
///
/// ```rust,no_run
/// # use merkl::{Hash, Hasher};
/// # use merkl_redb::{RedbBackend, RedbMerkleTree};
/// # struct H; impl Hasher for H { fn hash(_: &[u8]) -> Hash { [0u8; 32] } }
/// let backend = RedbBackend::in_memory().unwrap();
/// let tree: RedbMerkleTree<H> = RedbMerkleTree::new(backend);
/// ```
pub type RedbMerkleTree<H> = MerkleTree<RedbBackend, H>;

/// A [`RedbMerkleTree`] that uses SHA-256 as its hash function.
///
/// No type parameters are required:
///
/// ```rust,no_run
/// use merkl::Hash;
/// use merkl_redb::{RedbBackend, Sha256RedbMerkleTree};
///
/// let tree = Sha256RedbMerkleTree::new(RedbBackend::in_memory().unwrap());
/// let root = tree.insert(Hash::default(), b"hello").unwrap();
/// ```
#[cfg(feature = "sha2")]
pub type Sha256RedbMerkleTree = RedbMerkleTree<merkl::Sha256Hasher>;

#[cfg(feature = "sha2")]
pub use merkl::Sha256Hasher;
