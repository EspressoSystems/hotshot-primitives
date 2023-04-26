//! Utilities for maintaining a local stake table

use super::{error::StakeTableError, EncodedPublicKey};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{sync::Arc, vec::Vec};
use jf_primitives::crhf::{FixedLengthRescueCRHF, CRHF};
use jf_utils::canonical;
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;

/// Branch of merkle tree.
/// Set to 3 because we are currently using RATE-3 rescue hash function
const TREE_BRANCH: usize = 3;

/// Underlying field for rescue hash function
type F = ark_bn254::Fq;

/// Using rescue hash function
type Digest = FixedLengthRescueCRHF<F, 3, 1>;

#[tagged("MERKLE_COMM")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleCommitment(F);

impl AsRef<F> for MerkleCommitment {
    fn as_ref(&self) -> &F {
        &self.0
    }
}

impl From<F> for MerkleCommitment {
    fn from(value: F) -> Self {
        MerkleCommitment(value)
    }
}

/// A persistent merkle tree tailored for the stake table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersistentMerkleNode {
    Empty,
    Branch {
        #[serde(with = "canonical")]
        comm: MerkleCommitment,
        children: [Arc<PersistentMerkleNode>; TREE_BRANCH],
        num_keys: usize,
        total_stakes: u64,
    },
    Leaf {
        #[serde(with = "canonical")]
        comm: MerkleCommitment,
        #[serde(with = "canonical")]
        key: EncodedPublicKey,
        value: u64,
    },
}

impl PersistentMerkleNode {
    /// Construct an empty merkle node
    pub fn new_empty() -> Self {
        Self::Empty
    }

    /// Returns the succint commitment of this subtree
    pub fn commitment(&self) -> MerkleCommitment {
        match self {
            PersistentMerkleNode::Empty => MerkleCommitment(F::from(0u64)),
            PersistentMerkleNode::Branch {
                comm,
                children: _,
                num_keys: _,
                total_stakes: _,
            } => *comm,
            PersistentMerkleNode::Leaf {
                comm,
                key: _,
                value: _,
            } => *comm,
        }
    }

    /// Returns the total number of keys in this subtree
    pub fn num_keys(&self) -> usize {
        match self {
            PersistentMerkleNode::Empty => 0,
            PersistentMerkleNode::Branch {
                comm: _,
                children: _,
                num_keys,
                total_stakes: _,
            } => *num_keys,
            PersistentMerkleNode::Leaf {
                comm: _,
                key: _,
                value: _,
            } => 1,
        }
    }

    /// Returns the total stakes in this subtree
    pub fn total_stakes(&self) -> u64 {
        match self {
            PersistentMerkleNode::Empty => 0,
            PersistentMerkleNode::Branch {
                comm: _,
                children: _,
                num_keys: _,
                total_stakes,
            } => *total_stakes,
            PersistentMerkleNode::Leaf {
                comm: _,
                key: _,
                value,
            } => *value,
        }
    }

    /// Returns the stakes withhelded by a public key, None if the key is not registered.
    pub fn lookup(&self, height: usize, path: &[usize]) -> Option<u64> {
        match self {
            PersistentMerkleNode::Empty => None,
            PersistentMerkleNode::Branch {
                comm: _,
                children,
                num_keys: _,
                total_stakes: _,
            } => children[path[height - 1]].lookup(height - 1, path),
            PersistentMerkleNode::Leaf {
                comm: _,
                key: _,
                value,
            } => Some(*value),
        }
    }

    /// Imagine that the keys in this subtree is sorted, returns the first key such that
    /// the prefix sum of withholding stakes is greater or equal the given `stake_number`.
    /// Useful for key sampling weighted by withholding stakes
    pub fn get_key_by_stake(&self, mut stake_number: u64) -> Option<&EncodedPublicKey> {
        if stake_number >= self.total_stakes() {
            None
        } else {
            match self {
                PersistentMerkleNode::Empty => None,
                PersistentMerkleNode::Branch {
                    comm: _,
                    children,
                    num_keys: _,
                    total_stakes: _,
                } => {
                    let mut ptr = 0;
                    while stake_number >= children[ptr].total_stakes() {
                        stake_number -= children[ptr].total_stakes();
                        ptr += 1;
                    }
                    children[ptr].get_key_by_stake(stake_number)
                }
                PersistentMerkleNode::Leaf {
                    comm: _,
                    key,
                    value: _,
                } => Some(key),
            }
        }
    }

    /// Persistent update of a merkle tree
    /// Instead of direct modify the tree content, it will create a new copy for the affected Merkle path and modify upon it.
    pub fn update(
        &self,
        height: usize,
        path: &[usize],
        key: &EncodedPublicKey,
        delta: u64,
    ) -> Result<Self, StakeTableError> {
        match self {
            PersistentMerkleNode::Empty => Err(StakeTableError::KeyNotFound),
            PersistentMerkleNode::Branch {
                comm: _,
                children,
                num_keys: _,
                total_stakes: _,
            } => {
                let mut children = children.clone();
                children[path[height - 1]] =
                    Arc::new(children[path[height - 1]].update(height - 1, path, key, delta)?);
                let num_keys = children.iter().map(|child| child.num_keys()).sum();
                let total_stakes = children.iter().map(|child| child.total_stakes()).sum();
                let comm = MerkleCommitment(
                    Digest::evaluate(children.clone().map(|child| child.commitment().0))
                        .map_err(|_| StakeTableError::RescueError)?[0],
                );
                Ok(PersistentMerkleNode::Branch {
                    comm,
                    children,
                    num_keys,
                    total_stakes,
                })
            }
            PersistentMerkleNode::Leaf {
                comm: _,
                key: _,
                value,
            } => {
                let input = [
                    F::from(0u64),
                    <F as Field>::from_random_bytes(&key.0).unwrap(),
                    F::from(*value),
                ];
                Ok(PersistentMerkleNode::Leaf {
                    comm: MerkleCommitment(
                        Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0],
                    ),
                    key: key.clone(),
                    value: *value + delta,
                })
            }
        }
    }

    pub fn register(&self, height: usize, path: &[usize], key: &EncodedPublicKey) -> Option<Self> {
        todo!()
    }

    pub fn remove(&self, height: usize, path: &[usize], key: &EncodedPublicKey) -> Option<Self> {
        todo!()
    }
}
