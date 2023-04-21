//! Utilities for maintaining a local stake table

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{sync::Arc, vec::Vec};
use jf_utils::canonical;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tagged_base64::tagged;

/// Branch for Merkle tree, must be a power of 2
const TREE_BRANCH: usize = 16;
/// Log2(TREE_BRANCH)
const LOG2_TREE_BRANCH: usize = 4;

/// Copied from HotShot repo.
/// Type saftey wrapper for byte encoded keys.
#[tagged("PUBKEY")]
#[derive(
    Clone, Debug, Hash, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct EncodedPublicKey(pub Vec<u8>);

#[tagged("MERKLE_COMM")]
#[derive(Debug, Clone, PartialEq, Eq, Hash, CanonicalSerialize, CanonicalDeserialize)]
pub struct MerkleCommitment([u8; 32]);

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
    pub fn commitment(&self) -> &MerkleCommitment {
        match self {
            PersistentMerkleNode::Empty => &MerkleCommitment([0u8; 32]),
            PersistentMerkleNode::Branch {
                comm,
                children: _,
                num_keys: _,
                total_stakes: _,
            } => comm,
            PersistentMerkleNode::Leaf {
                comm,
                key: _,
                value: _,
            } => comm,
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

    pub fn batch_update(&self, height: usize) -> Self {
        todo!()
    }
}

// fn digest(input: &[u8]) -> [u8; 32] {
//     Keccak256::digest(input).into()
// }
