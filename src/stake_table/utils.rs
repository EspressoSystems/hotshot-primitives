//! Utilities for maintaining a local stake table

use super::{
    config::{u256_to_field, Digest, FieldType, TREE_BRANCH},
    error::StakeTableError,
    EncodedPublicKey,
};
use ark_ff::Field;
use ark_std::{sync::Arc, vec, vec::Vec};
use ethereum_types::U256;
use jf_primitives::crhf::CRHF;
use jf_utils::canonical;
use serde::{Deserialize, Serialize};

/// A persistent merkle tree tailored for the stake table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PersistentMerkleNode {
    Empty,
    Branch {
        #[serde(with = "canonical")]
        comm: FieldType,
        children: [Arc<PersistentMerkleNode>; TREE_BRANCH],
        num_keys: usize,
        total_stakes: U256,
    },
    Leaf {
        #[serde(with = "canonical")]
        comm: FieldType,
        #[serde(with = "canonical")]
        key: EncodedPublicKey,
        value: U256,
    },
}

/// A compressed Merkle node for Merkle path
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MerklePathEntry {
    Branch {
        pos: usize,
        #[serde(with = "canonical")]
        siblings: [FieldType; TREE_BRANCH - 1],
    },
    Leaf {
        key: EncodedPublicKey,
        value: U256,
    },
}
/// Path from a Merkle root to a leaf
pub type MerklePath = Vec<MerklePathEntry>;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
/// An existential proof
pub struct MerkleProof {
    /// Index for the given key
    pub index: usize,
    /// A Merkle path for the given leaf
    pub path: MerklePath,
}

impl MerkleProof {
    pub fn tree_height(&self) -> usize {
        self.path.len()
    }

    pub fn index(&self) -> &usize {
        &self.index
    }

    pub fn get_key(&self) -> Option<&EncodedPublicKey> {
        match self.path.first() {
            Some(MerklePathEntry::Leaf { key, value: _ }) => Some(key),
            _ => None,
        }
    }

    pub fn get_value(&self) -> Option<&U256> {
        match self.path.first() {
            Some(MerklePathEntry::Leaf { key: _, value }) => Some(value),
            _ => None,
        }
    }

    pub fn get_key_value(&self) -> Option<(&EncodedPublicKey, &U256)> {
        match self.path.first() {
            Some(MerklePathEntry::Leaf { key, value }) => Some((key, value)),
            _ => None,
        }
    }

    pub fn compute_root(&self) -> Result<FieldType, StakeTableError> {
        match self.path.first() {
            Some(MerklePathEntry::Leaf { key, value }) => {
                let input = [
                    FieldType::from(0),
                    <FieldType as Field>::from_random_bytes(&key.0).unwrap(),
                    u256_to_field(value),
                ];
                let init = Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0];
                self.path
                    .iter()
                    .skip(1)
                    .fold(Ok(init), |result, node| match node {
                        MerklePathEntry::Branch { pos, siblings } => match result {
                            Ok(comm) => {
                                let mut input = [FieldType::from(0); TREE_BRANCH];
                                input[..*pos].copy_from_slice(&siblings[..*pos]);
                                input[*pos] = comm;
                                input[pos + 1..].copy_from_slice(&siblings[*pos..]);
                                let comm = Digest::evaluate(input)
                                    .map_err(|_| StakeTableError::RescueError)?[0];
                                Ok(comm)
                            }
                            Err(_) => unreachable!(),
                        },
                        _ => Err(StakeTableError::MalformedProof),
                    })
            }
            _ => Err(StakeTableError::MalformedProof),
        }
    }

    pub fn verify(&self, comm: &MerkleCommitment) -> Result<(), StakeTableError> {
        if self.tree_height() != comm.tree_height() || !self.compute_root()?.eq(comm.digest()) {
            Err(StakeTableError::VerificationError)
        } else {
            Ok(())
        }
    }
}

/// A succint commitment for Merkle tree
pub struct MerkleCommitment {
    /// Merkle tree digest
    comm: FieldType,
    /// Height of a tree
    height: usize,
    /// Number of leaves
    size: usize,
}

impl MerkleCommitment {
    pub fn new(comm: FieldType, height: usize, size: usize) -> Self {
        Self { comm, height, size }
    }

    pub fn digest(&self) -> &FieldType {
        &self.comm
    }

    pub fn tree_height(&self) -> usize {
        self.height
    }

    pub fn size(&self) -> usize {
        self.size
    }
}

impl PersistentMerkleNode {
    /// Construct an empty merkle node
    pub fn new_empty() -> Self {
        Self::Empty
    }

    /// Returns the succint commitment of this subtree
    pub fn commitment(&self) -> FieldType {
        match self {
            PersistentMerkleNode::Empty => FieldType::from(0),
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
    pub fn total_stakes(&self) -> U256 {
        match self {
            PersistentMerkleNode::Empty => U256::zero(),
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
    pub fn simple_lookup(&self, height: usize, path: &[usize]) -> Result<U256, StakeTableError> {
        match self {
            PersistentMerkleNode::Empty => Err(StakeTableError::KeyNotFound),
            PersistentMerkleNode::Branch {
                comm: _,
                children,
                num_keys: _,
                total_stakes: _,
            } => children[path[height - 1]].simple_lookup(height - 1, path),
            PersistentMerkleNode::Leaf {
                comm: _,
                key: _,
                value,
            } => Ok(*value),
        }
    }

    /// Returns a Merkle proof to the given location
    pub fn lookup(&self, height: usize, path: &[usize]) -> Result<MerkleProof, StakeTableError> {
        match self {
            PersistentMerkleNode::Empty => Err(StakeTableError::KeyNotFound),
            PersistentMerkleNode::Branch {
                comm: _,
                children,
                num_keys: _,
                total_stakes: _,
            } => {
                let pos = path[height - 1];
                let mut proof = children[pos].lookup(height - 1, path)?;
                let siblings = children
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| *i != pos)
                    .map(|(_, node)| node.commitment())
                    .collect::<Vec<_>>();
                proof.path.push(MerklePathEntry::Branch {
                    pos,
                    siblings: siblings.try_into().unwrap(),
                });
                Ok(proof)
            }
            PersistentMerkleNode::Leaf {
                comm: _,
                key,
                value,
            } => Ok(MerkleProof {
                index: from_merkle_path(path),
                path: vec![MerklePathEntry::Leaf {
                    key: key.clone(),
                    value: *value,
                }],
            }),
        }
    }

    /// Imagine that the keys in this subtree is sorted, returns the first key such that
    /// the prefix sum of withholding stakes is greater or equal the given `stake_number`.
    /// Useful for key sampling weighted by withholding stakes
    pub fn get_key_by_stake(&self, mut stake_number: U256) -> Option<&EncodedPublicKey> {
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
        value: U256,
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
                    Arc::new(children[path[height - 1]].update(height - 1, path, key, value)?);
                let num_keys = children.iter().map(|child| child.num_keys()).sum();
                let total_stakes = children
                    .iter()
                    .map(|child| child.total_stakes())
                    .fold(U256::zero(), |sum, val| sum + val);
                let comm = Digest::evaluate(children.clone().map(|child| child.commitment()))
                    .map_err(|_| StakeTableError::RescueError)?[0];
                Ok(PersistentMerkleNode::Branch {
                    comm,
                    children,
                    num_keys,
                    total_stakes,
                })
            }
            PersistentMerkleNode::Leaf { .. } => {
                // WARNING(Chengyu): I try to directly (de)serialize the encoded public key as a field element here. May introduce error or unwanted behavior.
                let input = [
                    FieldType::from(0),
                    <FieldType as Field>::from_random_bytes(&key.0).unwrap(),
                    u256_to_field(&value),
                ];
                Ok(PersistentMerkleNode::Leaf {
                    comm: Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0],
                    key: key.clone(),
                    value,
                })
            }
        }
    }

    pub fn register(
        &self,
        height: usize,
        path: &[usize],
        key: &EncodedPublicKey,
        value: U256,
    ) -> Result<Self, StakeTableError> {
        match self {
            PersistentMerkleNode::Empty => {
                if height == 0 {
                    // WARNING(Chengyu): I try to directly (de)serialize the encoded public key as a field element here. May introduce error or unwanted behavior.
                    let input = [
                        FieldType::from(0u64),
                        <FieldType as Field>::from_random_bytes(&key.0).unwrap(),
                        u256_to_field(&value),
                    ];
                    Ok(PersistentMerkleNode::Leaf {
                        comm: Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0],
                        key: key.clone(),
                        value,
                    })
                } else {
                    let mut children =
                        [0; TREE_BRANCH].map(|_| Arc::new(PersistentMerkleNode::Empty));
                    children[path[height - 1]] = Arc::new(children[path[height - 1]].register(
                        height - 1,
                        path,
                        key,
                        value,
                    )?);
                    let num_keys = children.iter().map(|child| child.num_keys()).sum();
                    let total_stakes = children
                        .iter()
                        .map(|child| child.total_stakes())
                        .fold(U256::zero(), |sum, val| sum + val);
                    let comm = Digest::evaluate(children.clone().map(|child| child.commitment()))
                        .map_err(|_| StakeTableError::RescueError)?[0];
                    Ok(PersistentMerkleNode::Branch {
                        comm,
                        children,
                        num_keys,
                        total_stakes,
                    })
                }
            }
            PersistentMerkleNode::Branch {
                comm: _,
                children,
                num_keys: _,
                total_stakes: _,
            } => {
                let mut children = children.clone();
                children[path[height - 1]] =
                    Arc::new(children[path[height - 1]].register(height - 1, path, key, value)?);
                let num_keys = children.iter().map(|child| child.num_keys()).sum();
                let total_stakes = children
                    .iter()
                    .map(|child| child.total_stakes())
                    .fold(U256::zero(), |sum, val| sum + val);
                let comm = Digest::evaluate(children.clone().map(|child| child.commitment()))
                    .map_err(|_| StakeTableError::RescueError)?[0];
                Ok(PersistentMerkleNode::Branch {
                    comm,
                    children,
                    num_keys,
                    total_stakes,
                })
            }
            PersistentMerkleNode::Leaf { .. } => Err(StakeTableError::ExistingKey),
        }
    }

    pub fn remove(
        &self,
        height: usize,
        path: &[usize],
        key: &EncodedPublicKey,
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
                    Arc::new(children[path[height - 1]].remove(height - 1, path, key)?);
                let num_keys = children.iter().map(|child| child.num_keys()).sum();
                if num_keys == 0 {
                    Ok(PersistentMerkleNode::Empty)
                } else {
                    let total_stakes = children
                        .iter()
                        .map(|child| child.total_stakes())
                        .fold(U256::zero(), |sum, val| sum + val);
                    let comm = Digest::evaluate(children.clone().map(|child| child.commitment()))
                        .map_err(|_| StakeTableError::RescueError)?[0];
                    Ok(PersistentMerkleNode::Branch {
                        comm,
                        children,
                        num_keys,
                        total_stakes,
                    })
                }
            }
            PersistentMerkleNode::Leaf {
                comm: _,
                key: cur_key,
                value: _,
            } => {
                if key == cur_key {
                    Ok(PersistentMerkleNode::Empty)
                } else {
                    Err(StakeTableError::MismatchedKey)
                }
            }
        }
    }
}

/// Convert an index to a list of Merkle path branches
pub fn to_merkle_path(idx: usize, height: usize) -> Vec<usize> {
    let mut pos = idx;
    let mut ret: Vec<usize> = vec![];
    for _i in 0..height {
        ret.push(pos % TREE_BRANCH);
        pos /= TREE_BRANCH;
    }
    ret
}

/// Convert a list of Merkle path branches back to an index
pub fn from_merkle_path(path: &[usize]) -> usize {
    path.iter()
        .fold((0, 1), |(pos, mul), branch| {
            (pos + mul * branch, mul * TREE_BRANCH)
        })
        .0
}

#[cfg(test)]
mod tests {
    use super::{to_merkle_path, PersistentMerkleNode};
    use crate::stake_table::EncodedPublicKey;
    use ark_std::{vec, vec::Vec};
    use ethereum_types::U256;

    #[test]
    fn test_persistent_merkle_tree() {
        let height = 3;
        let mut roots = vec![PersistentMerkleNode::new_empty()];
        let path = (0..10)
            .map(|idx| to_merkle_path(idx, height))
            .collect::<Vec<_>>();
        let keys = (0u8..10u8)
            .map(|i| EncodedPublicKey(vec![i]))
            .collect::<Vec<_>>();
        // Insert key (0..10) with associated value 100 to the persistent merkle tree
        for (i, key) in keys.iter().enumerate() {
            roots.push(
                roots
                    .last()
                    .unwrap()
                    .register(height, &path[i], key, U256::from(100))
                    .unwrap(),
            );
        }
        // Check that if the insertion is perform correctly
        for i in 0..10 {
            assert!(roots[i].lookup(height, &path[i]).is_err());
            assert_eq!(i, roots[i].num_keys());
            assert_eq!(
                U256::from((i as u64 + 1) * 100),
                roots[i + 1].total_stakes()
            );
            assert_eq!(
                U256::from(100),
                roots[i + 1].simple_lookup(height, &path[i]).unwrap()
            );
        }
        // test get_key_by_stake
        keys.iter().enumerate().for_each(|(i, key)| {
            assert_eq!(
                key,
                roots
                    .last()
                    .unwrap()
                    .get_key_by_stake(U256::from(i as u64 * 100 + i as u64 + 1))
                    .unwrap()
            );
        });
        // test update
        roots.push(
            roots
                .last()
                .unwrap()
                .update(height, &path[2], &keys[2], U256::from(90))
                .unwrap(),
        );
        assert_eq!(
            U256::from(90),
            roots
                .last()
                .unwrap()
                .simple_lookup(height, &path[2])
                .unwrap()
        );
        // test remove
        for i in 0..10 {
            roots.push(
                roots
                    .last()
                    .unwrap()
                    .remove(height, &path[i], &keys[i])
                    .unwrap(),
            );
            assert_eq!(10 - i - 1, roots.last().unwrap().num_keys());
        }
    }
}
