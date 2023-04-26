//! Utilities for maintaining a local stake table

use super::{error::StakeTableError, EncodedPublicKey};
use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{sync::Arc, vec, vec::Vec};
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
        delta: i64,
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
                // WARNING(Chengyu): I try to directly (de)serialize the encoded public key as a field element here. May introduce error or unwanted behavior.
                let input = [
                    F::from(0u64),
                    <F as Field>::from_random_bytes(&key.0).unwrap(),
                    F::from(*value),
                ];
                let new_value = (*value as i64) + delta;
                if new_value < 0 {
                    Err(StakeTableError::InsufficientFund)
                } else {
                    Ok(PersistentMerkleNode::Leaf {
                        comm: MerkleCommitment(
                            Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0],
                        ),
                        key: key.clone(),
                        value: new_value as u64,
                    })
                }
            }
        }
    }

    pub fn register(
        &self,
        height: usize,
        path: &[usize],
        key: &EncodedPublicKey,
        value: u64,
    ) -> Result<Self, StakeTableError> {
        match self {
            PersistentMerkleNode::Empty => {
                if height == 0 {
                    // WARNING(Chengyu): I try to directly (de)serialize the encoded public key as a field element here. May introduce error or unwanted behavior.
                    let input = [
                        F::from(0u64),
                        <F as Field>::from_random_bytes(&key.0).unwrap(),
                        F::from(value),
                    ];
                    Ok(PersistentMerkleNode::Leaf {
                        comm: MerkleCommitment(
                            Digest::evaluate(input).map_err(|_| StakeTableError::RescueError)?[0],
                        ),
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

pub fn to_merkle_path(idx: u64, height: usize) -> Vec<usize> {
    let mut pos = idx;
    let mut ret: Vec<usize> = vec![];
    for _i in 0..height {
        ret.push(usize::try_from(pos % (TREE_BRANCH as u64)).unwrap());
        pos /= TREE_BRANCH as u64;
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::{to_merkle_path, PersistentMerkleNode};
    use crate::stake_table::EncodedPublicKey;
    use ark_std::{vec, vec::Vec};

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
                    .register(height, &path[i], key, 100u64)
                    .unwrap(),
            );
        }
        // Check that if the insertion is perform correctly
        for i in 0..10 {
            assert!(roots[i].lookup(height, &path[i]).is_none());
            assert_eq!(i, roots[i].num_keys());
            assert_eq!((i as u64 + 1) * 100, roots[i + 1].total_stakes());
            assert_eq!(100u64, roots[i + 1].lookup(height, &path[i]).unwrap());
        }
        // test get_key_by_stake
        keys.iter().enumerate().for_each(|(i, key)| {
            assert_eq!(
                key,
                roots
                    .last()
                    .unwrap()
                    .get_key_by_stake(i as u64 * 100 + i as u64 + 1)
                    .unwrap()
            );
        });
        // test update
        assert!(roots
            .last()
            .unwrap()
            .update(height, &path[3], &keys[3], -101)
            .is_err());
        roots.push(
            roots
                .last()
                .unwrap()
                .update(height, &path[2], &keys[2], -10)
                .unwrap(),
        );
        assert_eq!(
            90u64,
            roots.last().unwrap().lookup(height, &path[2]).unwrap()
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
