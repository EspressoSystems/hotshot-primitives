use self::utils::PersistentMerkleNode;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{collections::HashMap, vec::Vec};
use serde::{Deserialize, Serialize};
use tagged_base64::tagged;

pub mod error;
// TODO(Chengyu): temporarily export for clippy
pub mod config;
pub mod utils;

/// Copied from HotShot repo.
/// Type saftey wrapper for byte encoded keys.
#[tagged("PUBKEY")]
#[derive(
    Clone, Debug, Hash, CanonicalSerialize, CanonicalDeserialize, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct EncodedPublicKey(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeTableHeader {
    height: u64,
    root: PersistentMerkleNode,
}

/// Enum type for stake table version
///  * `STVersion::PENDING`: the most up-to-date stake table, where the incoming transactions shall be performed on.
///  * `STVersion::FROZEN`: when an epoch ends, the PENDING stake table is frozen for leader elections for next epoch.
///  * `STVersion::ACTIVE`: the active stake table for leader election.
pub enum STVersion {
    PENDING,
    FROZEN,
    ACTIVE,
}

/// Locally maintained stake table
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeTable {
    /// The most up-to-date stake table, where the incoming transactions shall be performed on.
    pending: StakeTableHeader,
    /// When an epoch ends, the PENDING stake table is frozen for leader elections for next epoch.
    frozen: StakeTableHeader,
    /// The active stake table for leader election.
    active: StakeTableHeader,

    /// The mapping from public keys to their location in the Merkle tree.
    mapping: HashMap<EncodedPublicKey, u64>,
}

// impl StakeTable {
//     pub fn lookup(&self, _height: u64, _key: &EncodedPublicKey) -> Option<u64> {
//         todo!("Implements key to merkle path")
//     }

//     pub fn commitment(&self, _height: u64) -> Option<&MerkleCommitment> {
//         todo!()
//     }

//     pub fn total_stakes(&self, _height: u64) -> Option<u64> {
//         todo!()
//     }
// }

// TODO(Chengyu): tests
#[cfg(test)]
mod tests {}
