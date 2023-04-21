use self::utils::{MerkleCommitment, PersistentMerkleNode};
use ark_std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use serde::{Deserialize, Serialize};

pub mod error;
mod transactions;
mod utils;

// Re-exports
pub use utils::EncodedPublicKey;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeTableHeader {
    pub height: u64,
    pub root: PersistentMerkleNode,
}

/// Locally maintained stake table
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeTable {
    data: VecDeque<Arc<StakeTableHeader>>,
    table: HashMap<u64, Arc<StakeTableHeader>>,
}

impl StakeTable {
    pub fn lookup(&self, height: u64, key: &EncodedPublicKey) -> Option<u64> {
        todo!("Implements key to merkle path")
    }

    pub fn commitment(&self, height: u64) -> Option<&MerkleCommitment> {
        self.table
            .get(&height)
            .map(|header| header.root.commitment())
    }

    pub fn total_stakes(&self, height: u64) -> Option<u64> {
        self.table
            .get(&height)
            .map(|header| header.root.total_stakes())
    }
}

// TODO: tests
#[cfg(test)]
mod tests {}
