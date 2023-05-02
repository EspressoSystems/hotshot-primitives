use self::{
    error::StakeTableError,
    utils::{to_merkle_path, MerkleCommitment, MerkleProof, PersistentMerkleNode},
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{
    collections::HashMap,
    rand::{CryptoRng, RngCore},
    sync::Arc,
    vec::Vec,
};
use ethereum_types::{U256, U512};
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
    pending: Arc<PersistentMerkleNode>,
    /// When an epoch ends, the PENDING stake table is frozen for leader elections for next epoch.
    frozen: Arc<PersistentMerkleNode>,
    /// The active stake table for leader election.
    active: Arc<PersistentMerkleNode>,

    /// Height of the underlying merkle tree, determines the capacity.
    height: usize,

    /// The mapping from public keys to their location in the Merkle tree.
    mapping: HashMap<EncodedPublicKey, usize>,
    /// Number of keys in the mapping
    mapping_num_keys: usize,
}

impl StakeTable {
    /// Update the stake table when the epoch number advances, should be manually called.
    pub fn advance(&mut self) {
        self.active = self.frozen.clone();
        self.frozen = self.pending.clone();
    }

    /// Returns the number of stakes holding by the input key for a specific stake table version
    pub fn simple_lookup(
        &self,
        version: STVersion,
        key: &EncodedPublicKey,
    ) -> Result<U256, StakeTableError> {
        let root = match version {
            STVersion::PENDING => &self.pending,
            STVersion::FROZEN => &self.frozen,
            STVersion::ACTIVE => &self.active,
        };
        match self.mapping.get(key) {
            Some(index) => {
                let branches = to_merkle_path(*index, self.height);
                root.simple_lookup(self.height, &branches)
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }

    /// Returns a membership proof for the input key for a specific stake table version
    pub fn lookup(
        &self,
        version: STVersion,
        key: &EncodedPublicKey,
    ) -> Result<MerkleProof, StakeTableError> {
        let root = match version {
            STVersion::PENDING => &self.pending,
            STVersion::FROZEN => &self.frozen,
            STVersion::ACTIVE => &self.active,
        };
        match self.mapping.get(key) {
            Some(index) => {
                let branches = to_merkle_path(*index, self.height);
                root.lookup(self.height, &branches)
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }

    /// Returns a succint commitment for a specific stake table version
    pub fn commitment(&self, version: STVersion) -> MerkleCommitment {
        let root = match version {
            STVersion::PENDING => &self.pending,
            STVersion::FROZEN => &self.frozen,
            STVersion::ACTIVE => &self.active,
        };
        MerkleCommitment::new(root.commitment(), self.height, root.num_keys())
    }

    /// Returns the total amount of stakes for a specific stake table version
    pub fn total_stakes(&self, version: STVersion) -> U256 {
        let root = match version {
            STVersion::PENDING => &self.pending,
            STVersion::FROZEN => &self.frozen,
            STVersion::ACTIVE => &self.active,
        };
        root.total_stakes()
    }

    /// Returns the number of keys for a specific stake table version
    pub fn num_keys(&self, version: STVersion) -> usize {
        let root = match version {
            STVersion::PENDING => &self.pending,
            STVersion::FROZEN => &self.frozen,
            STVersion::ACTIVE => &self.active,
        };
        root.num_keys()
    }

    /// Almost uniformly samples a key weighted by its withholding stakes from the active stake table
    pub fn sample_key_by_stake<R: CryptoRng + RngCore>(&self, rng: &mut R) -> &EncodedPublicKey {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let r = U512::from_big_endian(&bytes);
        let m = U512::from(self.active.total_stakes());
        let pos: U256 = (r & m).try_into().unwrap();
        self.active.get_key_by_stake(pos).unwrap()
    }

    /// Register a new key from the pendding stake table
    pub fn register(&mut self, key: &EncodedPublicKey, value: U256) -> Result<(), StakeTableError> {
        let pos = match self.mapping.get(key) {
            Some(pos) => *pos,
            None => {
                let pos = self.mapping_num_keys;
                self.mapping_num_keys += 1;
                self.mapping.insert(key.clone(), pos);
                pos
            }
        };
        self.pending = Arc::new(self.pending.register(
            self.height,
            &to_merkle_path(pos, self.height),
            key,
            value,
        )?);
        Ok(())
    }

    /// Deregister a key from the pending stake table
    pub fn deregister(&mut self, key: &EncodedPublicKey) -> Result<(), StakeTableError> {
        match self.mapping.get(key) {
            Some(pos) => {
                self.pending = Arc::new(self.pending.remove(
                    self.height,
                    &to_merkle_path(*pos, self.height),
                    key,
                )?);
                Ok(())
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }
}

// TODO(Chengyu): tests
#[cfg(test)]
mod tests {}
