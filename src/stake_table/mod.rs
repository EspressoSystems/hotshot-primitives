use self::{
    error::StakeTableError,
    utils::{to_merkle_path, PersistentMerkleNode},
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

mod config;
mod utils;

// Exports
pub mod error;
pub use utils::MerkleCommitment;
pub use utils::MerklePath;
pub use utils::MerklePathEntry;
pub use utils::MerkleProof;

/// Copied from HotShot repo.
/// Type saftey wrapper for byte encoded keys.
/// Assume that the content is a canonically serialized public key
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
    /// The capacity is `TREE_BRANCH.pow(height)`.
    height: usize,

    /// The mapping from public keys to their location in the Merkle tree.
    mapping: HashMap<EncodedPublicKey, usize>,
}

impl StakeTable {
    /// Initiating an empty stake table.
    /// Overall capacity is `TREE_BRANCH.pow(height)`.
    pub fn new(height: usize) -> Self {
        Self {
            pending: Arc::new(PersistentMerkleNode::Empty),
            frozen: Arc::new(PersistentMerkleNode::Empty),
            active: Arc::new(PersistentMerkleNode::Empty),
            height,
            mapping: HashMap::new(),
        }
    }

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

    /// Almost uniformly samples a key weighted by its stake from the active stake table
    pub fn sample_key_by_stake<R: CryptoRng + RngCore>(&self, rng: &mut R) -> &EncodedPublicKey {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let r = U512::from_big_endian(&bytes);
        let m = U512::from(self.active.total_stakes());
        let pos: U256 = (r % m).try_into().unwrap();
        self.active.get_key_by_stake(pos).unwrap()
    }

    /// Set the stake withheld by `key` to be `value`.
    /// Return the previous stake if succeed.
    pub fn set_value(
        &mut self,
        key: &EncodedPublicKey,
        value: U256,
    ) -> Result<U256, StakeTableError> {
        match self.mapping.get(key) {
            Some(pos) => {
                let old_value: U256;
                (self.pending, old_value) = self.pending.set_value(
                    self.height,
                    &to_merkle_path(*pos, self.height),
                    key,
                    value,
                )?;
                Ok(old_value)
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }

    /// Update the stake of the `key` with `(negative ? -1 : 1) * delta`.
    /// Return the updated stake
    pub fn update(
        &mut self,
        key: &EncodedPublicKey,
        delta: U256,
        negative: bool,
    ) -> Result<U256, StakeTableError> {
        match self.mapping.get(key) {
            Some(pos) => {
                let value: U256;
                (self.pending, value) = self.pending.update(
                    self.height,
                    &to_merkle_path(*pos, self.height),
                    key,
                    delta,
                    negative,
                )?;
                Ok(value)
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }

    /// Register a new key from the pending stake table
    pub fn register(&mut self, key: &EncodedPublicKey, value: U256) -> Result<(), StakeTableError> {
        match self.mapping.get(key) {
            Some(_) => Err(StakeTableError::ExistingKey),
            None => {
                let pos = self.mapping.len();
                self.mapping.insert(key.clone(), pos);
                self.pending = self.pending.register(
                    self.height,
                    &to_merkle_path(pos, self.height),
                    key,
                    value,
                )?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::stake_table::STVersion;

    use super::{config::FieldType, EncodedPublicKey, StakeTable};
    use ark_std::vec::Vec;
    use ethereum_types::U256;
    use jf_utils::to_bytes;

    #[test]
    fn test_stake_table() {
        let mut st = StakeTable::new(3);
        let keys = (0..10)
            .map(|i| EncodedPublicKey(to_bytes!(&FieldType::from(i)).unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(st.total_stakes(STVersion::PENDING), U256::from(0));

        // Registering keys
        keys.iter()
            .take(4)
            .for_each(|key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stakes(STVersion::PENDING), U256::from(400));
        assert_eq!(st.total_stakes(STVersion::FROZEN), U256::from(0));
        assert_eq!(st.total_stakes(STVersion::ACTIVE), U256::from(0));
        // set to zero for futher sampling test
        assert_eq!(
            st.set_value(&keys[1], U256::from(0)).unwrap(),
            U256::from(100)
        );
        st.advance();
        keys.iter()
            .skip(4)
            .take(3)
            .for_each(|key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stakes(STVersion::PENDING), U256::from(600));
        assert_eq!(st.total_stakes(STVersion::FROZEN), U256::from(300));
        assert_eq!(st.total_stakes(STVersion::ACTIVE), U256::from(0));
        st.advance();
        keys.iter()
            .skip(7)
            .for_each(|key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stakes(STVersion::PENDING), U256::from(900));
        assert_eq!(st.total_stakes(STVersion::FROZEN), U256::from(600));
        assert_eq!(st.total_stakes(STVersion::ACTIVE), U256::from(300));

        // No duplicate register
        assert!(st.register(&keys[0], U256::from(100)).is_err());
        // The 9-th key is still in pending stake table
        assert!(st.simple_lookup(STVersion::FROZEN, &keys[9]).is_err());
        assert!(st.simple_lookup(STVersion::FROZEN, &keys[5]).is_ok());
        // The 6-th key is still frozen
        assert!(st.simple_lookup(STVersion::ACTIVE, &keys[6]).is_err());
        assert!(st.simple_lookup(STVersion::ACTIVE, &keys[2]).is_ok());

        // Set value shall return the old value
        assert_eq!(
            st.set_value(&keys[0], U256::from(101)).unwrap(),
            U256::from(100)
        );
        assert_eq!(st.total_stakes(STVersion::PENDING), U256::from(901));
        assert_eq!(st.total_stakes(STVersion::FROZEN), U256::from(600));

        // Update that results in a negative stake
        assert!(st.update(&keys[0], U256::from(1000), true).is_err());
        // Update should return the updated stake
        assert_eq!(
            st.update(&keys[0], U256::from(1), true).unwrap(),
            U256::from(100)
        );
        assert_eq!(
            st.update(&keys[0], U256::from(100), false).unwrap(),
            U256::from(200)
        );

        // Testing membership proof
        let proof = st.lookup(STVersion::FROZEN, &keys[5]).unwrap();
        assert!(proof.verify(&st.commitment(STVersion::FROZEN)).is_ok());
        // Membership proofs are tied with a specific version
        assert!(proof.verify(&st.commitment(STVersion::PENDING)).is_err());
        assert!(proof.verify(&st.commitment(STVersion::ACTIVE)).is_err());

        // Random test for sampling keys
        let mut rng = jf_utils::test_rng();
        for _ in 0..100 {
            let key = st.sample_key_by_stake(&mut rng);
            // Sampled keys should have positive stake
            assert!(st.simple_lookup(STVersion::ACTIVE, key).unwrap() > U256::from(0));
        }
    }
}
