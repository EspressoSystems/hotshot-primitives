use self::{
    error::StakeTableError,
    utils::{to_merkle_path, Key, PersistentMerkleNode},
};
use ark_std::{collections::HashMap, rand::SeedableRng, sync::Arc, vec::Vec};
use digest::crypto_common::rand_core::CryptoRngCore;
use ethereum_types::{U256, U512};
use serde::{Deserialize, Serialize};

mod config;
mod utils;

// Exports
pub mod error;
pub use utils::{MerkleCommitment, MerklePath, MerklePathEntry, MerkleProof};

/// Snapshots of the stake table
/// - the latest "Head" where all new changes are applied to
/// - `EpochStart` marks the snapshot at the beginning of the current epoch
/// - `LastEpochStart` marks the beginning of the last epoch
/// - `BlockNum(u64)` at arbitrary block height
pub enum SnapshotVersion {
    Head,
    EpochStart,
    LastEpochStart,
    BlockNum(u64),
}

/// Common interfaces required for a stake table used in HotShot System.
/// APIs that doesn't take `version: SnapshotVersion` as an input by default works on the head/latest version.
pub trait StakeTableScheme {
    /// type for stake key
    type Key: Clone;
    /// type for the staked amount
    type Amount: Clone + Copy;
    /// type for the commitment to the current stake table
    type Commitment;
    /// type for the proof associated with the lookup result (if any)
    type LookupProof;
    /// type for the iterator over (key, value) entries
    type IntoIter: Iterator<Item = (Self::Key, Self::Amount)>;

    /// Register a new key into the stake table.
    fn register(&mut self, new_key: Self::Key, amount: Self::Amount)
        -> Result<(), StakeTableError>;

    /// Batch register a list of new keys. A default implementation is provided
    /// w/o batch optimization.
    fn batch_register<I, J>(&mut self, new_keys: I, amounts: J) -> Result<(), StakeTableError>
    where
        I: IntoIterator<Item = Self::Key>,
        J: IntoIterator<Item = Self::Amount>,
    {
        let _ = new_keys
            .into_iter()
            .zip(amounts.into_iter())
            .try_for_each(|(key, amount)| Self::register(self, key, amount));
        Ok(())
    }

    /// Deregister an existing key from the stake table.
    /// Returns error if some keys are not found.
    fn deregister(&mut self, existing_key: &Self::Key) -> Result<(), StakeTableError>;

    /// Batch deregister a list of keys. A default implementation is provided
    /// w/o batch optimization.
    fn batch_deregister<'a, I>(&mut self, existing_keys: I) -> Result<(), StakeTableError>
    where
        I: IntoIterator<Item = &'a <Self as StakeTableScheme>::Key>,
        <Self as StakeTableScheme>::Key: 'a,
    {
        let _ = existing_keys
            .into_iter()
            .try_for_each(|key| Self::deregister(self, key));
        Ok(())
    }

    /// Returns the commitment to the `version` of stake table.
    fn commitment(&self, version: SnapshotVersion) -> Result<Self::Commitment, StakeTableError>;

    /// Returns the accumulated stakes of all registered keys of the `version`
    /// of stake table.
    fn total_stake(&self, version: SnapshotVersion) -> Result<Self::Amount, StakeTableError>;

    /// Returns the number of keys in the `version` of the table.
    fn len(&self, version: SnapshotVersion) -> Result<usize, StakeTableError>;

    /// Returns true if `key` is currently registered, else returns false.
    fn contains_key(&self, key: &Self::Key) -> bool;

    /// Lookup the stake under a key against a specific historical `version`,
    /// returns error if keys unregistered.
    fn lookup(
        &self,
        version: SnapshotVersion,
        key: &Self::Key,
    ) -> Result<(Self::Amount, Self::LookupProof), StakeTableError>;

    /// Returns the stakes withhelded by a public key, None if the key is not registered.
    /// If you need a lookup proof, use [`Self::lookup()`] instead (which is usually more expensive).
    fn simple_lookup(
        &self,
        version: SnapshotVersion,
        key: &Self::Key,
    ) -> Result<Self::Amount, StakeTableError>;

    /// Update the stake of the `key` with `(negative ? -1 : 1) * delta`.
    /// Return the updated stake or error.
    fn update(
        &mut self,
        key: &Self::Key,
        delta: Self::Amount,
        negative: bool,
    ) -> Result<Self::Amount, StakeTableError>;

    /// Batch update the stake balance of `keys`. Read documentation about
    /// [`Self::update()`]. By default, we call `Self::update()` on each
    /// (key, amount, negative) tuple.
    fn batch_update(
        &mut self,
        keys: &[Self::Key],
        amounts: &[Self::Amount],
        negative_flags: Vec<bool>,
    ) -> Result<Vec<Self::Amount>, StakeTableError> {
        let updated_amounts = keys
            .iter()
            .zip(amounts.iter())
            .zip(negative_flags.iter())
            .map(|((key, &amount), negative)| Self::update(self, key, amount, *negative))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(updated_amounts)
    }

    /// Randomly sample a (key, stake_amount) pair proportional to the stake distributions,
    /// given a fixed seed for `rng`, this sampling should be deterministic.
    fn sample(
        &self,
        rng: &mut (impl SeedableRng + CryptoRngCore),
    ) -> Option<(&Self::Key, &Self::Amount)>;

    /// Returns an iterator over all (key, value) entries of the `version` of the table
    fn iter(&self, version: SnapshotVersion) -> Result<Self::IntoIter, StakeTableError>;
}

/// Locally maintained stake table
/// generic over public key type `K`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "K: Key")]
pub struct StakeTable<K: Key> {
    /// The most up-to-date stake table, where the incoming transactions shall be performed on.
    head: Arc<PersistentMerkleNode<K>>,
    /// The snapshot of stake table at the beginning of the current epoch
    epoch_start: Arc<PersistentMerkleNode<K>>,
    /// The stake table used for leader election.
    last_epoch_start: Arc<PersistentMerkleNode<K>>,

    /// Height of the underlying merkle tree, determines the capacity.
    /// The capacity is `TREE_BRANCH.pow(height)`.
    height: usize,

    /// The mapping from public keys to their location in the Merkle tree.
    #[serde(skip)]
    mapping: HashMap<K, usize>,
}

impl<K: Key> StakeTableScheme for StakeTable<K> {
    type Key = K;
    type Amount = U256;
    type Commitment = MerkleCommitment;
    type LookupProof = MerkleProof<K>;
    type IntoIter = utils::IntoIter<K>;

    fn register(
        &mut self,
        new_key: Self::Key,
        amount: Self::Amount,
    ) -> Result<(), StakeTableError> {
        match self.mapping.get(&new_key) {
            Some(_) => Err(StakeTableError::ExistingKey),
            None => {
                let pos = self.mapping.len();
                self.head = self.head.register(
                    self.height,
                    &to_merkle_path(pos, self.height),
                    &new_key,
                    amount,
                )?;
                self.mapping.insert(new_key, pos);
                Ok(())
            }
        }
    }

    fn deregister(&mut self, _existing_key: &Self::Key) -> Result<(), StakeTableError> {
        // TODO: (alex) work on this in a future PR
        unimplemented!()
    }

    fn commitment(&self, version: SnapshotVersion) -> Result<Self::Commitment, StakeTableError> {
        let root = Self::get_root(self, version)?;
        Ok(MerkleCommitment::new(
            root.commitment(),
            self.height,
            root.num_keys(),
        ))
    }

    fn total_stake(&self, version: SnapshotVersion) -> Result<Self::Amount, StakeTableError> {
        let root = Self::get_root(self, version)?;
        Ok(root.total_stakes())
    }

    fn len(&self, version: SnapshotVersion) -> Result<usize, StakeTableError> {
        let root = Self::get_root(self, version)?;
        Ok(root.num_keys())
    }

    fn contains_key(&self, key: &Self::Key) -> bool {
        self.mapping.contains_key(key)
    }

    fn lookup(
        &self,
        version: SnapshotVersion,
        key: &Self::Key,
    ) -> Result<(Self::Amount, Self::LookupProof), StakeTableError> {
        let root = Self::get_root(self, version)?;

        let proof = match self.mapping.get(key) {
            Some(index) => {
                let branches = to_merkle_path(*index, self.height);
                root.lookup(self.height, &branches)
            }
            None => Err(StakeTableError::KeyNotFound),
        }?;
        let amount = *proof.get_value().ok_or(StakeTableError::KeyNotFound)?;
        Ok((amount, proof))
    }

    fn simple_lookup(
        &self,
        version: SnapshotVersion,
        key: &K,
    ) -> Result<Self::Amount, StakeTableError> {
        let root = Self::get_root(self, version)?;
        match self.mapping.get(key) {
            Some(index) => {
                let branches = to_merkle_path(*index, self.height);
                root.simple_lookup(self.height, &branches)
            }
            None => Err(StakeTableError::KeyNotFound),
        }
    }

    fn update(
        &mut self,
        key: &Self::Key,
        delta: Self::Amount,
        negative: bool,
    ) -> Result<Self::Amount, StakeTableError> {
        match self.mapping.get(key) {
            Some(pos) => {
                let value: U256;
                (self.head, value) = self.head.update(
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

    /// Almost uniformly samples a key weighted by its stake from the
    /// last_epoch_start stake table
    fn sample(
        &self,
        rng: &mut (impl SeedableRng + CryptoRngCore),
    ) -> Option<(&Self::Key, &Self::Amount)> {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let r = U512::from_big_endian(&bytes);
        let m = U512::from(self.last_epoch_start.total_stakes());
        let pos: U256 = (r % m).try_into().unwrap(); // won't fail
        self.last_epoch_start.get_key_by_stake(pos)
    }

    fn iter(&self, version: SnapshotVersion) -> Result<Self::IntoIter, StakeTableError> {
        let root = Self::get_root(self, version)?;
        Ok(utils::IntoIter::new(root))
    }
}

impl<K: Key> StakeTable<K> {
    /// Initiating an empty stake table.
    /// Overall capacity is `TREE_BRANCH.pow(height)`.
    pub fn new(height: usize) -> Self {
        Self {
            head: Arc::new(PersistentMerkleNode::Empty),
            epoch_start: Arc::new(PersistentMerkleNode::Empty),
            last_epoch_start: Arc::new(PersistentMerkleNode::Empty),
            height,
            mapping: HashMap::new(),
        }
    }

    // returns the root of stake table at `version`
    fn get_root(
        &self,
        version: SnapshotVersion,
    ) -> Result<Arc<PersistentMerkleNode<K>>, StakeTableError> {
        match version {
            SnapshotVersion::Head => Ok(Arc::clone(&self.head)),
            SnapshotVersion::EpochStart => Ok(Arc::clone(&self.epoch_start)),
            SnapshotVersion::LastEpochStart => Ok(Arc::clone(&self.last_epoch_start)),
            SnapshotVersion::BlockNum(_) => Err(StakeTableError::SnapshotUnsupported),
        }
    }

    /// Update the stake table when the epoch number advances, should be manually called.
    pub fn advance(&mut self) {
        self.last_epoch_start = self.epoch_start.clone();
        self.epoch_start = self.head.clone();
    }

    /// Set the stake withheld by `key` to be `value`.
    /// Return the previous stake if succeed.
    pub fn set_value(&mut self, key: &K, value: U256) -> Result<U256, StakeTableError> {
        match self.mapping.get(key) {
            Some(pos) => {
                let old_value: U256;
                (self.head, old_value) = self.head.set_value(
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
}

#[cfg(test)]
mod tests {
    use super::{error::StakeTableError, SnapshotVersion, StakeTable, StakeTableScheme};
    use ark_std::{rand::SeedableRng, vec::Vec};
    use ethereum_types::U256;

    // Hotshot use bn254::Fq as key type.
    type Key = ark_bn254::Fq;

    #[test]
    fn test_stake_table() -> Result<(), StakeTableError> {
        let mut st = StakeTable::new(3);
        let keys = (0..10).map(Key::from).collect::<Vec<_>>();
        assert_eq!(st.total_stake(SnapshotVersion::Head)?, U256::from(0));

        // Registering keys
        keys.iter()
            .take(4)
            .for_each(|&key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stake(SnapshotVersion::Head)?, U256::from(400));
        assert_eq!(st.total_stake(SnapshotVersion::EpochStart)?, U256::from(0));
        assert_eq!(
            st.total_stake(SnapshotVersion::LastEpochStart)?,
            U256::from(0)
        );
        // set to zero for futher sampling test
        assert_eq!(
            st.set_value(&keys[1], U256::from(0)).unwrap(),
            U256::from(100)
        );
        st.advance();
        keys.iter()
            .skip(4)
            .take(3)
            .for_each(|&key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stake(SnapshotVersion::Head)?, U256::from(600));
        assert_eq!(
            st.total_stake(SnapshotVersion::EpochStart)?,
            U256::from(300)
        );
        assert_eq!(
            st.total_stake(SnapshotVersion::LastEpochStart)?,
            U256::from(0)
        );
        st.advance();
        keys.iter()
            .skip(7)
            .for_each(|&key| st.register(key, U256::from(100)).unwrap());
        assert_eq!(st.total_stake(SnapshotVersion::Head)?, U256::from(900));
        assert_eq!(
            st.total_stake(SnapshotVersion::EpochStart)?,
            U256::from(600)
        );
        assert_eq!(
            st.total_stake(SnapshotVersion::LastEpochStart)?,
            U256::from(300)
        );

        // No duplicate register
        assert!(st.register(keys[0], U256::from(100)).is_err());
        // The 9-th key is still in head stake table
        assert!(st.lookup(SnapshotVersion::EpochStart, &keys[9]).is_err());
        assert!(st.lookup(SnapshotVersion::EpochStart, &keys[5]).is_ok());
        // The 6-th key is still frozen
        assert!(st
            .lookup(SnapshotVersion::LastEpochStart, &keys[6])
            .is_err());
        assert!(st.lookup(SnapshotVersion::LastEpochStart, &keys[2]).is_ok());

        // Set value shall return the old value
        assert_eq!(
            st.set_value(&keys[0], U256::from(101)).unwrap(),
            U256::from(100)
        );
        assert_eq!(st.total_stake(SnapshotVersion::Head)?, U256::from(901));
        assert_eq!(
            st.total_stake(SnapshotVersion::EpochStart)?,
            U256::from(600)
        );

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
        let proof = st.lookup(SnapshotVersion::EpochStart, &keys[5])?.1;
        assert!(proof
            .verify(&st.commitment(SnapshotVersion::EpochStart)?)
            .is_ok());
        // Membership proofs are tied with a specific version
        assert!(proof
            .verify(&st.commitment(SnapshotVersion::Head)?)
            .is_err());
        assert!(proof
            .verify(&st.commitment(SnapshotVersion::LastEpochStart)?)
            .is_err());

        // Random test for sampling keys
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(41u64);
        for _ in 0..100 {
            let (_key, value) = st.sample(&mut rng).unwrap();
            // Sampled keys should have positive stake
            assert!(value > &U256::from(0));
        }

        Ok(())
    }
}
