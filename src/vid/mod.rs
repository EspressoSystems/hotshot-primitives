use ark_std as std; // needed for thiserror crate
use ark_std::{fmt::Debug, string::String, vec::Vec};

pub mod advz;

#[derive(thiserror::Error, Debug)]
pub enum VidError {
    #[error("invalid arguments: {0}")]
    Argument(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

type VidResult<T> = Result<T, VidError>;

/// VID: Verifiable Information Dispersal
/// See <https://arxiv.org/abs/2111.12323> section 1.3--1.4 for intro to VID semantics.
pub trait VidScheme {
    /// Payload commitment.
    type Commitment: Clone + Debug + Eq + PartialEq + Sync; // TODO missing upstream Hash, Send

    /// Share-specific data sent to a storage node.
    type StorageShare: Clone + Debug + Eq + PartialEq + Sync; // TODO missing upstream Hash, Send

    /// Common data sent to all storage nodes.
    type StorageCommon: Clone + Debug + Eq + PartialEq + Sync; // TODO missing upstream Hash, Send

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> VidResult<Self::Commitment>;

    /// Compute shares to send to the storage nodes
    fn dispersal_data(
        &self,
        payload: &[u8],
    ) -> VidResult<(Vec<Self::StorageShare>, Self::StorageCommon)>;

    /// Verify a share. Used by both storage node and retrieval client.
    /// Why is return type a nested `Result`? See <https://sled.rs/errors>
    /// Returns:
    /// - VidResult::Err in case of actual error
    /// - VidResult::Ok(Result::Err) if verification fails
    /// - VidResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(
        &self,
        share: &Self::StorageShare,
        bcast: &Self::StorageCommon,
    ) -> VidResult<Result<(), ()>>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against anything.
    fn recover_payload(
        &self,
        shares: &[Self::StorageShare],
        bcast: &Self::StorageCommon,
    ) -> VidResult<Vec<u8>>;
}
