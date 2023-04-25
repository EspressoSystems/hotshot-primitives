use ark_std as std; // needed for thiserror crate
use ark_std::{string::String, vec::Vec};

pub mod advz;

#[derive(thiserror::Error, Debug)]
pub enum VIDError {
    #[error("invalid arguments: {0}")]
    Argument(String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error), // could be any error
}

type VIDResult<T> = Result<T, VIDError>;

/// VID: Verifiable Information Dispersal
pub trait VID {
    /// Payload commitment.
    type Commitment;

    /// Share-specific data sent to a storage node.
    type Share;

    /// Common data broadcast to all storage nodes.
    type Bcast;

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> VIDResult<Self::Commitment>;

    /// Compute shares to send to the storage nodes
    fn disperse(&self, payload: &[u8]) -> VIDResult<(Vec<Self::Share>, Self::Bcast)>;

    /// Verify a share. Used by both storage node and retrieval client.
    /// Returns:
    /// - VIDResult::Err in case of actual error
    /// - VIDResult::Ok(Result::Err) if verification fails
    /// - VIDResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(&self, share: &Self::Share, bcast: &Self::Bcast) -> VIDResult<Result<(), ()>>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against a commitment.
    fn recover_payload(&self, shares: &[Self::Share], bcast: &Self::Bcast) -> VIDResult<Vec<u8>>;
}
