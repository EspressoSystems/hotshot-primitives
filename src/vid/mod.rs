use ark_std as std; // needed for thiserror crate
use ark_std::{string::String, vec::Vec};

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
pub trait Vid {
    /// Payload commitment.
    type Commitment;

    /// Share-specific data sent to a storage node.
    type Share;

    /// Common data broadcast to all storage nodes.
    type Bcast;

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> VidResult<Self::Commitment>;

    /// Compute shares to send to the storage nodes
    fn disperse(&self, payload: &[u8]) -> VidResult<(Vec<Self::Share>, Self::Bcast)>;

    /// Verify a share. Used by both storage node and retrieval client.
    /// Returns:
    /// - VidResult::Err in case of actual error
    /// - VidResult::Ok(Result::Err) if verification fails
    /// - VidResult::Ok(Result::Ok) if verification succeeds
    fn verify_share(&self, share: &Self::Share, bcast: &Self::Bcast) -> VidResult<Result<(), ()>>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against anything.
    fn recover_payload(&self, shares: &[Self::Share], bcast: &Self::Bcast) -> VidResult<Vec<u8>>;
}
