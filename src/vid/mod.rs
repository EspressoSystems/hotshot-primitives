use ark_std::vec::Vec;
use jf_primitives::errors::PrimitivesError;
// use serde::{Deserialize, Serialize};

pub mod advz;

/// A trait for VID.
/// TODO: split into subtraits VIDSender, VIDStorage node for the different parties?
pub trait VID {
    /// Payload commitment.
    type Commitment;

    /// Share data sent to each storage node
    type Share;

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> Self::Commitment;

    /// Compute shares to send to the storage nodes
    fn disperse(&self, payload: &[u8]) -> Vec<Self::Share>;

    /// Verify a share. Used by both storage node and retrieval client.
    fn verify_share(&self, share: &Self::Share) -> Result<(), PrimitivesError>;

    /// Recover payload from shares.
    /// Does not check validity of shares.
    fn recover_payload(&self, shares: &[Self::Share]) -> Result<Vec<u8>, PrimitivesError>;
}
