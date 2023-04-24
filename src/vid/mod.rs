use ark_std::vec::Vec;
use jf_primitives::errors::PrimitivesError;
// use serde::{Deserialize, Serialize};

pub mod advz;

/// A trait for VID.
/// TODO: split into subtraits VIDSender, VIDStorage node for the different parties?
pub trait VID {
    /// Payload commitment.
    type Commitment;

    /// Share-specific data sent to a storage node.
    type Share;

    /// Common data broadcast to all storage nodes.
    type Bcast;

    /// Compute a payload commitment.
    fn commit(&self, payload: &[u8]) -> Result<Self::Commitment, PrimitivesError>;

    /// Compute shares to send to the storage nodes
    fn disperse(&self, payload: &[u8]) -> Result<(Vec<Self::Share>, Self::Bcast), PrimitivesError>;

    /// Verify a share. Used by both storage node and retrieval client.
    fn verify_share(&self, share: &Self::Share, bcast: &Self::Bcast)
        -> Result<(), PrimitivesError>;

    /// Recover payload from shares.
    /// Do not verify shares or check recovered payload against a commitment.
    fn recover_payload(
        &self,
        shares: &[Self::Share],
        bcast: &Self::Bcast,
    ) -> Result<Vec<u8>, PrimitivesError>;
}
