use ark_std::vec::Vec;
use jf_primitives::errors::PrimitivesError;
// use serde::{Deserialize, Serialize};

pub mod advz;

/// A trait for VID.
/// TODO: split into subtraits VIDSender, VIDStorage node for the different parties?
pub trait VID {
    /// Block payload.
    type Payload;

    /// Payload commitment.
    type Commitment;

    /// Share data sent to each storage node
    type ShareData;

    /// Acknowledgement of share data from a storage node
    type Acknowledgement;

    /// Certificate of retrievability
    type RetrievabilityCert;

    /// Compute a payload commitment.
    fn commit(&self, payload: &Self::Payload) -> Self::Commitment;

    /// Compute shares to send to the storage nodes
    fn disperse(&self, payload: &Self::Payload) -> Vec<Self::ShareData>;

    /// Storage node compute an acknowledgement.
    /// TODO: take a signature secret key
    /// TODO: unify error handling
    fn disperse_reply(
        &self,
        my_id: u16,
        share_data: &Self::ShareData,
    ) -> Result<Self::Acknowledgement, PrimitivesError>;

    /// Compute a certificate of retrievability from sufficiently many acknowledgements
    fn retrievability_cert(
        &self,
        acknowledgements: &[Self::Acknowledgement],
    ) -> Result<Self::RetrievabilityCert, PrimitivesError>;

    /// Compute requests to send to the storage nodes for the payload certified by `cert`
    /// TODO: nothing to do! "requests" are just "send me your data for `commit`"
    fn retrieve(&self, cert: &Self::RetrievabilityCert) -> ();

    /// Storage node retrieve its share for `commitment`.
    /// TODO: Don't include ShareData::commit?
    fn retrieve_reply(
        &self,
        commitment: &Self::Commitment,
    ) -> Result<Self::ShareData, PrimitivesError>;
}
