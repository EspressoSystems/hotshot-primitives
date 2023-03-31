//! Implementation of VID from https://eprint.iacr.org/2021/1500
//! Why call it `advz`? authors Alhaddad-Duan-Varia-Zhang

use super::{Vec, VID};
use sha2::digest::generic_array::{typenum::U32, GenericArray};

pub struct Advz {
    num_storage_nodes: u16,
    payload_byte_length: u64,
}

impl Advz {
    pub fn new(num_storage_nodes: u16, payload_byte_length: u64) -> Self {
        // TODO: for now assume payload_byte_length is a multiple of num_storage_nodes
        assert!(
            payload_byte_length % (num_storage_nodes as u64) == 0,
            "num_storage_nodes {} must divide payload_byte_length {}",
            num_storage_nodes,
            payload_byte_length
        );
        Self {
            num_storage_nodes,
            payload_byte_length,
        }
    }
}

pub type Commitment = GenericArray<u8, U32>;

pub struct ShareData {
    // TODO: split `polynomial_commitments` from ShareData to avoid duplicate data?
    // TODO `u32` -> KZG commitments
    // polynomial_commitments: Vec<u32>,

    // TODO: `u32` -> field element (polynomial evaluation)
    // encoded_payload: Vec<u32>,

    // TODO: u32 -> KZG batch proof
    // proof: u32,
}

impl VID for Advz {
    type Payload = Vec<u8>;

    type Commitment = Commitment;

    type ShareData = ShareData;

    type Acknowledgement = ();

    type RetrievabilityCert = ();

    fn commit(&self, payload: &Self::Payload) -> Self::Commitment {
        assert!((payload.len() as u64) == self.payload_byte_length);
        // TODO: for now just return the zero hash digest
        GenericArray::from([0; 32])
    }

    fn disperse(&self, _payload: &Self::Payload) -> Vec<Self::ShareData> {
        assert!(self.num_storage_nodes == 0); // temporary compiler pacification
        todo!()
    }

    fn disperse_reply(
        &self,
        _my_id: u16,
        _share_data: &Self::ShareData,
    ) -> Result<Self::Acknowledgement, jf_primitives::errors::PrimitivesError> {
        todo!()
    }

    fn retrievability_cert(
        &self,
        _acknowledgements: &[Self::Acknowledgement],
    ) -> Result<Self::RetrievabilityCert, jf_primitives::errors::PrimitivesError> {
        todo!()
    }

    fn retrieve(&self, _cert: &Self::RetrievabilityCert) -> () {
        todo!()
    }

    fn retrieve_reply(
        &self,
        _commitment: &Self::Commitment,
    ) -> Result<Self::ShareData, jf_primitives::errors::PrimitivesError> {
        todo!()
    }
}
