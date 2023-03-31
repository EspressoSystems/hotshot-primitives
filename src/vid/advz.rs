//! Implementation of VID from https://eprint.iacr.org/2021/1500
//! Why call it `advz`? authors Alhaddad-Duan-Varia-Zhang

use super::{Vec, VID};
use sha2::digest::generic_array::{typenum::U32, GenericArray};

pub struct Advz {
    num_storage_nodes: u16,
}

impl Advz {
    pub fn new(num_storage_nodes: u16) -> Self {
        Self { num_storage_nodes }
    }
}

pub type Commitment = GenericArray<u8, U32>;

pub struct Share {
    // TODO: split `polynomial_commitments` from ShareData to avoid duplicate data?
    // TODO `u32` -> KZG commitments
    // polynomial_commitments: Vec<u32>,

    // TODO: `u32` -> field element (polynomial evaluation)
    // encoded_payload: Vec<u32>,

    // TODO: u32 -> KZG batch proof
    // proof: u32,
}

impl VID for Advz {
    type Commitment = Commitment;

    type Share = Share;

    fn commit(&self, _payload: &[u8]) -> Self::Commitment {
        // TODO: for now just return the zero hash digest
        GenericArray::from([0; 32])
    }

    fn disperse(&self, _payload: &[u8]) -> Vec<Self::Share> {
        assert!(self.num_storage_nodes == 0); // temporary compiler pacification
        todo!()
    }

    fn verify_share(
        &self,
        _share: &Self::Share,
    ) -> Result<(), jf_primitives::errors::PrimitivesError> {
        todo!()
    }

    fn recover_payload(
        &self,
        _shares: &[Self::Share],
    ) -> Result<Vec<u8>, jf_primitives::errors::PrimitivesError> {
        todo!()
    }
}
