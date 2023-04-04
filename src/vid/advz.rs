//! Implementation of VID from https://eprint.iacr.org/2021/1500
//! Why call it `advz`? authors Alhaddad-Duan-Varia-Zhang

use super::{Vec, VID};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_serialize::CanonicalSerializeHashExt;
use ark_std::string::ToString;
use jf_primitives::{
    errors::PrimitivesError,
    pcs::{
        prelude::{
            UnivariateKzgPCS,
            UnivariateProverParam,
            UnivariateUniversalParams,
            // UnivariateVerifierParam,
        },
        PolynomialCommitmentScheme, StructuredReferenceString,
    },
};
use jf_utils::bytes_to_field_elements;
use jf_utils::test_rng;
use sha2::{
    digest::generic_array::{typenum::U32, GenericArray},
    Sha256,
};

pub struct Advz {
    num_storage_nodes: usize,
    reconstruction_size: usize,
    // temp_pp: UnivariateUniversalParams<Bls12_381>, // TODO temporary until we have a KZG ceremony
    ck: UnivariateProverParam<<Bls12_381 as Pairing>::G1Affine>,
    // vk: UnivariateVerifierParam<Bls12_381>,
}

impl Advz {
    /// TODO we desperately need better error handling
    pub fn new(
        num_storage_nodes: usize,
        reconstruction_size: usize,
    ) -> Result<Self, PrimitivesError> {
        if reconstruction_size > num_storage_nodes {
            return Err(PrimitivesError::ParameterError(
                "Number of storage nodes must be at least the message length.".to_string(),
            ));
        }
        let pp = UnivariateUniversalParams::<Bls12_381>::gen_srs_for_testing(
            &mut test_rng(),
            reconstruction_size,
        )
        .map_err(|_| {
            PrimitivesError::ParameterError(
                "Number of storage nodes must be at least the message length.".to_string(),
            )
        })?;
        let (ck, _vk) = pp
            .trim(reconstruction_size)
            .map_err(|_| PrimitivesError::ParameterError("why am i fighting this.".to_string()))?;

        Ok(Self {
            num_storage_nodes,
            reconstruction_size,
            ck,
            // vk,
        })
    }
}

pub type Commitment = GenericArray<u8, U32>;
// pub type Commitment =
//     <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Commitment;

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

    fn commit(&self, payload: &[u8]) -> Result<Self::Commitment, PrimitivesError> {
        let field_elements: Vec<<Bls12_381 as Pairing>::ScalarField> =
            bytes_to_field_elements(payload);
        let polynomial = DensePolynomial::from_coefficients_vec(field_elements);

        let commitment : <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Commitment = UnivariateKzgPCS::commit(&self.ck, &polynomial)
            .map_err(|_| PrimitivesError::ParameterError("why am i fighting this.".to_string()))?;

        Ok(commitment.hash_uncompressed::<Sha256>())
    }

    fn disperse(&self, _payload: &[u8]) -> Vec<Self::Share> {
        assert!(self.num_storage_nodes == 0); // temporary compiler pacification
        assert!(self.reconstruction_size == 0); // temporary compiler pacification
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

// impl Advz {
//     fn (&self)
// }
