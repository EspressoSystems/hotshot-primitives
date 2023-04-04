//! Implementation of VID from https://eprint.iacr.org/2021/1500
//! Why call it `advz`? authors Alhaddad-Duan-Varia-Zhang

use super::{Vec, VID};
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerializeHashExt;
use ark_std::string::ToString;
use jf_primitives::{
    errors::PrimitivesError,
    pcs::{
        prelude::{
            UnivariateKzgPCS, UnivariateProverParam, UnivariateUniversalParams,
            UnivariateVerifierParam,
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
    vk: UnivariateVerifierParam<Bls12_381>,
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
        let (ck, vk) = pp
            .trim(reconstruction_size)
            .map_err(|_| PrimitivesError::ParameterError("why am i fighting this.".to_string()))?;

        Ok(Self {
            num_storage_nodes,
            reconstruction_size,
            ck,
            vk,
        })
    }
}

// TODO sucks that I need `GenericArray` here. You'd think the `sha2` crate would export a type alias for hash outputs.
pub type Commitment = GenericArray<u8, U32>;

pub struct Share {
    id: usize,

    // TODO: split `polynomial_commitments` from ShareData to avoid duplicate data?
    // TODO only one commitment for now
    polynomial_commitments:
        <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Commitment,

    // TODO only one payload for now
    encoded_payload:
        <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Evaluation,

    proof: <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Proof,
}

impl VID for Advz {
    type Commitment = Commitment;

    type Share = Share;

    fn commit(&self, payload: &[u8]) -> Result<Self::Commitment, PrimitivesError> {
        // TODO eliminate fully qualified syntax?
        let field_elements: Vec<<Bls12_381 as Pairing>::ScalarField> =
            bytes_to_field_elements(payload);

        // TODO for now just put it all in a single polynomial
        let polynomial = DensePolynomial::from_coefficients_vec(field_elements);

        // TODO eliminate fully qualified syntax?
        let commitment : <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Commitment = UnivariateKzgPCS::commit(&self.ck, &polynomial)
            .map_err(|_| PrimitivesError::ParameterError("why am i fighting this.".to_string()))?;

        Ok(commitment.hash_uncompressed::<Sha256>())
    }

    fn disperse(&self, payload: &[u8]) -> Result<Vec<Self::Share>, PrimitivesError> {
        // TODO eliminate fully qualified syntax?
        let field_elements: Vec<<Bls12_381 as Pairing>::ScalarField> =
            bytes_to_field_elements(payload);

        // TODO for now just put it all in a single polynomial
        let polynomial = DensePolynomial::from_coefficients_vec(field_elements);

        // TODO eliminate fully qualified syntax?
        let commitment : <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme<Bls12_381>>::Commitment = UnivariateKzgPCS::commit(&self.ck, &polynomial)
        .map_err(|_| PrimitivesError::ParameterError("why am i fighting this.".to_string()))?;

        // TODO random linear combo of polynomials
        // let input =
        // let foo = polynomial.evaluate();

        // TODO range should be roots of unity
        let output: Vec<Self::Share> = (1..=self.num_storage_nodes)
            .map(|j| {
                let id =
                    <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&j.to_be_bytes());

                let chunk = polynomial.evaluate(&id);

                // TODO don't unwrap: use `collect` to handle `Result`
                let (proof, _value) =
                    UnivariateKzgPCS::<Bls12_381>::open(&self.ck, &polynomial, &id).unwrap();

                Share {
                    id: j,
                    polynomial_commitments: commitment,
                    encoded_payload: chunk,
                    proof: proof,
                }
            })
            .collect();

        Ok(output)
    }

    fn verify_share(
        &self,
        share: &Self::Share,
    ) -> Result<(), jf_primitives::errors::PrimitivesError> {
        let id =
            <Bls12_381 as Pairing>::ScalarField::from_be_bytes_mod_order(&share.id.to_be_bytes());

        // TODO value = random lin combo of payloads
        let value = share.encoded_payload.clone();

        let success = UnivariateKzgPCS::<Bls12_381>::verify(
            &self.vk,
            &share.polynomial_commitments,
            &id,
            &value,
            &share.proof,
        )
        .unwrap();

        match success {
            true => Ok(()),
            false => Err(PrimitivesError::ParameterError(
                "why am i fighting this.".to_string(),
            )),
        }
    }

    fn recover_payload(
        &self,
        _shares: &[Self::Share],
    ) -> Result<Vec<u8>, jf_primitives::errors::PrimitivesError> {
        assert!(self.reconstruction_size > 0); // TODO compiler pacification
        todo!()
    }
}
