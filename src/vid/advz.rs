//! Implementation of VID from https://eprint.iacr.org/2021/1500
//! Why call it `advz`? authors Alhaddad-Duan-Varia-Zhang

use super::VID;
use ark_ec::AffineRepr;
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_poly::DenseUVPolynomial;
use ark_serialize::CanonicalSerialize;
use ark_std::{format, marker::PhantomData, vec, vec::Vec, Zero};

use jf_primitives::{
    erasure_code::{
        reed_solomon_erasure::{ReedSolomonErasureCode, ReedSolomonErasureCodeShare},
        ErasureCode,
    },
    errors::PrimitivesError,
    pcs::PolynomialCommitmentScheme,
};
use jf_utils::test_rng;
use jf_utils::{bytes_from_field_elements, bytes_to_field_elements};
use sha2::{
    digest::generic_array::{typenum::U32, GenericArray},
    Digest, Sha256,
};

pub struct Advz<P, T>
where
    P: PolynomialCommitmentScheme,
{
    reconstruction_size: usize,
    num_storage_nodes: usize,
    // ck: <P::SRS as StructuredReferenceString>::ProverParam,
    // vk: <P::SRS as StructuredReferenceString>::VerifierParam,
    ck: P::ProverParam,
    vk: P::VerifierParam,
    _phantom: PhantomData<T>, // TODO need this for trait bounds for PolynomialCommitmentScheme
}

impl<P, T> Advz<P, T>
where
    P: PolynomialCommitmentScheme,
{
    /// TODO we desperately need better error handling
    pub fn new(
        reconstruction_size: usize,
        num_storage_nodes: usize,
    ) -> Result<Self, PrimitivesError> {
        if num_storage_nodes < reconstruction_size {
            return Err(PrimitivesError::ParameterError(format!(
                "reconstruction_size {} exceeds num_storage_nodes {}",
                reconstruction_size, num_storage_nodes
            )));
        }
        let pp = P::gen_srs_for_testing(&mut test_rng(), reconstruction_size).unwrap();
        let (ck, vk) = P::trim(pp, reconstruction_size, None).unwrap();
        Ok(Self {
            reconstruction_size,
            num_storage_nodes,
            ck,
            vk,
            _phantom: PhantomData,
        })
    }
}

pub struct Share<P>
where
    P: PolynomialCommitmentScheme,
{
    // TODO: split `polynomial_commitments` from ShareData to avoid duplicate data?
    polynomial_commitments: Vec<P::Commitment>,

    id: usize,
    encoded_data: Vec<P::Evaluation>,

    // TODO for now do not aggregate proofs
    old_proofs: Vec<P::Proof>,
    _proof: P::Proof,
}

impl<P, T> VID for Advz<P, T>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
{
    // TODO sucks that I need `GenericArray` here. You'd think the `sha2` crate would export a type alias for hash outputs.
    type Commitment = GenericArray<u8, U32>;
    // type Commitment = sha2::Digest::Output;

    type Share = Share<P>;

    fn commit(&self, payload: &[u8]) -> Result<Self::Commitment, PrimitivesError> {
        let mut hasher = Sha256::new();

        // TODO perf: DenseUVPolynomial::from_coefficients_slice copies the slice.
        // We could avoid unnecessary mem copies if bytes_to_field_elements returned Vec<Vec<F>>
        let elems = bytes_to_field_elements(payload);
        for coeffs in elems.chunks(self.reconstruction_size) {
            let poly = DenseUVPolynomial::from_coefficients_slice(coeffs);
            let commitment = P::commit(&self.ck, &poly).unwrap();
            commitment.serialize_uncompressed(&mut hasher).unwrap();
        }

        Ok(hasher.finalize())
    }

    fn disperse(&self, payload: &[u8]) -> Result<Vec<Self::Share>, PrimitivesError> {
        // TODO eliminate fully qualified syntax?
        let field_elements: Vec<P::Evaluation> = bytes_to_field_elements(payload);

        // TODO temporary: one polynomial only
        // assert_eq!(field_elements.len(), self.reconstruction_size);

        self.disperse_field_elements(&field_elements)
    }

    fn verify_share(
        &self,
        share: &Self::Share,
    ) -> Result<(), jf_primitives::errors::PrimitivesError> {
        assert_eq!(share.encoded_data.len(), share.polynomial_commitments.len());

        let id: P::Point = P::Point::from(share.id as u64);

        // compute payload commitment from polynomial commitments
        let payload_commitment = {
            let mut hasher = Sha256::new();
            for comm in share.polynomial_commitments.iter() {
                comm.serialize_uncompressed(&mut hasher).unwrap();
            }
            hasher.finalize()
        };

        // compute my scalar
        let scalar: P::Evaluation = {
            let mut hasher = Sha256::new().chain_update(payload_commitment);
            let hasher_to_field =
                <DefaultFieldHasher<Sha256> as HashToField<P::Evaluation>>::new(&[1, 2, 3]); // TODO domain separator
            for eval in share.encoded_data.iter() {
                eval.serialize_uncompressed(&mut hasher).unwrap();
            }
            *hasher_to_field
                .hash_to_field(&hasher.finalize(), 1)
                .first()
                .unwrap()
        };

        // compute aggregate KZG commit and aggregate polynomial eval
        let aggregate_commit = P::Commitment::from(
            share
                .polynomial_commitments
                .iter()
                .rfold(T::zero(), |res, comm| {
                    (*comm.as_ref() * scalar + res).into()
                }),
        );
        let aggregate_value = share
            .encoded_data
            .iter()
            .rfold(P::Evaluation::zero(), |res, val| scalar * val + res);

        // verify aggregate proof
        let success = P::verify(
            &self.vk,
            &aggregate_commit,
            &id,
            &aggregate_value,
            &share._proof,
        )
        .unwrap();
        if !success {
            return Err(PrimitivesError::VerificationError(
                "aggregate verification failed".into(),
            ));
        }

        // TODO: OLD: verify all old proofs
        assert_eq!(share.encoded_data.len(), share.old_proofs.len());
        for ((data, proof), comm) in share
            .encoded_data
            .iter()
            .zip(share.old_proofs.iter())
            .zip(share.polynomial_commitments.iter())
        {
            let success = P::verify(&self.vk, &comm, &id, &data, &proof).unwrap();
            if !success {
                return Err(PrimitivesError::VerificationError(
                    "verification failed".into(),
                ));
            }
        }
        Ok(())
    }

    fn recover_payload(
        &self,
        shares: &[Self::Share],
    ) -> Result<Vec<u8>, jf_primitives::errors::PrimitivesError> {
        let field_elements = self.recover_field_elements(shares)?;
        Ok(bytes_from_field_elements(field_elements).unwrap())
    }
}

impl<P, T> Advz<P, T>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
{
    /// Compute shares to send to the storage nodes
    /// TODO take ownership of payload?
    pub fn disperse_field_elements(
        &self,
        payload: &[P::Evaluation],
    ) -> Result<Vec<<Advz<P, T> as VID>::Share>, PrimitivesError> {
        // - partition payload into polynomials
        // - compute commitments to those polynomials for result bcast
        // - evaluate those polynomials at 0..self.num_storage_nodes for result encoded data
        // - compute payload commitment as in VID::commit
        // TODO make this idiomatic and memory efficient
        let mut hasher = Sha256::new();
        let num_polys = (payload.len() - 1) / self.reconstruction_size + 1;
        let mut polys = Vec::with_capacity(num_polys);
        let mut commitments = Vec::with_capacity(num_polys);
        let mut storage_node_evals = vec![Vec::with_capacity(num_polys); self.num_storage_nodes];
        let mut old_storage_node_proofs =
            vec![Vec::with_capacity(num_polys); self.num_storage_nodes];
        for coeffs in payload.chunks(self.reconstruction_size) {
            let poly = DenseUVPolynomial::from_coefficients_slice(coeffs);
            let commitment = P::commit(&self.ck, &poly).unwrap();
            commitment.serialize_uncompressed(&mut hasher).unwrap();

            // TODO use batch_open_fk23
            for index in 0..self.num_storage_nodes {
                let id = P::Point::from((index + 1) as u64);
                let (proof, value) = P::open(&self.ck, &poly, &id).unwrap();
                storage_node_evals[index].push(value);
                old_storage_node_proofs[index].push(proof);
            }

            polys.push(poly);
            commitments.push(commitment);
        }
        let payload_commitment = hasher.finalize();

        // sanity checks
        assert_eq!(polys.len(), num_polys);
        assert_eq!(commitments.len(), num_polys);
        assert_eq!(storage_node_evals.len(), self.num_storage_nodes);
        assert_eq!(old_storage_node_proofs.len(), self.num_storage_nodes);
        for (v, p) in storage_node_evals
            .iter()
            .zip(old_storage_node_proofs.iter())
        {
            assert_eq!(v.len(), num_polys);
            assert_eq!(p.len(), num_polys);
        }

        // compute pseudorandom scalars t[j] = hash(commit(payload), poly_evals(j))
        // as per hotshot paper
        let hasher = Sha256::new().chain_update(payload_commitment);
        let hasher_to_field =
            <DefaultFieldHasher<Sha256> as HashToField<P::Evaluation>>::new(&[1, 2, 3]); // TODO domain separator
        let storage_node_scalars: Vec<P::Evaluation> = storage_node_evals
            .iter()
            .map(|evals| {
                let mut hasher = hasher.clone();
                for eval in evals.iter() {
                    eval.serialize_uncompressed(&mut hasher).unwrap();
                }

                // TODO
                // can't use from_random_bytes because it's fallible
                // (in what sense is it from "random" bytes?!)
                // HashToField does not expose an incremental API
                // So use a vanilla hasher and pipe hasher.finalize() through hash-to-field (sheesh!)
                *hasher_to_field
                    .hash_to_field(&hasher.finalize(), 1)
                    .first()
                    .unwrap()
            })
            .collect();

        // compute aggregate KZG proofs for each storage node j as per hotshot paper:
        // - compute pseudorandom combo polynomial p_j = sum_i t[j]^i * poly[i]
        // - compute KZG proof for p_j(j)
        Ok(storage_node_scalars
            .iter()
            .zip(storage_node_evals)
            .zip(old_storage_node_proofs) // TODO eliminate
            .enumerate()
            .map(|(index, ((scalar, evals), old_proofs))| {
                // Horner's method
                let storage_node_poly = polys.iter().rfold(P::Polynomial::zero(), |res, poly| {
                    // `Polynomial` does not impl `Mul` by scalar
                    // so we need to multiply each coeff by t
                    // TODO refactor into a mul_by_scalar function
                    // TODO refactor into a lin_combo function that works on anything that can be multiplied by a field element
                    res + P::Polynomial::from_coefficients_vec(
                        poly.coeffs().iter().map(|coeff| *scalar * coeff).collect(),
                    )
                });
                let id = P::Point::from((index + 1) as u64);
                let (proof, _value) = P::open(&self.ck, &storage_node_poly, &id).unwrap();
                Share {
                    polynomial_commitments: commitments.clone(),
                    id: index + 1,
                    encoded_data: evals,
                    old_proofs: old_proofs,
                    _proof: proof,
                }
            })
            .collect())
    }

    pub fn recover_field_elements(
        &self,
        shares: &[<Advz<P, T> as VID>::Share],
    ) -> Result<Vec<P::Evaluation>, PrimitivesError> {
        if shares.len() < self.reconstruction_size {
            return Err(PrimitivesError::ParameterError("not enough shares".into()));
        }

        // all shares must have equal data len
        let num_polys = shares
            .first()
            .ok_or(PrimitivesError::ParameterError("not enough shares".into()))?
            .encoded_data
            .len();
        if shares.iter().any(|s| s.encoded_data.len() != num_polys) {
            return Err(PrimitivesError::ParameterError(
                "shares do not have equal data lengths".into(),
            ));
        }

        for s in shares.iter() {
            self.verify_share(s)?;
        }

        // TODO check payload commitment

        let result_len = num_polys * self.reconstruction_size;
        let mut result = Vec::with_capacity(result_len);
        for i in 0..num_polys {
            let mut coeffs = ReedSolomonErasureCode::decode(
                shares.iter().map(|s| ReedSolomonErasureCodeShare {
                    index: s.id,
                    value: s.encoded_data[i],
                }),
                self.reconstruction_size,
            )?;
            result.append(&mut coeffs);
        }
        assert_eq!(result.len(), result_len);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::{Field, PrimeField};
    use ark_std::{
        println,
        rand::{seq::SliceRandom, RngCore},
        vec,
    };
    use jf_primitives::pcs::prelude::UnivariateKzgPCS;

    use super::*;
    type PCS = UnivariateKzgPCS<Bls12_381>;
    type G = <Bls12_381 as Pairing>::G1Affine;

    #[test]
    fn round_trip() {
        let vid_sizes = [(2, 3), (3, 9)];
        let byte_lens = [2, 16, 32, 47, 48, 49, 64, 100, 400];

        let mut rng = test_rng();

        println!(
            "modulus byte len: {}",
            (<<PCS as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

        for (reconstruction_size, num_storage_nodes) in vid_sizes {
            let vid = Advz::<PCS, G>::new(reconstruction_size, num_storage_nodes).unwrap();

            for len in byte_lens {
                println!(
                    "m: {} n: {} byte_len: {}",
                    reconstruction_size, num_storage_nodes, len
                );

                let mut bytes_random = vec![0u8; len];
                rng.fill_bytes(&mut bytes_random);

                let mut shares = vid.disperse(&bytes_random).unwrap();
                assert_eq!(shares.len(), num_storage_nodes);

                for s in shares.iter() {
                    vid.verify_share(s).unwrap();
                }

                // sample a random subset of shares with size reconstruction_size
                shares.shuffle(&mut rng);
                let shares = &shares[..reconstruction_size];

                let bytes_recovered = vid.recover_payload(shares).unwrap();
                assert_eq!(bytes_recovered, bytes_random);
            }
        }
    }

    #[test]
    fn basic_correctness_field_elements() {
        let vid = Advz::<PCS, G>::new(2, 3).unwrap();

        let field_elements = [
            <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme>::Evaluation::from(7u64),
            <UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme>::Evaluation::from(13u64),
        ];

        let shares = vid.disperse_field_elements(&field_elements).unwrap();
        assert_eq!(shares.len(), 3);

        for s in shares.iter() {
            vid.verify_share(s).unwrap();
        }

        // recover from a subset of shares
        let recovered_field_elements = vid.recover_field_elements(&shares[..2]).unwrap();
        assert_eq!(recovered_field_elements, field_elements);
    }

    #[test]
    fn commit_basic_correctness() {
        let mut rng = test_rng();
        let lengths = [2, 16, 32, 48, 63, 64, 65, 100, 200];
        let vid = Advz::<PCS, G>::new(2, 3).unwrap();

        for len in lengths {
            let mut random_bytes = vec![0u8; len];
            rng.fill_bytes(&mut random_bytes);

            vid.commit(&random_bytes).unwrap();
        }
    }
}
