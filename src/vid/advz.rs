//! Implementation of Verifiable Information Dispersal (VID) from https://eprint.iacr.org/2021/1500
//! `Avdz` named for the authors Alhaddad-Duan-Varia-Zhang

use super::{VIDError, VIDResult, VID};
use anyhow::anyhow;
use ark_ec::AffineRepr;
use ark_ff::fields::field_hashers::{DefaultFieldHasher, HashToField};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_serialize::CanonicalSerialize;
use ark_std::{format, marker::PhantomData, vec, vec::Vec, Zero};

use jf_primitives::{
    erasure_code::{
        reed_solomon_erasure::{ReedSolomonErasureCode, ReedSolomonErasureCodeShare},
        ErasureCode,
    },
    pcs::PolynomialCommitmentScheme,
};
use jf_utils::test_rng;
use jf_utils::{bytes_from_field_elements, bytes_to_field_elements};
use sha2::{digest::crypto_common::Output, Digest, Sha256};

pub struct Advz<P, T>
where
    P: PolynomialCommitmentScheme,
{
    reconstruction_size: usize,
    num_storage_nodes: usize,
    // TODO uncomment after https://github.com/EspressoSystems/jellyfish/pull/231
    // ck: <P::SRS as StructuredReferenceString>::ProverParam,
    // vk: <P::SRS as StructuredReferenceString>::VerifierParam,
    ck: P::ProverParam,
    vk: P::VerifierParam,
    _phantom: PhantomData<T>, // needed for trait bounds for `PolynomialCommitmentScheme`
}

impl<P, T> Advz<P, T>
where
    P: PolynomialCommitmentScheme,
{
    pub fn new(reconstruction_size: usize, num_storage_nodes: usize) -> VIDResult<Self> {
        if num_storage_nodes < reconstruction_size {
            return Err(VIDError::Argument(format!(
                "reconstruction_size {} exceeds num_storage_nodes {}",
                reconstruction_size, num_storage_nodes
            )));
        }
        let pp = P::gen_srs_for_testing(&mut test_rng(), reconstruction_size)?;
        let (ck, vk) = P::trim(pp, reconstruction_size, None)?;
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
    index: usize,
    evals: Vec<P::Evaluation>,
    proof: P::Proof,
}

/// Explanation of trait bounds:
/// 1,2: `Polynomial` is univariate: domain (`Point`) same field as range (`Evaluation').
/// 3,4: `Commitment` is (convertible to/from) an elliptic curve group in affine form.
/// TODO switch to `UnivariatePCS` after https://github.com/EspressoSystems/jellyfish/pull/231
impl<P, T> VID for Advz<P, T>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>, // 1
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,                                      // 2
    P::Commitment: From<T> + AsRef<T>,                                                    // 3
    T: AffineRepr<ScalarField = P::Evaluation>,                                           // 4
{
    type Commitment = Output<sha2::Sha256>; // Sha256 hash
    type Share = Share<P>;
    type Bcast = Vec<P::Commitment>;

    fn commit(&self, payload: &[u8]) -> VIDResult<Self::Commitment> {
        let mut hasher = Sha256::new();

        // TODO perf: DenseUVPolynomial::from_coefficients_slice copies the slice.
        // We could avoid unnecessary mem copies if bytes_to_field_elements returned Vec<Vec<F>>
        let elems = bytes_to_field_elements(payload);
        for coeffs in elems.chunks(self.reconstruction_size) {
            let poly = DenseUVPolynomial::from_coefficients_slice(coeffs);
            let commitment = P::commit(&self.ck, &poly)?;
            commitment.serialize_uncompressed(&mut hasher)?;
        }

        Ok(hasher.finalize())
    }

    fn disperse(&self, payload: &[u8]) -> VIDResult<(Vec<Self::Share>, Self::Bcast)> {
        self.disperse_elems(&bytes_to_field_elements(payload))
    }

    fn verify_share(&self, share: &Self::Share, bcast: &Self::Bcast) -> VIDResult<Result<(), ()>> {
        assert_eq!(share.evals.len(), bcast.len());

        // compute payload commitment from polynomial commitments
        let payload_commitment = {
            let mut hasher = Sha256::new();
            for comm in bcast.iter() {
                comm.serialize_uncompressed(&mut hasher)?;
            }
            hasher.finalize()
        };

        // compute my scalar
        let scalar: P::Evaluation = {
            let mut hasher = Sha256::new().chain_update(payload_commitment);
            let hasher_to_field = <DefaultFieldHasher<Sha256> as HashToField<P::Evaluation>>::new(
                HASH_TO_FIELD_DOMAIN_SEP,
            );
            for eval in share.evals.iter() {
                eval.serialize_uncompressed(&mut hasher)?;
            }
            *hasher_to_field
                .hash_to_field(&hasher.finalize(), 1)
                .first()
                .ok_or_else(|| anyhow!("hash_to_field output is empty"))?
        };

        // compute aggregate KZG commit and aggregate polynomial eval
        // see "TODO rfold:" comment
        let aggregate_commit = P::Commitment::from(
            bcast
                .iter()
                .rfold(T::Group::zero(), |res, comm| *comm.as_ref() * scalar + res) // group ops in projective form
                .into(), // final conversion to affine form
        );
        let aggregate_value = share
            .evals
            .iter()
            .rfold(P::Evaluation::zero(), |res, val| scalar * val + res);

        // verify aggregate proof
        Ok(P::verify(
            &self.vk,
            &aggregate_commit,
            &Self::index_to_point(share.index),
            &aggregate_value,
            &share.proof,
        )?
        .then_some(())
        .ok_or(()))
    }

    fn recover_payload(&self, shares: &[Self::Share], bcast: &Self::Bcast) -> VIDResult<Vec<u8>> {
        Ok(bytes_from_field_elements(
            self.recover_elems(shares, bcast)?,
        ))
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
    pub fn disperse_elems(
        &self,
        payload: &[P::Evaluation],
    ) -> VIDResult<(Vec<<Self as VID>::Share>, <Self as VID>::Bcast)> {
        let num_polys = (payload.len() - 1) / self.reconstruction_size + 1;

        // polys: partition payload into polynomial coefficients
        // poly_commits: for result bcast
        // storage_node_evals: evaluate polys at many points for erasure-coded result shares
        // payload_commit: same as in VID::commit
        let (polys, poly_commits, storage_node_evals, payload_commit) = {
            let mut hasher = Sha256::new();
            let mut polys = Vec::with_capacity(num_polys);
            let mut poly_commits = Vec::with_capacity(num_polys);
            let mut storage_node_evals =
                vec![Vec::with_capacity(num_polys); self.num_storage_nodes];
            for coeffs in payload.chunks(self.reconstruction_size) {
                let poly = DenseUVPolynomial::from_coefficients_slice(coeffs);
                let poly_commit = P::commit(&self.ck, &poly)?;
                poly_commit.serialize_uncompressed(&mut hasher)?;

                // TODO use batch_open_fk23
                for (index, eval) in storage_node_evals.iter_mut().enumerate() {
                    eval.push(poly.evaluate(&Self::index_to_point(index)));
                }

                polys.push(poly);
                poly_commits.push(poly_commit);
            }

            // sanity checks
            assert_eq!(polys.len(), num_polys);
            assert_eq!(poly_commits.len(), num_polys);
            assert_eq!(storage_node_evals.len(), self.num_storage_nodes);
            for v in storage_node_evals.iter() {
                assert_eq!(v.len(), num_polys);
            }

            (polys, poly_commits, storage_node_evals, hasher.finalize())
        };

        // storage_node_scalars[j]: hash(payload_commit, poly_evals(j))
        //   used for pseudorandom linear combos as per hotshot paper.
        //
        // Notes on hash-to-field:
        // - Can't use `Field::from_random_bytes` because it's fallible
        //   (in what sense is it from "random" bytes?!)
        // - `HashToField` does not expose an incremental API (ie. `update`)
        //   so use an ordinary hasher and pipe `hasher.finalize()` through `hash_to_field` (sheesh!)
        let hasher = Sha256::new().chain_update(payload_commit);
        let hasher_to_field = <DefaultFieldHasher<Sha256> as HashToField<P::Evaluation>>::new(
            HASH_TO_FIELD_DOMAIN_SEP,
        );
        let storage_node_scalars: Vec<P::Evaluation> = storage_node_evals
            .iter()
            .map(|evals| {
                let mut hasher = hasher.clone();
                for eval in evals.iter() {
                    eval.serialize_uncompressed(&mut hasher)?;
                }
                Ok(*(hasher_to_field
                    .hash_to_field(&hasher.finalize(), 1)
                    .first()
                    .ok_or_else(|| anyhow!("hash_to_field output is empty"))?))
            })
            .collect::<Result<_, anyhow::Error>>()?;

        // For each storage node j as per hotshot paper:
        // - Compute pseudorandom storage_node_poly[j]: sum_i storage_node_scalars[j]^i * polys[i]
        // - Compute aggregate proof for storage_node_poly[j](j)
        Ok((
            storage_node_scalars
                .iter()
                .zip(storage_node_evals)
                .enumerate()
                .map(|(index, (scalar, evals))| {
                    // Horner's method
                    let storage_node_poly =
                        // see "TODO rfold:" comment
                        polys.iter().rfold(P::Polynomial::zero(), |res, poly| {
                            // `Polynomial` does not impl `Mul` by scalar
                            // so we need to multiply each coeff by t
                            res + P::Polynomial::from_coefficients_vec(
                                poly.coeffs().iter().map(|coeff| *scalar * coeff).collect(),
                            )
                        });
                    let (proof, _value) =
                        P::open(&self.ck, &storage_node_poly, &Self::index_to_point(index))?;
                    Ok(Share {
                        index,
                        evals,
                        proof,
                    })
                })
                .collect::<Result<_, anyhow::Error>>()?,
            poly_commits,
        ))
    }

    pub fn recover_elems(
        &self,
        shares: &[<Self as VID>::Share],
        _bcast: &<Self as VID>::Bcast,
    ) -> VIDResult<Vec<P::Evaluation>> {
        if shares.len() < self.reconstruction_size {
            return Err(VIDError::Argument(format!(
                "not enough shares {}, expected at least {}",
                shares.len(),
                self.reconstruction_size
            )));
        }

        // all shares must have equal evals len
        let num_polys = shares
            .first()
            .ok_or_else(|| VIDError::Argument("shares is empty".into()))?
            .evals
            .len();
        if let Some((index, share)) = shares
            .iter()
            .enumerate()
            .find(|(_, s)| s.evals.len() != num_polys)
        {
            return Err(VIDError::Argument(format!(
                "shares do not have equal evals lengths: share {} len {}, share {} len {}",
                0,
                num_polys,
                index,
                share.evals.len()
            )));
        }

        let result_len = num_polys * self.reconstruction_size;
        let mut result = Vec::with_capacity(result_len);
        for i in 0..num_polys {
            let mut coeffs = ReedSolomonErasureCode::decode(
                shares.iter().map(|s| ReedSolomonErasureCodeShare {
                    index: s.index + 1, // 1-based index for ReedSolomonErasureCodeShare
                    value: s.evals[i],
                }),
                self.reconstruction_size,
            )?;
            result.append(&mut coeffs);
        }
        assert_eq!(result.len(), result_len);
        Ok(result)
    }

    fn index_to_point(index: usize) -> P::Point {
        P::Point::from((index + 1) as u64)
    }
}

const HASH_TO_FIELD_DOMAIN_SEP: &[u8; 4] = b"rick";

/// # Goal:
/// `anyhow::Error` has the property that `?` magically coerces the error into `anyhow::Error`.
/// I want the same property for `VIDError`.
/// I don't know how to achieve this without the following boilerplate.
///
/// # Boilerplate:
/// I want to coerce any error `E` into `VIDError::Internal` similar to `anyhow::Error`.
/// Unfortunately, I need to manually impl `From<E> for VIDError` for each `E`.
/// Can't do a generic impl because it conflicts with `impl<T> From<T> for T` in core.
impl From<jf_primitives::errors::PrimitivesError> for VIDError {
    fn from(value: jf_primitives::errors::PrimitivesError) -> Self {
        Self::Internal(value.into())
    }
}

impl From<jf_primitives::pcs::prelude::PCSError> for VIDError {
    fn from(value: jf_primitives::pcs::prelude::PCSError) -> Self {
        Self::Internal(value.into())
    }
}

impl From<ark_serialize::SerializationError> for VIDError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        Self::Internal(value.into())
    }
}

// TODO rfold: Use of `rfold` in this source file should be refactored into a
// function that works on anything that can be multiplied by a field element.
// Unfortunately, the concrete arkworks types involved in each of our uses of
// `rfold` offer a different subset of the needed traits `Mul`, `Add`, etc.
// Thus, any attempt to refactor would not improve code readability or
// maintainability. :sad:

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

                let (mut shares, bcast) = vid.disperse(&bytes_random).unwrap();
                assert_eq!(shares.len(), num_storage_nodes);

                for share in shares.iter() {
                    vid.verify_share(share, &bcast).unwrap().unwrap();
                }

                // sample a random subset of shares with size reconstruction_size
                shares.shuffle(&mut rng);
                let shares = &shares[..reconstruction_size];

                let bytes_recovered = vid.recover_payload(shares, &bcast).unwrap();
                assert_eq!(bytes_recovered, bytes_random);
            }
        }
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
