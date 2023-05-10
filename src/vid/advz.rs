//! Implementation of Verifiable Information Dispersal (VID) from <https://eprint.iacr.org/2021/1500>.
//!
//! `advz` named for the authors Alhaddad-Duan-Varia-Zhang.

use super::{VidError, VidResult, VidScheme};
use anyhow::anyhow;
use ark_ec::AffineRepr;
use ark_ff::{
    fields::field_hashers::{DefaultFieldHasher, HashToField},
    Field,
};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::{
    borrow::Borrow,
    format,
    marker::PhantomData,
    ops::{Add, Mul},
    vec,
    vec::Vec,
    Zero,
};
use derivative::Derivative;
use digest::{crypto_common::Output, Digest, DynDigest};
use jf_primitives::{
    erasure_code::{
        reed_solomon_erasure::{ReedSolomonErasureCode, ReedSolomonErasureCodeShare},
        ErasureCode,
    },
    pcs::PolynomialCommitmentScheme,
};
use jf_utils::{bytes_from_field_elements, bytes_to_field_elements};

/// Concrete impl for [`VidScheme`].
pub struct Advz<P, T, H>
where
    P: PolynomialCommitmentScheme,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    // TODO uncomment after https://github.com/EspressoSystems/jellyfish/pull/231
    // ck: <P::SRS as StructuredReferenceString>::ProverParam,
    // vk: <P::SRS as StructuredReferenceString>::VerifierParam,
    ck: P::ProverParam,
    vk: P::VerifierParam,
    _phantom_t: PhantomData<T>, // needed for trait bounds
    _phantom_h: PhantomData<H>, // needed for trait bounds
}

impl<P, T, H> Advz<P, T, H>
where
    P: PolynomialCommitmentScheme,
{
    /// Return a new instance of `Self`.
    ///
    /// # Errors
    /// Return [`VidError::Argument`] if `num_storage_nodes < payload_chunk_size`.
    pub fn new(
        payload_chunk_size: usize,
        num_storage_nodes: usize,
        srs: impl Borrow<P::SRS>,
    ) -> VidResult<Self> {
        if num_storage_nodes < payload_chunk_size {
            return Err(VidError::Argument(format!(
                "payload_chunk_size {} exceeds num_storage_nodes {}",
                payload_chunk_size, num_storage_nodes
            )));
        }
        let (ck, vk) = P::trim(srs, payload_chunk_size, None)?;
        Ok(Self {
            payload_chunk_size,
            num_storage_nodes,
            ck,
            vk,
            _phantom_t: PhantomData,
            _phantom_h: PhantomData,
        })
    }
}

/// The [`VidScheme::StorageShare`] type for [`Advz`].
// Can't use `[#derive]` for `Share<P>` due to https://github.com/rust-lang/rust/issues/26925#issuecomment-1528025201
// Workaround: use `[#derivative]`
#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(Clone, Debug, Eq, PartialEq)]
pub struct Share<P>
where
    P: PolynomialCommitmentScheme,
{
    index: usize,
    evals: Vec<P::Evaluation>,
    aggregate_proof: P::Proof,
}

// Explanation of trait bounds:
// 1,2: `Polynomial` is univariate: domain (`Point`) same field as range (`Evaluation').
// 3,4: `Commitment` is (convertible to/from) an elliptic curve group in affine form.
// 5: `H` is a hasher
// TODO switch to `UnivariatePCS` after <https://github.com/EspressoSystems/jellyfish/pull/231>
impl<P, T, H> VidScheme for Advz<P, T, H>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>, // 1
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,                                      // 2
    P::Commitment: From<T> + AsRef<T>,                                                    // 3
    T: AffineRepr<ScalarField = P::Evaluation>,                                           // 4
    H: Digest + DynDigest + Default + Clone + Write,                                      // 5
{
    type Commitment = Output<H>;
    type StorageShare = Share<P>;
    type StorageCommon = Vec<P::Commitment>;

    fn commit(&self, payload: &[u8]) -> VidResult<Self::Commitment> {
        let mut hasher = H::new();

        // TODO perf: DenseUVPolynomial::from_coefficients_slice copies the slice.
        // We could avoid unnecessary mem copies if bytes_to_field_elements returned Vec<Vec<F>>
        let elems = bytes_to_field_elements(payload);
        for coeffs in elems.chunks(self.payload_chunk_size) {
            let poly = DenseUVPolynomial::from_coefficients_slice(coeffs);
            let commitment = P::commit(&self.ck, &poly)?;
            commitment.serialize_uncompressed(&mut hasher)?;
        }

        Ok(hasher.finalize())
    }

    fn dispersal_data(
        &self,
        payload: &[u8],
    ) -> VidResult<(Vec<Self::StorageShare>, Self::StorageCommon)> {
        self.dispersal_data_from_elems(&bytes_to_field_elements(payload))
    }

    fn verify_share(
        &self,
        share: &Self::StorageShare,
        common: &Self::StorageCommon,
    ) -> VidResult<Result<(), ()>> {
        if share.evals.len() != common.len() {
            return Err(VidError::Argument(format!(
                "(share eval, common) lengths differ ({},{})",
                share.evals.len(),
                common.len()
            )));
        }

        // compute payload commitment from polynomial commitments
        let payload_commitment = {
            let mut hasher = H::new();
            for comm in common.iter() {
                comm.serialize_uncompressed(&mut hasher)?;
            }
            hasher.finalize()
        };

        // compute my pseudorandom scalar
        let scalar: P::Evaluation = {
            let mut hasher = H::new().chain_update(payload_commitment);
            let hasher_to_field = <DefaultFieldHasher<H> as HashToField<P::Evaluation>>::new(
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

        // Compute aggregate polynomial [commitment|evaluation]
        // as a pseudorandom linear combo of [commitments|evaluations]
        // via evaluation of the polynomial whose coefficients are [commitments|evaluations]
        // and whose input point is the pseudorandom scalar.
        let aggregate_commit = P::Commitment::from(
            polynomial_eval(common.iter().map(|x| CurveMultiplier(x.as_ref())), scalar).into(),
        );
        let aggregate_value = polynomial_eval(share.evals.iter().map(FieldMultiplier), scalar);

        // verify aggregate proof
        Ok(P::verify(
            &self.vk,
            &aggregate_commit,
            &Self::index_to_point(share.index),
            &aggregate_value,
            &share.aggregate_proof,
        )?
        .then_some(())
        .ok_or(()))
    }

    fn recover_payload(
        &self,
        shares: &[Self::StorageShare],
        common: &Self::StorageCommon,
    ) -> VidResult<Vec<u8>> {
        Ok(bytes_from_field_elements(
            self.recover_elems(shares, common)?,
        ))
    }
}

impl<P, T, H> Advz<P, T, H>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
{
    /// Same as [`VidScheme::dispersal_data`] except `payload` is a slice of field elements.
    pub fn dispersal_data_from_elems(
        &self,
        payload: &[P::Evaluation],
    ) -> VidResult<(
        Vec<<Self as VidScheme>::StorageShare>,
        <Self as VidScheme>::StorageCommon,
    )> {
        let num_polys = (payload.len() - 1) / self.payload_chunk_size + 1;

        // polys: partition payload into polynomial coefficients
        // poly_commits: for result `common`
        // storage_node_evals: evaluate polys at many points for erasure-coded result shares
        // payload_commit: same as in Vid::commit
        let (polys, poly_commits, storage_node_evals, payload_commit) = {
            let mut hasher = H::new();
            let mut polys = Vec::with_capacity(num_polys);
            let mut poly_commits = Vec::with_capacity(num_polys);
            let mut storage_node_evals =
                vec![Vec::with_capacity(num_polys); self.num_storage_nodes];
            for coeffs in payload.chunks(self.payload_chunk_size) {
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
        let hasher = H::new().chain_update(payload_commit);
        let hasher_to_field =
            <DefaultFieldHasher<H> as HashToField<P::Evaluation>>::new(HASH_TO_FIELD_DOMAIN_SEP);
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
        // -  Compute aggregate polynomial
        //    as a pseudorandom linear combo of payload polynomials
        //    via evaluation of the polynomial whose coefficients are payload polynomials
        //    and whose input point is the pseudorandom scalar.
        // - Compute aggregate proof for the aggregate polynomial evaluated at j.
        Ok((
            storage_node_scalars
                .iter()
                .zip(storage_node_evals)
                .enumerate()
                .map(|(index, (scalar, evals))| {
                    let aggregate_poly =
                        polynomial_eval(polys.iter().map(PolynomialMultiplier), scalar);
                    let (aggregate_proof, _value) =
                        P::open(&self.ck, &aggregate_poly, &Self::index_to_point(index))?;
                    Ok(Share {
                        index,
                        evals,
                        aggregate_proof,
                    })
                })
                .collect::<Result<_, anyhow::Error>>()?,
            poly_commits,
        ))
    }

    /// Same as [`VidScheme::recover_payload`] except returns a [`Vec`] of field elements.
    pub fn recover_elems(
        &self,
        shares: &[<Self as VidScheme>::StorageShare],
        _common: &<Self as VidScheme>::StorageCommon,
    ) -> VidResult<Vec<P::Evaluation>> {
        if shares.len() < self.payload_chunk_size {
            return Err(VidError::Argument(format!(
                "not enough shares {}, expected at least {}",
                shares.len(),
                self.payload_chunk_size
            )));
        }

        // all shares must have equal evals len
        let num_polys = shares
            .first()
            .ok_or_else(|| VidError::Argument("shares is empty".into()))?
            .evals
            .len();
        if let Some((index, share)) = shares
            .iter()
            .enumerate()
            .find(|(_, s)| s.evals.len() != num_polys)
        {
            return Err(VidError::Argument(format!(
                "shares do not have equal evals lengths: share {} len {}, share {} len {}",
                0,
                num_polys,
                index,
                share.evals.len()
            )));
        }

        let result_len = num_polys * self.payload_chunk_size;
        let mut result = Vec::with_capacity(result_len);
        for i in 0..num_polys {
            let mut coeffs = ReedSolomonErasureCode::decode(
                shares.iter().map(|s| ReedSolomonErasureCodeShare {
                    index: s.index + 1, // 1-based index for ReedSolomonErasureCodeShare
                    value: s.evals[i],
                }),
                self.payload_chunk_size,
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

// `From` impls for `VidError`
//
// # Goal
// `anyhow::Error` has the property that `?` magically coerces the error into `anyhow::Error`.
// I want the same property for `VidError`.
// I don't know how to achieve this without the following boilerplate.
//
// # Boilerplate
// I want to coerce any error `E` into `VidError::Internal` similar to `anyhow::Error`.
// Unfortunately, I need to manually impl `From<E> for VidError` for each `E`.
// Can't do a generic impl because it conflicts with `impl<T> From<T> for T` in core.
impl From<jf_primitives::errors::PrimitivesError> for VidError {
    fn from(value: jf_primitives::errors::PrimitivesError) -> Self {
        Self::Internal(value.into())
    }
}

impl From<jf_primitives::pcs::prelude::PCSError> for VidError {
    fn from(value: jf_primitives::pcs::prelude::PCSError) -> Self {
        Self::Internal(value.into())
    }
}

impl From<ark_serialize::SerializationError> for VidError {
    fn from(value: ark_serialize::SerializationError) -> Self {
        Self::Internal(value.into())
    }
}

/// Evaluate a generalized polynomial at a given point using Horner's method.
///
/// Coefficients can be anything that can be multiplied by a point
/// and such that the result of such multiplications can be added.
fn polynomial_eval<U, F, I>(coeffs: I, point: impl Borrow<F>) -> U
where
    I: IntoIterator,
    I::Item: for<'a> Mul<&'a F, Output = U>,
    U: Add<Output = U> + Zero,
{
    coeffs
        .into_iter()
        .fold(U::zero(), |res, coeff| coeff * point.borrow() + res)
}

struct FieldMultiplier<'a, F>(&'a F);

/// Arkworks does not provide (&F,&F) multiplication
impl<F> Mul<&F> for FieldMultiplier<'_, F>
where
    F: Field,
{
    type Output = F;

    fn mul(self, rhs: &F) -> Self::Output {
        *self.0 * rhs
    }
}

/// Arkworks does not provide (&C,&F) multiplication
struct CurveMultiplier<'a, C>(&'a C);

impl<C, F> Mul<&F> for CurveMultiplier<'_, C>
where
    C: AffineRepr<ScalarField = F>,
{
    type Output = C::Group;

    fn mul(self, rhs: &F) -> Self::Output {
        *self.0 * rhs
    }
}

/// Arkworks does not provide (&P,&F) multiplication
struct PolynomialMultiplier<'a, P>(&'a P);

impl<P, F> Mul<&F> for PolynomialMultiplier<'_, P>
where
    P: DenseUVPolynomial<F>,
    F: Field,
{
    type Output = P;

    fn mul(self, rhs: &F) -> Self::Output {
        // `Polynomial` does not impl `Mul` by scalar
        // so we need to multiply each coeff by `rhs`
        P::from_coefficients_vec(self.0.coeffs().iter().map(|coeff| *coeff * rhs).collect())
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
    use jf_utils::test_rng;
    use sha2::Sha256;

    use super::*;
    type Pcs = UnivariateKzgPCS<Bls12_381>;
    type G = <Bls12_381 as Pairing>::G1Affine;
    type H = Sha256;

    #[test]
    fn round_trip() {
        let vid_sizes = [(2, 3), (3, 9)];
        let byte_lens = [2, 16, 32, 47, 48, 49, 64, 100, 400];

        let mut rng = test_rng();
        let srs = Pcs::gen_srs_for_testing(
            &mut test_rng(),
            vid_sizes.iter().max_by_key(|v| v.0).unwrap().0,
        )
        .unwrap();

        println!(
            "modulus byte len: {}",
            (<<Pcs as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

        for (payload_chunk_size, num_storage_nodes) in vid_sizes {
            let vid = Advz::<Pcs, G, H>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap();

            for len in byte_lens {
                println!(
                    "m: {} n: {} byte_len: {}",
                    payload_chunk_size, num_storage_nodes, len
                );

                let mut bytes_random = vec![0u8; len];
                rng.fill_bytes(&mut bytes_random);

                let (mut shares, common) = vid.dispersal_data(&bytes_random).unwrap();
                assert_eq!(shares.len(), num_storage_nodes);

                for share in shares.iter() {
                    vid.verify_share(share, &common).unwrap().unwrap();
                }

                // sample a random subset of shares with size payload_chunk_size
                shares.shuffle(&mut rng);

                // give minimum number of shares for recovery
                let bytes_recovered = vid
                    .recover_payload(&shares[..payload_chunk_size], &common)
                    .unwrap();
                assert_eq!(bytes_recovered, bytes_random);

                // give an intermediate number of shares for recovery
                let intermediate_num_shares = (payload_chunk_size + num_storage_nodes) / 2;
                let bytes_recovered = vid
                    .recover_payload(&shares[..intermediate_num_shares], &common)
                    .unwrap();
                assert_eq!(bytes_recovered, bytes_random);

                // give all shares for recovery
                let bytes_recovered = vid.recover_payload(&shares, &common).unwrap();
                assert_eq!(bytes_recovered, bytes_random);
            }
        }
    }

    #[test]
    fn commit_infallibility() {
        let vid_sizes = [(3, 9)];
        let byte_lens = [2, 32, 500];

        let mut rng = test_rng();
        let srs = Pcs::gen_srs_for_testing(
            &mut test_rng(),
            vid_sizes.iter().max_by_key(|v| v.0).unwrap().0,
        )
        .unwrap();

        for (payload_chunk_size, num_storage_nodes) in vid_sizes {
            let vid = Advz::<Pcs, G, H>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap();

            for len in byte_lens {
                let mut random_bytes = vec![0u8; len];
                rng.fill_bytes(&mut random_bytes);

                vid.commit(&random_bytes).unwrap();
            }
        }
    }
}
