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
    pcs::{PolynomialCommitmentScheme, StructuredReferenceString},
};
use jf_utils::{bytes_from_field_elements, bytes_to_field_elements};

/// Context data for the ADVZ VID scheme.
///
/// This struct is a concrete impl for [`VidScheme`].
/// Generic parameters `T`, `H` are needed only to express trait bounds in the impl for [`VidScheme`].
/// - `H` is a hasher.
/// - `T` is a group.
pub struct Advz<P, T, H>
where
    P: PolynomialCommitmentScheme,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    ck: <P::SRS as StructuredReferenceString>::ProverParam,
    vk: <P::SRS as StructuredReferenceString>::VerifierParam,
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
    use super::{VidError::Argument, *};

    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_std::{rand::RngCore, vec};
    use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
    use sha2::Sha256;

    type Pcs = UnivariateKzgPCS<Bls12_381>;
    type G = <Bls12_381 as Pairing>::G1Affine;
    type H = Sha256;

    #[test]
    fn sad_path_verify_share_corrupt_share() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        for share in shares {
            // missing share eval
            let share_missing_eval = Share {
                evals: share.evals[1..].to_vec(),
                ..share.clone()
            };
            assert_arg_err(
                advz.verify_share(&share_missing_eval, &common),
                "1 missing share should be arg error",
            );

            // bad index
            let share_bad_index = Share {
                index: share.index + 5,
                ..share.clone()
            };
            advz.verify_share(&share_bad_index, &common)
                .unwrap()
                .expect_err("bad share index should fail verification");
        }
    }

    #[test]
    fn sad_path_verify_share_corrupt_commit() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        // missing commit
        let common_missing_item = common[1..].to_vec();
        assert_arg_err(
            advz.verify_share(&shares[0], &common_missing_item),
            "1 missing commit should be arg error",
        );

        // 1 corrupt commit
        let common_1_corruption = {
            let mut corrupted = common; // common.clone()
            corrupted[0] = G::zero().into();
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_corruption)
            .unwrap()
            .expect_err("1 corrupt commit should fail verification");
    }

    #[test]
    fn sad_path_verify_share_corrupt_share_and_commit() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        for mut share in shares {
            let mut common_missing_items = common.clone();

            while !common_missing_items.is_empty() {
                common_missing_items.pop();
                share.evals.pop();

                // equal amounts of share evals, common items
                advz.verify_share(&share, &common_missing_items)
                    .unwrap()
                    .unwrap_err();
            }

            // ensure we tested the empty shares edge case
            assert!(share.evals.is_empty() && common_missing_items.is_empty())
        }
    }

    #[test]
    fn sad_path_recover_payload_corrupt_shares() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        // unequal share eval lengths
        let mut shares_missing_evals = shares.clone();
        for i in 0..shares_missing_evals.len() - 1 {
            shares_missing_evals[i].evals.pop();
            assert_arg_err(
                advz.recover_payload(&shares_missing_evals, &common),
                format!("{} shares missing 1 eval should be arg error", i + 1).as_str(),
            );
        }

        // 1 eval missing from all shares
        shares_missing_evals.last_mut().unwrap().evals.pop();
        let bytes_recovered = advz
            .recover_payload(&shares_missing_evals, &common)
            .expect("recover_payload should succeed when shares have equal eval lengths");
        assert_ne!(bytes_recovered, bytes_random);

        // corrupt indices
        let mut shares_bad_indices = shares; // shares.clone()
        for share in &mut shares_bad_indices {
            share.index += 5;
            let bytes_recovered = advz
                .recover_payload(&shares_missing_evals, &common)
                .expect("recover_payload should succeed for any share indices");
            assert_ne!(bytes_recovered, bytes_random);
        }
    }

    /// Routine initialization tasks.
    ///
    /// Returns the following tuple:
    /// 1. An initialized [`Advz`] instance.
    /// 2. A `Vec<u8>` filled with random bytes.
    fn avdz_init() -> (Advz<Pcs, G, H>, Vec<u8>) {
        let (payload_chunk_size, num_storage_nodes) = (3, 5);
        let mut rng = jf_utils::test_rng();
        let srs = Pcs::gen_srs_for_testing(&mut rng, payload_chunk_size).unwrap();
        let advz = Advz::<Pcs, G, H>::new(payload_chunk_size, num_storage_nodes, srs).unwrap();

        let mut bytes_random = vec![0u8; 4000];
        rng.fill_bytes(&mut bytes_random);

        (advz, bytes_random)
    }

    /// Convenience wrapper to assert [`VidError::Argument`] return value.
    fn assert_arg_err<T>(res: VidResult<T>, msg: &str) {
        assert!(matches!(res, Err(Argument(_))), "{}", msg);
    }
}
