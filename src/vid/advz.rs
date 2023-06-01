//! Implementation of Verifiable Information Dispersal (VID) from <https://eprint.iacr.org/2021/1500>.
//!
//! `advz` named for the authors Alhaddad-Duan-Varia-Zhang.

use super::{VidError, VidResult, VidScheme};
use anyhow::anyhow;
use ark_ec::{pairing::Pairing, AffineRepr};
use ark_ff::{
    fields::field_hashers::{DefaultFieldHasher, HashToField},
    Field,
};
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Write};
use ark_std::{
    borrow::Borrow,
    fmt::Debug,
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
    merkle_tree::{hasher::HasherMerkleTree, MerkleCommitment, MerkleTreeScheme},
    pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme, StructuredReferenceString},
};
use jf_utils::{bytes_from_field_elements, bytes_to_field_elements, canonical};
use serde::{Deserialize, Serialize};

/// The [ADVZ VID scheme](https://eprint.iacr.org/2021/1500), a concrete impl for [`VidScheme`].
///
/// - `H` is any [`Digest`]-compatible hash function
/// - `E` is any [`Pairing`]
pub type Advz<E, H> = GenericAdvz<
    UnivariateKzgPCS<E>,
    <E as Pairing>::G1Affine,
    H,
    HasherMerkleTree<H, Vec<<UnivariateKzgPCS<E> as PolynomialCommitmentScheme>::Evaluation>>,
>;

/// Like [`Advz`] except with more abstraction.
///
/// - `P` is a [`PolynomialCommitmentScheme`]
/// - `T` is the group type underlying [`PolynomialCommitmentScheme::Commitment`]
/// - `H` is a [`Digest`]-compatible hash function.
/// - `V` is a [`MerkleTreeScheme`], though any vector commitment would suffice
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derive(Clone, Debug, Default, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct GenericAdvz<P, T, H, V>
where
    P: PolynomialCommitmentScheme,
{
    payload_chunk_size: usize,
    num_storage_nodes: usize,
    ck: <P::SRS as StructuredReferenceString>::ProverParam,
    vk: <P::SRS as StructuredReferenceString>::VerifierParam,
    _phantom_t: PhantomData<T>, // needed for trait bounds
    _phantom_h: PhantomData<H>, // needed for trait bounds
    _phantom_v: PhantomData<V>, // needed for trait bounds
}

impl<P, T, H, V> GenericAdvz<P, T, H, V>
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
            _phantom_v: PhantomData,
        })
    }
}

/// The [`VidScheme::StorageShare`] type for [`Advz`].
#[derive(Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug)]
pub struct Share<P, V>
where
    P: PolynomialCommitmentScheme,
    V: MerkleTreeScheme,
    V::MembershipProof: Sync + Debug, // TODO https://github.com/EspressoSystems/jellyfish/issues/253
{
    index: usize,
    #[serde(with = "canonical")]
    evals: Vec<P::Evaluation>,
    #[serde(with = "canonical")]
    aggregate_proof: P::Proof,
    evals_proof: V::MembershipProof,
}

/// The [`VidScheme::StorageCommon`] type for [`Advz`].
#[derive(CanonicalSerialize, CanonicalDeserialize, Derivative, Deserialize, Serialize)]
// TODO https://github.com/EspressoSystems/jellyfish/issues/253
// #[derivative(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[derivative(Clone, Debug, Default, Eq, PartialEq)]
pub struct Common<P, V>
where
    P: PolynomialCommitmentScheme,
    V: MerkleTreeScheme,
{
    #[serde(with = "canonical")]
    poly_commits: Vec<P::Commitment>,
    all_evals_digest: V::NodeValue,
}

// We take great pains to maintain abstraction by relying only on traits and not concrete impls of those traits.
// Explanation of trait bounds:
// 1,2: `Polynomial` is univariate: domain (`Point`) same field as range (`Evaluation').
// 3,4: `Commitment` is (convertible to/from) an elliptic curve group in affine form.
// 5: `H` is a hasher
impl<P, T, H, V> VidScheme for GenericAdvz<P, T, H, V>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>, // 1
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,                                      // 2
    P::Commitment: From<T> + AsRef<T>,                                                    // 3
    T: AffineRepr<ScalarField = P::Evaluation>,                                           // 4
    H: Digest + DynDigest + Default + Clone + Write,                                      // 5
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug, // TODO https://github.com/EspressoSystems/jellyfish/issues/253
    V::Index: From<u64>,
{
    type Commitment = Output<H>;
    type StorageShare = Share<P, V>;
    type StorageCommon = Common<P, V>;

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
        if share.evals.len() != common.poly_commits.len() {
            return Err(VidError::Argument(format!(
                "(share eval, common poly commit) lengths differ ({},{})",
                share.evals.len(),
                common.poly_commits.len()
            )));
        }

        // verify eval proof
        if V::verify(
            common.all_evals_digest,
            &V::Index::from(share.index as u64),
            &share.evals_proof,
        )?
        .is_err()
        {
            return Ok(Err(()));
        }

        let pseudorandom_scalar = Self::pseudorandom_scalar(common)?;

        // Compute aggregate polynomial [commitment|evaluation]
        // as a pseudorandom linear combo of [commitments|evaluations]
        // via evaluation of the polynomial whose coefficients are [commitments|evaluations]
        // and whose input point is the pseudorandom scalar.
        let aggregate_poly_commit = P::Commitment::from(
            polynomial_eval(
                common
                    .poly_commits
                    .iter()
                    .map(|x| CurveMultiplier(x.as_ref())),
                pseudorandom_scalar,
            )
            .into(),
        );
        let aggregate_eval =
            polynomial_eval(share.evals.iter().map(FieldMultiplier), pseudorandom_scalar);

        // verify aggregate proof
        Ok(P::verify(
            &self.vk,
            &aggregate_poly_commit,
            &Self::index_to_point(share.index),
            &aggregate_eval,
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

impl<P, T, H, V> GenericAdvz<P, T, H, V>
where
    P: PolynomialCommitmentScheme<Point = <P as PolynomialCommitmentScheme>::Evaluation>,
    P::Polynomial: DenseUVPolynomial<P::Evaluation>,
    P::Commitment: From<T> + AsRef<T>,
    T: AffineRepr<ScalarField = P::Evaluation>,
    H: Digest + DynDigest + Default + Clone + Write,
    V: MerkleTreeScheme<Element = Vec<P::Evaluation>>,
    V::MembershipProof: Sync + Debug, // TODO https://github.com/EspressoSystems/jellyfish/issues/253
    V::Index: From<u64>,
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

        // partition payload into polynomial coefficients
        let polys: Vec<P::Polynomial> = payload
            .chunks(self.payload_chunk_size)
            .map(DenseUVPolynomial::from_coefficients_slice)
            .collect();

        // evaluate polynomials
        let all_evals = {
            let mut all_evals = vec![Vec::with_capacity(num_polys); self.num_storage_nodes];

            // TODO https://github.com/EspressoSystems/hotshot-primitives/issues/19
            for poly in polys.iter() {
                for (index, evals) in all_evals.iter_mut().enumerate() {
                    evals.push(poly.evaluate(&Self::index_to_point(index)));
                }
            }

            // sanity checks
            assert_eq!(all_evals.len(), self.num_storage_nodes);
            for evals in all_evals.iter() {
                assert_eq!(evals.len(), num_polys);
            }

            all_evals
        };

        // vector commitment to polynomial evaluations
        // TODO why do I need to compute the height of the merkle tree?
        let height: usize = all_evals
            .len()
            .checked_ilog(V::ARITY)
            .ok_or_else(|| {
                VidError::Argument(format!(
                    "num_storage_nodes {} log base {} invalid",
                    all_evals.len(),
                    V::ARITY
                ))
            })?
            .try_into()
            .expect("num_storage_nodes log base arity should fit into usize");
        let height = height + 1; // avoid fully qualified syntax for try_into()
        let all_evals_commit = V::from_elems(height, &all_evals)?;

        // common data
        let common = Common {
            poly_commits: polys
                .iter()
                .map(|poly| P::commit(&self.ck, poly))
                .collect::<Result<_, _>>()?,
            all_evals_digest: all_evals_commit.commitment().digest(),
        };

        // pseudorandom scalar
        let pseudorandom_scalar = Self::pseudorandom_scalar(&common)?;

        // Compute aggregate polynomial
        // as a pseudorandom linear combo of polynomials
        // via evaluation of the polynomial whose coefficients are polynomials
        // and whose input point is the pseudorandom scalar.
        let aggregate_poly =
            polynomial_eval(polys.iter().map(PolynomialMultiplier), pseudorandom_scalar);

        // aggregate proofs
        // TODO https://github.com/EspressoSystems/hotshot-primitives/issues/19
        let aggregate_proofs: Vec<P::Proof> = (0..self.num_storage_nodes)
            .map(|index| {
                P::open(&self.ck, &aggregate_poly, &Self::index_to_point(index)).map(|ok| ok.0)
            })
            .collect::<Result<_, _>>()?;

        let shares = all_evals
            .into_iter()
            .zip(aggregate_proofs)
            .enumerate()
            .map(|(index, (evals, aggregate_proof))| {
                Ok(Share {
                    index,
                    evals,
                    aggregate_proof,
                    evals_proof: all_evals_commit
                        .lookup(V::Index::from(index as u64))
                        .expect_ok()?
                        .1,
                })
            })
            .collect::<Result<_, VidError>>()?;

        Ok((shares, common))
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
            // TODO https://github.com/EspressoSystems/hotshot-primitives/issues/19
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

    fn pseudorandom_scalar(
        common: &<Self as VidScheme>::StorageCommon,
    ) -> VidResult<P::Evaluation> {
        let mut hasher = H::new();
        for poly_commit in common.poly_commits.iter() {
            poly_commit.serialize_uncompressed(&mut hasher)?;
        }
        common
            .all_evals_digest
            .serialize_uncompressed(&mut hasher)?;

        // Notes on hash-to-field:
        // - Can't use `Field::from_random_bytes` because it's fallible
        //   (in what sense is it from "random" bytes?!)
        // - `HashToField` does not expose an incremental API (ie. `update`)
        //   so use an ordinary hasher and pipe `hasher.finalize()` through `hash_to_field` (sheesh!)
        const HASH_TO_FIELD_DOMAIN_SEP: &[u8; 4] = b"rick";
        let hasher_to_field =
            <DefaultFieldHasher<H> as HashToField<P::Evaluation>>::new(HASH_TO_FIELD_DOMAIN_SEP);
        Ok(*hasher_to_field
            .hash_to_field(&hasher.finalize(), 1)
            .first()
            .ok_or_else(|| anyhow!("hash_to_field output is empty"))?)
    }
}

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
    use ark_std::{rand::RngCore, vec};
    use jf_primitives::merkle_tree::hasher::HasherNode;
    use sha2::Sha256;

    #[test]
    fn sad_path_verify_share_corrupt_share() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        for (i, share) in shares.iter().enumerate() {
            // missing share eval
            {
                let share_missing_eval = Share {
                    evals: share.evals[1..].to_vec(),
                    ..share.clone()
                };
                assert_arg_err(
                    advz.verify_share(&share_missing_eval, &common),
                    "1 missing share should be arg error",
                );
            }

            // corrupted share eval
            {
                let mut share_bad_eval = share.clone();
                share_bad_eval.evals[0].double_in_place();
                advz.verify_share(&share_bad_eval, &common)
                    .unwrap()
                    .expect_err("bad share value should fail verification");
            }

            // corrupted index
            {
                let share_bad_index = Share {
                    index: share.index + 5,
                    ..share.clone()
                };
                advz.verify_share(&share_bad_index, &common)
                    .unwrap()
                    .expect_err("bad share index should fail verification");
            }

            // corrupt eval proof
            {
                // We have no way to corrupt a proof
                // (without also causing a deserialization failure).
                // So we use another share's proof instead.
                let share_bad_evals_proof = Share {
                    evals_proof: shares[(i + 1) % shares.len()].evals_proof.clone(),
                    ..share.clone()
                };
                advz.verify_share(&share_bad_evals_proof, &common)
                    .unwrap()
                    .expect_err("bad share evals proof should fail verification");
            }
        }
    }

    #[test]
    fn sad_path_verify_share_corrupt_commit() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        // missing commit
        let common_missing_item = Common {
            poly_commits: common.poly_commits[1..].to_vec(),
            ..common.clone()
        };
        assert_arg_err(
            advz.verify_share(&shares[0], &common_missing_item),
            "1 missing commit should be arg error",
        );

        // 1 corrupt commit, poly_commit
        let common_1_poly_corruption = {
            let mut corrupted = common.clone();
            corrupted.poly_commits[0] = <Bls12_381 as Pairing>::G1Affine::zero().into();
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_poly_corruption)
            .unwrap()
            .expect_err("1 corrupt poly_commit should fail verification");

        // 1 corrupt commit, all_evals_digest
        let common_1_digest_corruption = {
            let mut corrupted = common;
            let mut digest_bytes = vec![0u8; corrupted.all_evals_digest.uncompressed_size()];
            corrupted
                .all_evals_digest
                .serialize_uncompressed(&mut digest_bytes)
                .expect("digest serialization should succeed");
            digest_bytes[0] += 1;
            corrupted.all_evals_digest =
                HasherNode::deserialize_uncompressed(digest_bytes.as_slice())
                    .expect("digest deserialization should succeed");
            corrupted
        };
        advz.verify_share(&shares[0], &common_1_digest_corruption)
            .unwrap()
            .expect_err("1 corrupt all_evals_digest should fail verification");
    }

    #[test]
    fn sad_path_verify_share_corrupt_share_and_commit() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        for mut share in shares {
            let mut common_missing_items = common.clone();

            while !common_missing_items.poly_commits.is_empty() {
                common_missing_items.poly_commits.pop();
                share.evals.pop();

                // equal amounts of share evals, common items
                advz.verify_share(&share, &common_missing_items)
                    .unwrap()
                    .unwrap_err();
            }

            // ensure we tested the empty shares edge case
            assert!(share.evals.is_empty() && common_missing_items.poly_commits.is_empty())
        }
    }

    #[test]
    fn sad_path_recover_payload_corrupt_shares() {
        let (advz, bytes_random) = avdz_init();
        let (shares, common) = advz.dispersal_data(&bytes_random).unwrap();

        {
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
        }

        // corrupt indices
        let mut shares_bad_indices = shares;
        for i in 0..shares_bad_indices.len() {
            shares_bad_indices[i].index += 5;
            let bytes_recovered = advz
                .recover_payload(&shares_bad_indices, &common)
                .expect("recover_payload should succeed for any share indices");
            assert_ne!(bytes_recovered, bytes_random);
        }
    }

    /// Routine initialization tasks.
    ///
    /// Returns the following tuple:
    /// 1. An initialized [`Advz`] instance.
    /// 2. A `Vec<u8>` filled with random bytes.
    fn avdz_init() -> (Advz<Bls12_381, Sha256>, Vec<u8>) {
        let (payload_chunk_size, num_storage_nodes) = (3, 5);
        let mut rng = jf_utils::test_rng();
        let srs = UnivariateKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, payload_chunk_size)
            .unwrap();
        let advz = Advz::new(payload_chunk_size, num_storage_nodes, srs).unwrap();

        let mut bytes_random = vec![0u8; 4000];
        rng.fill_bytes(&mut bytes_random);

        (advz, bytes_random)
    }

    /// Convenience wrapper to assert [`VidError::Argument`] return value.
    fn assert_arg_err<T>(res: VidResult<T>, msg: &str) {
        assert!(matches!(res, Err(Argument(_))), "{}", msg);
    }
}
