use bitvec::prelude::*;
use core::marker::PhantomData;

use ark_std::{
    format,
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
};
use ethereum_types::U256;
use jf_primitives::errors::PrimitivesError;
use jf_primitives::errors::PrimitivesError::ParameterError;
use jf_primitives::signatures::AggregateableSignatureSchemes;

/// Trait for validating a QC built from different signatures on the same message
pub trait QuorumCertificateValidation<A: AggregateableSignatureSchemes> {
    /// Public parameters for generating the QC
    /// E.g: snark proving/verifying keys, list of (or pointer to) public keys stored in the smart contract.
    type QCProverParams;

    /// Public parameters for validating the QC
    /// E.g: verifying keys, stake table commitment
    type QCVerifierParams;

    /// Extra value to check the aggregated signature of the QC
    /// E.g: snark proof, bitmap corresponding to the public keys involved in signing
    type Proof;

    /// Produces a partial signature on a message with a single user signing key
    /// * `agg_sig_pp` - public parameters for aggregate signature
    /// * `message` - message to be signed
    /// * `signing_keys` - user signing key
    /// * `returns` - a "simple" signature
    fn partial_sign<R: CryptoRng + RngCore>(
        agg_sig_pp: &A::PublicParameter,
        message: &[A::MessageUnit],
        sig_key: &A::SigningKey,
        prng: &mut R,
    ) -> Result<A::Signature, PrimitivesError>;

    /// Computes an aggregated signature from a set of partial signatures and the verification keys involved
    /// * `qc_pp` - public parameters for generating the QC
    /// * `active_keys` - a bool vector indicating the list of verification keys corresponding to the set of partial signatures
    /// * `partial_sigs` - partial signatures on the same message
    /// * `returns` - an error if some of the partial signatures provided are invalid
    ///     or the number of partial signatures / verifications keys are different.
    ///     Otherwise return an aggregated signature with a proof.
    fn assemble(
        qc_pp: &Self::QCProverParams,
        active_keys: &BitSlice,
        partial_sigs: &[A::Signature],
    ) -> Result<(A::Signature, Self::Proof), PrimitivesError>;

    /// Checks an aggregated signature over some message provided as input
    /// * `qc_vp` - public parameters for validating the QC
    /// * `message` - message to check the aggregated signature against
    /// * `sig` - aggregated signature on message
    /// * `proof` - auxiliary information to check the signature
    /// * `returns` - nothing if the signature is valid, an error otherwise.
    fn check(
        qc_pp: &Self::QCVerifierParams,
        message: &[A::MessageUnit],
        sig: &A::Signature,
        proof: &Self::Proof,
    ) -> Result<(), PrimitivesError>;
}

// TODO: add CanonicalSerialize/Deserialize
pub struct BitvectorQuorumCertificate<A: AggregateableSignatureSchemes>(PhantomData<A>);

pub struct StakeTableEntry<A: AggregateableSignatureSchemes> {
    pub stake_key: A::VerificationKey,
    pub stake_amount: U256,
}

pub struct StakeTableDigest<A: AggregateableSignatureSchemes>(Vec<A::MessageUnit>);

// TODO: refactor
pub struct QCParams<A: AggregateableSignatureSchemes> {
    pub stake_table_digest: StakeTableDigest<A>,
    pub stake_entries: Vec<StakeTableEntry<A>>,
    pub threshold: U256,
    pub agg_sig_pp: A::PublicParameter,
}

impl<A> QuorumCertificateValidation<A> for BitvectorQuorumCertificate<A>
where
    A: AggregateableSignatureSchemes,
{
    type QCProverParams = QCParams<A>;

    // TODO: later with SNARKs we'll use a smaller verifier parameter
    type QCVerifierParams = QCParams<A>;

    type Proof = BitVec;

    fn partial_sign<R: CryptoRng + RngCore>(
        agg_sig_pp: &A::PublicParameter,
        message: &[A::MessageUnit],
        sig_key: &A::SigningKey,
        prng: &mut R,
    ) -> Result<A::Signature, PrimitivesError> {
        A::sign(agg_sig_pp, sig_key, message, prng)
    }

    fn assemble(
        qc_pp: &Self::QCProverParams,
        active_keys: &BitSlice,
        partial_sigs: &[A::Signature],
    ) -> Result<(A::Signature, Self::Proof), PrimitivesError> {
        if active_keys.len() != qc_pp.stake_entries.len() {
            return Err(ParameterError(format!(
                "bit vector len {} != the number of stake entries {}",
                active_keys.len(),
                qc_pp.stake_entries.len(),
            )));
        }
        let total_weight: U256 = qc_pp.stake_entries.iter().zip(active_keys.iter()).fold(
            U256::zero(),
            |acc, (entry, b)| {
                if *b {
                    acc + entry.stake_amount
                } else {
                    acc
                }
            },
        );
        if total_weight < qc_pp.threshold {
            return Err(ParameterError(format!(
                "total_weight {} less than threshold {}",
                total_weight, qc_pp.threshold,
            )));
        }
        let mut ver_keys = vec![];
        for (entry, b) in qc_pp.stake_entries.iter().zip(active_keys.iter()) {
            if *b {
                ver_keys.push(entry.stake_key.clone());
            }
        }
        if ver_keys.len() != partial_sigs.len() {
            return Err(ParameterError(format!(
                "the number of ver_keys {} != the number of partial signatures {}",
                ver_keys.len(),
                partial_sigs.len(),
            )));
        }
        let sig = A::aggregate(&qc_pp.agg_sig_pp, &ver_keys[..], partial_sigs)?;

        Ok((sig, active_keys.into()))
    }

    fn check(
        qc_vp: &Self::QCVerifierParams,
        message: &[A::MessageUnit],
        sig: &A::Signature,
        proof: &Self::Proof,
    ) -> Result<(), PrimitivesError> {
        if proof.len() != qc_vp.stake_entries.len() {
            return Err(ParameterError(format!(
                "proof bit vector len {} != the number of stake entries {}",
                proof.len(),
                qc_vp.stake_entries.len(),
            )));
        }
        let total_weight: U256 =
            qc_vp
                .stake_entries
                .iter()
                .zip(proof.iter())
                .fold(U256::zero(), |acc, (entry, b)| {
                    if *b {
                        acc + entry.stake_amount
                    } else {
                        acc
                    }
                });
        if total_weight < qc_vp.threshold {
            return Err(ParameterError(format!(
                "total_weight {} less than threshold {}",
                total_weight, qc_vp.threshold,
            )));
        }
        let mut ver_keys = vec![];
        for (entry, b) in qc_vp.stake_entries.iter().zip(proof.iter()) {
            if *b {
                ver_keys.push(entry.stake_key.clone());
            }
        }
        A::multi_sig_verify(&qc_vp.agg_sig_pp, &ver_keys[..], message, sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jf_primitives::signatures::bls_over_bn254::{BLSOverBN254CurveSignatureScheme, KeyPair};
    use jf_primitives::signatures::SignatureScheme;

    macro_rules! test_quorum_certificate {
        ($aggsig:tt) => {
            let mut rng = jf_utils::test_rng();
            let agg_sig_pp = $aggsig::param_gen(Some(&mut rng)).unwrap();
            let key_pair1 = KeyPair::generate(&mut rng);
            let key_pair2 = KeyPair::generate(&mut rng);
            let key_pair3 = KeyPair::generate(&mut rng);
            let entry1 = StakeTableEntry::<$aggsig> {
                stake_key: key_pair1.ver_key(),
                stake_amount: U256::from(3u8),
            };
            let entry2 = StakeTableEntry::<$aggsig> {
                stake_key: key_pair2.ver_key(),
                stake_amount: U256::from(5u8),
            };
            let entry3 = StakeTableEntry::<$aggsig> {
                stake_key: key_pair3.ver_key(),
                stake_amount: U256::from(7u8),
            };
            let qc_pp = QCParams::<$aggsig> {
                stake_table_digest: StakeTableDigest::<$aggsig>(vec![12u8, 2u8, 7u8, 8u8]),
                stake_entries: vec![entry1, entry2, entry3],
                threshold: U256::from(10u8),
                agg_sig_pp,
            };
            let msg = vec![72u8];
            let sig1 = BitvectorQuorumCertificate::<$aggsig>::partial_sign(
                &agg_sig_pp,
                &msg[..],
                key_pair1.sign_key_ref(),
                &mut rng,
            )
            .unwrap();
            let sig2 = BitvectorQuorumCertificate::<$aggsig>::partial_sign(
                &agg_sig_pp,
                &msg[..],
                key_pair2.sign_key_ref(),
                &mut rng,
            )
            .unwrap();
            let sig3 = BitvectorQuorumCertificate::<$aggsig>::partial_sign(
                &agg_sig_pp,
                &msg[..],
                key_pair3.sign_key_ref(),
                &mut rng,
            )
            .unwrap();

            // happy path
            let active_keys = bitvec![0, 1, 1];
            let qc1 = BitvectorQuorumCertificate::<$aggsig>::assemble(
                &qc_pp,
                active_keys.as_bitslice(),
                &[sig2.clone(), sig3.clone()],
            )
            .unwrap();
            assert!(
                BitvectorQuorumCertificate::<$aggsig>::check(&qc_pp, &msg[..], &qc1.0, &qc1.1)
                    .is_ok()
            );

            // bad paths
            // number of signatures unmatch
            assert!(BitvectorQuorumCertificate::<$aggsig>::assemble(
                &qc_pp,
                active_keys.as_bitslice(),
                &[sig2.clone()]
            )
            .is_err());
            // total weight under threshold
            let active_bad = bitvec![1, 1, 0];
            assert!(BitvectorQuorumCertificate::<$aggsig>::assemble(
                &qc_pp,
                active_bad.as_bitslice(),
                &[sig1.clone(), sig2.clone()]
            )
            .is_err());
            // wrong bool vector length
            let active_bad_2 = bitvec![0, 1, 1, 0];
            assert!(BitvectorQuorumCertificate::<$aggsig>::assemble(
                &qc_pp,
                active_bad_2.as_bitslice(),
                &[sig2, sig3],
            )
            .is_err());

            assert!(BitvectorQuorumCertificate::<$aggsig>::check(
                &qc_pp,
                &msg[..],
                &qc1.0,
                &active_bad
            )
            .is_err());
            assert!(BitvectorQuorumCertificate::<$aggsig>::check(
                &qc_pp,
                &msg[..],
                &qc1.0,
                &active_bad_2
            )
            .is_err());
            let bad_msg = vec![70u8];
            assert!(BitvectorQuorumCertificate::<$aggsig>::check(
                &qc_pp,
                &bad_msg[..],
                &qc1.0,
                &qc1.1
            )
            .is_err());

            let bad_sig = &sig1;
            assert!(
                BitvectorQuorumCertificate::<$aggsig>::check(&qc_pp, &msg, &bad_sig, &qc1.1)
                    .is_err()
            );
        };
    }
    #[test]
    fn test_quorum_certificate() {
        test_quorum_certificate!(BLSOverBN254CurveSignatureScheme);
    }

    // #[test]
    // fn test_serde() {
    //     // TODO
    // }
}
