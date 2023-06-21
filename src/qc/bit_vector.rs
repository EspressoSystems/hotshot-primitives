//! Implementation for BitVectorQC that uses BLS signature + Bit vector.
//! See more details in HotShot paper.

use crate::qc::QuorumCertificate;
use ark_std::{
    fmt::Debug,
    format,
    marker::PhantomData,
    rand::{CryptoRng, RngCore},
    vec,
    vec::Vec,
};
use bitvec::prelude::*;
use ethereum_types::U256;
use generic_array::GenericArray;
use jf_primitives::errors::PrimitivesError;
use jf_primitives::errors::PrimitivesError::ParameterError;
use jf_primitives::signatures::AggregateableSignatureSchemes;
use serde::{Deserialize, Serialize};
use typenum::U32;

/// An implementation of QC using BLS signature and a bit-vector.
#[derive(Serialize, Deserialize)]
pub struct BitVectorQC<A: AggregateableSignatureSchemes + Serialize + for<'a> Deserialize<'a>>(
    PhantomData<A>,
);

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct StakeTableEntry<V> {
    pub stake_key: V,
    pub stake_amount: U256,
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct QCParams<V, P> {
    pub stake_entries: Vec<StakeTableEntry<V>>,
    pub threshold: U256,
    pub agg_sig_pp: P,
}

impl<A> QuorumCertificate<A> for BitVectorQC<A>
where
    A: AggregateableSignatureSchemes + Serialize + for<'a> Deserialize<'a>,
{
    type QCProverParams = QCParams<A::VerificationKey, A::PublicParameter>;

    // TODO: later with SNARKs we'll use a smaller verifier parameter
    type QCVerifierParams = QCParams<A::VerificationKey, A::PublicParameter>;

    type QC = (A::Signature, BitVec);
    type MessageLength = U32;
    type CheckedType = ();

    fn sign<R: CryptoRng + RngCore>(
        agg_sig_pp: &A::PublicParameter,
        message: &GenericArray<A::MessageUnit, Self::MessageLength>,
        sk: &A::SigningKey,
        prng: &mut R,
    ) -> Result<A::Signature, PrimitivesError> {
        A::sign(agg_sig_pp, sk, message, prng)
    }

    fn assemble(
        qc_pp: &Self::QCProverParams,
        signers: &BitSlice,
        sigs: &[A::Signature],
    ) -> Result<Self::QC, PrimitivesError> {
        if signers.len() != qc_pp.stake_entries.len() {
            return Err(ParameterError(format!(
                "bit vector len {} != the number of stake entries {}",
                signers.len(),
                qc_pp.stake_entries.len(),
            )));
        }
        let total_weight: U256 =
            qc_pp
                .stake_entries
                .iter()
                .zip(signers.iter())
                .fold(U256::zero(), |acc, (entry, b)| {
                    if *b {
                        acc + entry.stake_amount
                    } else {
                        acc
                    }
                });
        if total_weight < qc_pp.threshold {
            return Err(ParameterError(format!(
                "total_weight {} less than threshold {}",
                total_weight, qc_pp.threshold,
            )));
        }
        let mut ver_keys = vec![];
        for (entry, b) in qc_pp.stake_entries.iter().zip(signers.iter()) {
            if *b {
                ver_keys.push(entry.stake_key.clone());
            }
        }
        if ver_keys.len() != sigs.len() {
            return Err(ParameterError(format!(
                "the number of ver_keys {} != the number of partial signatures {}",
                ver_keys.len(),
                sigs.len(),
            )));
        }
        let sig = A::aggregate(&qc_pp.agg_sig_pp, &ver_keys[..], sigs)?;

        Ok((sig, signers.into()))
    }

    fn check(
        qc_vp: &Self::QCVerifierParams,
        message: &GenericArray<A::MessageUnit, Self::MessageLength>,
        qc: &Self::QC,
    ) -> Result<Self::CheckedType, PrimitivesError> {
        let (sig, proof) = qc;
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
            let entry1 = StakeTableEntry {
                stake_key: key_pair1.ver_key(),
                stake_amount: U256::from(3u8),
            };
            let entry2 = StakeTableEntry {
                stake_key: key_pair2.ver_key(),
                stake_amount: U256::from(5u8),
            };
            let entry3 = StakeTableEntry {
                stake_key: key_pair3.ver_key(),
                stake_amount: U256::from(7u8),
            };
            let qc_pp = QCParams {
                stake_entries: vec![entry1, entry2, entry3],
                threshold: U256::from(10u8),
                agg_sig_pp,
            };
            let msg = [72u8; 32];
            let sig1 = BitVectorQC::<$aggsig>::sign(
                &agg_sig_pp,
                &msg.into(),
                key_pair1.sign_key_ref(),
                &mut rng,
            )
            .unwrap();
            let sig2 = BitVectorQC::<$aggsig>::sign(
                &agg_sig_pp,
                &msg.into(),
                key_pair2.sign_key_ref(),
                &mut rng,
            )
            .unwrap();
            let sig3 = BitVectorQC::<$aggsig>::sign(
                &agg_sig_pp,
                &msg.into(),
                key_pair3.sign_key_ref(),
                &mut rng,
            )
            .unwrap();

            // happy path
            let signers = bitvec![0, 1, 1];
            let qc = BitVectorQC::<$aggsig>::assemble(
                &qc_pp,
                signers.as_bitslice(),
                &[sig2.clone(), sig3.clone()],
            )
            .unwrap();
            assert!(BitVectorQC::<$aggsig>::check(&qc_pp, &msg.into(), &qc).is_ok());

            // Check the QC and the QCParams can be serialized / deserialized
            assert_eq!(
                qc,
                bincode::deserialize(&bincode::serialize(&qc).unwrap()).unwrap()
            );

            assert_eq!(
                qc_pp,
                bincode::deserialize(&bincode::serialize(&qc_pp).unwrap()).unwrap()
            );

            // bad paths
            // number of signatures unmatch
            assert!(BitVectorQC::<$aggsig>::assemble(
                &qc_pp,
                signers.as_bitslice(),
                &[sig2.clone()]
            )
            .is_err());
            // total weight under threshold
            let active_bad = bitvec![1, 1, 0];
            assert!(BitVectorQC::<$aggsig>::assemble(
                &qc_pp,
                active_bad.as_bitslice(),
                &[sig1.clone(), sig2.clone()]
            )
            .is_err());
            // wrong bool vector length
            let active_bad_2 = bitvec![0, 1, 1, 0];
            assert!(BitVectorQC::<$aggsig>::assemble(
                &qc_pp,
                active_bad_2.as_bitslice(),
                &[sig2, sig3],
            )
            .is_err());

            assert!(BitVectorQC::<$aggsig>::check(
                &qc_pp,
                &msg.into(),
                &(qc.0.clone(), active_bad)
            )
            .is_err());
            assert!(BitVectorQC::<$aggsig>::check(
                &qc_pp,
                &msg.into(),
                &(qc.0.clone(), active_bad_2)
            )
            .is_err());
            let bad_msg = [70u8; 32];
            assert!(BitVectorQC::<$aggsig>::check(&qc_pp, &bad_msg.into(), &qc).is_err());

            let bad_sig = &sig1;
            assert!(
                BitVectorQC::<$aggsig>::check(&qc_pp, &msg.into(), &(bad_sig.clone(), qc.1))
                    .is_err()
            );
        };
    }
    #[test]
    fn test_quorum_certificate() {
        test_quorum_certificate!(BLSOverBN254CurveSignatureScheme);
    }
}