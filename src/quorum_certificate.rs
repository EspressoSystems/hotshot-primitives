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
    /// Public parameters for validating the QC
    /// E.g: snark proving/verifying keys, list of (or pointer to) public keys stored in the smart contract.
    type QCpp;

    /// Extra value to check the aggregated signature of the QC
    /// E.g: snark proof, bitmap corresponding to the public keys involved in signing
    type Proof;

    /// Produces a partial signature on a message with a single user signing key
    /// * `qc_pp` - public parameters for validating the QC
    /// * `message` - message to be signed
    /// * `signing_keys` - user signing key
    /// * `returns` - a "simple" signature
    fn partial_sign<R: CryptoRng + RngCore>(
        qc_pp: &Self::QCpp,
        message: &[A::MessageUnit],
        sig_key: &A::SigningKey,
        prng: &mut R,
    ) -> Result<A::Signature, PrimitivesError>;

    /// Computes an aggregated signature from a set of partial signatures and the verification keys involved
    /// * `qc_pp` - public parameters for validating the QC
    /// * `active_keys` - a bool vector indicating the list of verification keys corresponding to the set of partial signatures
    /// * `partial_sigs` - partial signatures on the same message
    /// * `returns` - an error if some of the partial signatures provided are invalid
    ///     or the number of partial signatures / verifications keys are different.
    ///     Otherwise return an aggregated signature with a proof.
    fn assemble(
        qc_pp: &Self::QCpp,
        active_keys: &[bool],
        partial_sigs: &[A::Signature],
    ) -> Result<(A::Signature, Self::Proof), PrimitivesError>;

    /// Checks an aggregated signature over some message provided as input
    /// * `qc_pp` - public parameters for validating the QC
    /// * `message` - message to check the aggregated signature against
    /// * `sig` - aggregated signature on message
    /// * `proof` - auxiliary information to check the signature
    /// * `returns` - nothing if the signature is valid, an error otherwise.
    fn check(
        qc_pp: &Self::QCpp,
        message: &[A::MessageUnit],
        sig: &A::Signature,
        proof: &Self::Proof,
    ) -> Result<(), PrimitivesError>;
}

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
    type QCpp = QCParams<A>;

    type Proof = Vec<bool>;

    fn partial_sign<R: CryptoRng + RngCore>(
        qc_pp: &Self::QCpp,
        message: &[A::MessageUnit],
        sig_key: &A::SigningKey,
        prng: &mut R,
    ) -> Result<A::Signature, PrimitivesError> {
        let msg = [&qc_pp.stake_table_digest.0, message].concat();
        A::sign(&qc_pp.agg_sig_pp, sig_key, &msg[..], prng)
    }

    fn assemble(
        qc_pp: &Self::QCpp,
        active_keys: &[bool],
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
            |acc, (entry, &b)| {
                if b {
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
        for (entry, &b) in qc_pp.stake_entries.iter().zip(active_keys.iter()) {
            if b {
                ver_keys.push(entry.stake_key.clone());
            }
        }
        let sig = A::aggregate(&qc_pp.agg_sig_pp, &ver_keys[..], partial_sigs)?;

        Ok((sig, active_keys.to_vec()))
    }

    fn check(
        qc_pp: &Self::QCpp,
        message: &[A::MessageUnit],
        sig: &A::Signature,
        proof: &Self::Proof,
    ) -> Result<(), PrimitivesError> {
        if proof.len() != qc_pp.stake_entries.len() {
            return Err(ParameterError(format!(
                "proof bit vector len {} != the number of stake entries {}",
                proof.len(),
                qc_pp.stake_entries.len(),
            )));
        }
        let total_weight: U256 =
            qc_pp
                .stake_entries
                .iter()
                .zip(proof.iter())
                .fold(
                    U256::zero(),
                    |acc, (entry, &b)| {
                        if b {
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
        for (entry, &b) in qc_pp.stake_entries.iter().zip(proof.iter()) {
            if b {
                ver_keys.push(entry.stake_key.clone());
            }
        }
        let msg = [&qc_pp.stake_table_digest.0, message].concat();
        A::multi_sig_verify(&qc_pp.agg_sig_pp, &ver_keys[..], &msg[..], sig)
    }
}
