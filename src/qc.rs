//! Quorum Certificate traits and implementations.

use ark_std::rand::{CryptoRng, RngCore};
use bitvec::prelude::*;
use generic_array::{ArrayLength, GenericArray};
use jf_primitives::errors::PrimitivesError;
use jf_primitives::signatures::AggregateableSignatureSchemes;
use serde::{Deserialize, Serialize};

pub mod bit_vector;

/// Trait for validating a QC built from different signatures on the same message
pub trait QuorumCertificateValidation<
    A: AggregateableSignatureSchemes + Serialize + for<'a> Deserialize<'a>,
>
{
    /// Public parameters for generating the QC
    /// E.g: snark proving/verifying keys, list of (or pointer to) public keys stored in the smart contract.
    type QCProverParams: Serialize + for<'a> Deserialize<'a>;

    /// Public parameters for validating the QC
    /// E.g: verifying keys, stake table commitment
    type QCVerifierParams: Serialize + for<'a> Deserialize<'a>;

    /// Extra value to check the aggregated signature of the QC
    /// E.g: snark proof, bitmap corresponding to the public keys involved in signing
    type Proof: Serialize + for<'a> Deserialize<'a>;

    /// Allows to fix the size of the message at compilation time.
    type MessageLength: ArrayLength<A::MessageUnit>;

    /// Type of some auxiliary information returned by the check function in order to feed oth
    type CheckedType;

    /// Produces a partial signature on a message with a single user signing key
    /// NOTE: the original message (vote) should be prefixed with the hash of the stake table.
    /// * `agg_sig_pp` - public parameters for aggregate signature
    /// * `message` - message to be signed
    /// * `signing_keys` - user signing key
    /// * `returns` - a "simple" signature
    fn partial_sign<R: CryptoRng + RngCore>(
        agg_sig_pp: &A::PublicParameter,
        message: &GenericArray<A::MessageUnit, Self::MessageLength>,
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
        message: &GenericArray<A::MessageUnit, Self::MessageLength>,
        sig: &A::Signature,
        proof: &Self::Proof,
    ) -> Result<Self::CheckedType, PrimitivesError>;
}
