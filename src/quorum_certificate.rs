use jf_primitives::errors::PrimitivesError;
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
    /// * `agg_sig_pp` -  public parameters of the aggregated signature scheme
    /// * `message` - message to be signed
    /// * `signing_keys` - user signing key
    /// * `returns` - a "simple" signature
    fn partial_sign(
        agg_sig_pp: A::PublicParameter,
        message: &[A::MessageUnit],
        sig_key: A::SigningKey,
    ) -> A::Signature;

    /// Computes an aggregated signature from a set of partial signatures and the verification keys involved
    /// * `qc_pp` - public parameters for validating the QC
    /// * `agg_sign_pp` - public parameter for the aggregated signature scheme
    /// * `ver_keys` - list of verification keys corresponding to the set of partial signatures
    /// * `partial_sigs` - partial signatures on the same message
    /// * `returns` - an error if some of the partial signatures provided are invalid
    ///     or the number of partial signatures / verifications keys are different.
    ///     Otherwise return an aggregated signature with a proof.
    fn assemble(
        qc_pp: Self::QCpp,
        agg_sig_pp: A::PublicParameter,
        message: &[A::MessageUnit],
        ver_keys: &[A::VerificationKey],
        partial_sigs: &[A::Signature],
    ) -> Result<(A::Signature, Self::Proof), PrimitivesError>;

    /// Checks an aggregated signature over some message provided as input
    /// * `qc_pp` - public parameters for validating the QC
    /// * `agg_sig_pp` -  public parameters of the aggregated signature scheme
    /// * `message` - message to check the aggregated signature against
    /// * `sig` - aggregated signature on message
    /// * `ver_key` - aggregated verification key
    /// * `proof` - auxiliary information to check the signature
    /// * `returns` - nothing if the signature is valid, an error otherwise.
    fn check(
        qc_pp: Self::QCpp,
        message: &[A::MessageUnit],
        sig: A::Signature,
        ver_key: A::VerificationKey,
        proof: Self::Proof,
    ) -> Result<(), PrimitivesError>;
}
