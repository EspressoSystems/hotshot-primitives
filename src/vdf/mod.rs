use ark_std::{
    fmt::Debug,
    rand::{CryptoRng, RngCore},
};
use jf_primitives::errors::PrimitivesError;
use serde::{Deserialize, Serialize};

/// A trait for VDF proof, evaluation and verification.
pub trait VDF {
    /// Public parameters
    type PublicParameter;

    /// VDF proof.
    type Proof: Debug + Clone + Send + Sync + for<'a> Deserialize<'a> + Serialize + PartialEq + Eq;

    /// VDF input.
    type Input: Debug + Clone + Send + Sync + for<'a> Deserialize<'a> + Serialize + PartialEq + Eq;

    /// VDF output.
    type Output: Debug + Clone + Send + Sync + for<'a> Deserialize<'a> + Serialize + PartialEq + Eq;

    /// Generates a public parameter from RNG with given difficulty.
    fn param_gen<R: CryptoRng + RngCore>(
        &self,
        difficulty: u64,
        prng: Option<&mut R>,
    ) -> Result<Self::PublicParameter, PrimitivesError>;

    /// Computes the VDF output and proof.
    fn eval(
        &mut self,
        pp: &Self::PublicParameter,
        input: &Self::Input,
    ) -> Result<(Self::Output, Self::Proof), PrimitivesError>;

    /// Verifies a VDF output given the proof.
    fn verify(
        &mut self,
        pp: &Self::PublicParameter,
        input: &Self::Input,
        output: &Self::Output,
        proof: &Self::Proof,
    ) -> Result<bool, PrimitivesError>;
}
