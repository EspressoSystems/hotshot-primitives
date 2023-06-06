//! Circuit implementation of stake key aggregation for quorum certificates verification.

use ark_ec::twisted_edwards::Affine;
use ark_ec::twisted_edwards::TECurveConfig as Config;
use ark_ff::PrimeField;
use ark_std::{format, vec};
use jf_primitives::{circuit::rescue::RescueNativeGadget, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::{
        ecc::{non_native::EmulatedPointVariable, Point},
        EmulationConfig,
    },
    BoolVar, Circuit, PlonkCircuit, Variable,
};

#[derive(Debug, Clone)]
/// Stake public key variable
/// Wrap EmulatedPointVariable because we need to simulate curve operations over the same curve's scalar field
pub struct VerKeyVar<E: PrimeField>(pub EmulatedPointVariable<E>);

/// Plonk circuit gadget for stake key aggregation for quorum certificates.
pub trait QCKeyAggregateGadget<F>
where
    F: RescueParameter,
{
    /// Key aggregation circuit
    /// * `vks` - list of stake public keys.
    /// * `bit_vec` - the indicator vector for the quorum set, `bit_vec[i] = 1` if `i` is in the quorum set, o/w `bit_vec[i] = 0`.
    /// * `agg_vk` - the public aggregated stake key.
    /// * `d_ecc` - the twisted Edward curve parameter for the simulated curve
    fn check_aggregate_vk<E: EmulationConfig<F>, P: Config<BaseField = E>>(
        &mut self,
        vks: &[VerKeyVar<E>],
        bit_vec: &[BoolVar],
        agg_vk: &VerKeyVar<E>,
        d_ecc: E,
    ) -> Result<(), CircuitError>;

    /// Stake table commitment checking circuit
    /// * `vk` - list of stake public keys.
    /// * `stake_amts` - list of stake amounts for the corresponding stake keys.
    /// * `digest` - the hash of the stake table.
    fn check_stake_table_digest<E: EmulationConfig<F>>(
        &mut self,
        vks: &[VerKeyVar<E>],
        stake_amts: &[Variable],
        digest: Variable,
    ) -> Result<(), CircuitError>;

    /// Quorum threshold checking circuit
    /// * `stake_amts` - list of stake amounts for the corresponding stake keys.
    /// * `bit_vec` - the indicator vector for the quorum set.
    /// * `threshold` - the public quorum threshold.
    fn check_threshold(
        &mut self,
        stake_amts: &[Variable],
        bit_vec: &[BoolVar],
        threshold: Variable,
    ) -> Result<(), CircuitError>;
}

impl<F> QCKeyAggregateGadget<F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn check_aggregate_vk<E: EmulationConfig<F>, P: Config<BaseField = E>>(
        &mut self,
        vks: &[VerKeyVar<E>],
        bit_vec: &[BoolVar],
        agg_vk: &VerKeyVar<E>,
        d_ecc: E,
    ) -> Result<(), CircuitError> {
        if vks.len() != bit_vec.len() {
            return Err(CircuitError::ParameterError(format!(
                "bit vector len {} != the number of stake keys {}",
                bit_vec.len(),
                vks.len(),
            )));
        }
        let neutral_point = Point::from(Affine::<P>::zero());
        let emulated_neutral_point_var =
            self.create_constant_emulated_point_variable(neutral_point)?;
        let mut expect_agg_point_var = emulated_neutral_point_var.clone();
        for (vk, &bit) in vks.iter().zip(bit_vec.iter()) {
            let point_var =
                self.binary_emulated_point_vars_select(bit, &emulated_neutral_point_var, &vk.0)?;
            expect_agg_point_var =
                self.emulated_ecc_add::<E>(&expect_agg_point_var, &point_var, d_ecc)?;
        }
        self.enforce_emulated_point_equal(&expect_agg_point_var, &agg_vk.0)
    }

    fn check_stake_table_digest<E: EmulationConfig<F>>(
        &mut self,
        vks: &[VerKeyVar<E>],
        stake_amts: &[Variable],
        digest: Variable,
    ) -> Result<(), CircuitError> {
        if stake_amts.len() != vks.len() {
            return Err(CircuitError::ParameterError(format!(
                "the number of stake amounts {} != the number of stake verification keys {}",
                stake_amts.len(),
                vks.len(),
            )));
        }
        let mut hash_input = vec![];
        for (vk, &stake_amt) in vks.iter().zip(stake_amts.iter()) {
            hash_input.append(&mut vk.0 .0.to_vec());
            hash_input.append(&mut vk.0 .1.to_vec());
            hash_input.push(stake_amt);
        }
        let expected_digest =
            RescueNativeGadget::<F>::rescue_sponge_with_padding(self, &hash_input, 1)?[0];
        self.enforce_equal(expected_digest, digest)
    }

    fn check_threshold(
        &mut self,
        stake_amts: &[Variable],
        bit_vec: &[BoolVar],
        threshold: Variable,
    ) -> Result<(), CircuitError> {
        if stake_amts.len() != bit_vec.len() {
            return Err(CircuitError::ParameterError(format!(
                "bit vector len {} != the number of stake entries {}",
                bit_vec.len(),
                stake_amts.len(),
            )));
        }
        let mut active_amts = vec![];
        for (&stake_amt, &bit) in stake_amts.iter().zip(bit_vec.iter()) {
            active_amts.push(self.mul(stake_amt, bit.into())?);
        }
        let sum = self.sum(&active_amts[..])?;
        self.enforce_geq(sum, threshold)
    }
}

#[cfg(test)]
mod tests {}
