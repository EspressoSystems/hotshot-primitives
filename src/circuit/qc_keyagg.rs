//! Circuit implementation of stake key aggregation for quorum certificates.

use ark_ec::twisted_edwards::TECurveConfig as Config;
use ark_std::{format, vec};
use jf_primitives::{circuit::rescue::RescueNativeGadget, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError, gadgets::ecc::PointVariable, BoolVar, Circuit, PlonkCircuit, Variable,
};

#[derive(Debug, Clone)]
/// Stake public key variable
/// TODO: use non-native point variable
pub struct VerKeyVar(pub PointVariable);

/// Plonk circuit gadget for stake key aggregation for quorum certificates.
pub trait QCKeyAggregateGadget<F, P>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    /// Key aggregation circuit
    /// * `vks` - list of stake public keys.
    /// * `bit_vec` - the indicator vector for the quorum set, `bit_vec[i] = 1` if `i` is in the quorum set, o/w `bit_vec[i] = 0`.
    /// * `agg_vk` - the public aggregated stake key.
    fn check_aggregate_vk(
        &mut self,
        vks: &[VerKeyVar],
        bit_vec: &[BoolVar],
        agg_vk: VerKeyVar,
    ) -> Result<(), CircuitError>;

    /// Stake table commitment checking circuit
    /// * `vk` - list of stake public keys.
    /// * `stake_amts` - list of stake amounts for the corresponding stake keys.
    /// * `digest` - the hash of the stake table.
    fn check_stake_table_digest(
        &mut self,
        vks: &[VerKeyVar],
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

impl<F, P> QCKeyAggregateGadget<F, P> for PlonkCircuit<F>
where
    F: RescueParameter,
    P: Config<BaseField = F>,
{
    fn check_aggregate_vk(
        &mut self,
        vks: &[VerKeyVar],
        bit_vec: &[BoolVar],
        agg_vk: VerKeyVar,
    ) -> Result<(), CircuitError> {
        if vks.len() != bit_vec.len() {
            return Err(CircuitError::ParameterError(format!(
                "bit vector len {} != the number of stake keys {}",
                bit_vec.len(),
                vks.len(),
            )));
        }
        let mut expect_agg_point = self.neutral_point_variable();
        for (vk, &bit) in vks.iter().zip(bit_vec.iter()) {
            // TODO: make API public in Jellyfish
            let point =
                self.binary_point_vars_select(bit, &self.neutral_point_variable(), &vk.0)?;
            expect_agg_point = self.ecc_add::<P>(&expect_agg_point, &point)?;
        }
        self.enforce_point_equal(&expect_agg_point, &agg_vk.0)
    }

    fn check_stake_table_digest(
        &mut self,
        vks: &[VerKeyVar],
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
            hash_input.push(vk.0.get_x());
            hash_input.push(vk.0.get_y());
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
