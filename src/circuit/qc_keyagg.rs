//! Circuit implementation of stake key aggregation for quorum certificates.

use ark_std::{format, vec};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    errors::CircuitError, gadgets::ecc::PointVariable, BoolVar, Circuit, PlonkCircuit, Variable,
};

#[derive(Debug, Clone)]
/// Stake public key variable
/// TODO: use non-native point variable
pub struct VerKeyVar(pub PointVariable);

/// Plonk circuit gadget for stake key aggregation for quorum certificates.
pub trait QCKeyAggregateGadget<F>
where
    F: RescueParameter,
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

impl<F> QCKeyAggregateGadget<F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn check_aggregate_vk(
        &mut self,
        _vks: &[VerKeyVar],
        _bit_vec: &[BoolVar],
        _agg_vk: VerKeyVar,
    ) -> Result<(), CircuitError> {
        todo!()
    }

    fn check_stake_table_digest(
        &mut self,
        _vks: &[VerKeyVar],
        _stake_amts: &[Variable],
        _digest: Variable,
    ) -> Result<(), CircuitError> {
        todo!()
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
