//! Circuit implementation of stake key aggregation for quorum certificates verification.

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::EmulationConfig, BoolVar, Variable};

pub trait VerKeyVar<E: PrimeField>: Sized + Into<E> {}

/// Plonk circuit gadget for stake key aggregation for quorum certificates.
/// Assuming that the underlying key composes of a short Weierstrass curve point.
pub trait QCKeyAggregateGadget<F>
where
    F: RescueParameter,
{
    /// Key aggregation circuit
    /// * `vks` - list of stake public keys.
    /// * `bit_vec` - the indicator vector for the quorum set, `bit_vec[i] = 1` if `i` is in the quorum set, o/w `bit_vec[i] = 0`.
    /// * `agg_vk` - the public aggregated stake key.
    /// * `a_ecc` - the short Weierstrass curve parameter for the simulated curve
    fn check_aggregate_vk<E: EmulationConfig<F>, P: SWCurveConfig<BaseField = E>>(
        &mut self,
        vks: &[dyn VerKeyVar<E>],
        bit_vec: &[BoolVar],
        agg_vk: &dyn VerKeyVar<E>,
        a_ecc: E,
    ) -> Result<(), CircuitError>;

    /// Stake table commitment checking circuit
    /// * `vk` - list of stake public keys.
    /// * `stake_amts` - list of stake amounts for the corresponding stake keys.
    /// * `digest` - the hash of the stake table.
    fn check_stake_table_digest<E: EmulationConfig<F>>(
        &mut self,
        vks: &[dyn VerKeyVar<E>],
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
