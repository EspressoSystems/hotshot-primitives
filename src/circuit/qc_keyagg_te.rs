//! Circuit implementation of stake key aggregation for quorum certificates verification.
use ark_ec::{
    short_weierstrass::{Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_std::{format, vec, Zero};
use jf_primitives::{circuit::rescue::RescueNativeGadget, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::{
        ecc::{emulated::EmulatedTEPointVariable, SWToTEConParam, TEPoint},
        EmulationConfig,
    },
    BoolVar, Circuit, PlonkCircuit, Variable,
};

#[derive(Debug, Clone)]
/// Stake public key variable
/// Wrap EmulatedTEPointVariable because we need to simulate curve operations over the same curve's scalar field
pub struct VerKeyTEVar<E: PrimeField>(pub EmulatedTEPointVariable<E>);

/// Plonk circuit gadget for stake key aggregation for quorum certificates.
/// Assuming that the underlying key composes of a twisted Edwards curve point.
pub trait QCKeyAggregateTEGadget<F>
where
    F: RescueParameter,
{
    /// Key aggregation circuit
    /// * `vks` - list of stake public keys.
    /// * `bit_vec` - the indicator vector for the quorum set, `bit_vec[i] = 1` if `i` is in the quorum set, o/w `bit_vec[i] = 0`.
    /// * `agg_vk` - the public aggregated stake key.
    /// * `d_ecc` - the twisted Edward curve parameter for the simulated curve
    fn check_aggregate_vk<E: EmulationConfig<F> + SWToTEConParam, P: SWCurveConfig<BaseField = E>>(
        &mut self,
        vks: &[VerKeyTEVar<E>],
        bit_vec: &[BoolVar],
        agg_vk: &VerKeyTEVar<E>,
        d_ecc: E,
    ) -> Result<(), CircuitError>;

    /// Stake table commitment checking circuit
    /// * `vk` - list of stake public keys.
    /// * `stake_amts` - list of stake amounts for the corresponding stake keys.
    /// * `digest` - the hash of the stake table.
    fn check_stake_table_digest<E: EmulationConfig<F>>(
        &mut self,
        vks: &[VerKeyTEVar<E>],
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

impl<F> QCKeyAggregateTEGadget<F> for PlonkCircuit<F>
where
    F: RescueParameter,
{
    fn check_aggregate_vk<
        E: EmulationConfig<F> + SWToTEConParam,
        P: SWCurveConfig<BaseField = E>,
    >(
        &mut self,
        vks: &[VerKeyTEVar<E>],
        bit_vec: &[BoolVar],
        agg_vk: &VerKeyTEVar<E>,
        d_ecc: E,
    ) -> Result<(), CircuitError> {
        if vks.len() != bit_vec.len() {
            return Err(CircuitError::ParameterError(format!(
                "bit vector len {} != the number of stake keys {}",
                bit_vec.len(),
                vks.len(),
            )));
        }
        let neutral_point: TEPoint<E> = Projective::<P>::zero().into_affine().into();
        let emulated_neutral_point_var =
            self.create_constant_emulated_te_point_variable(neutral_point)?;
        let mut expect_agg_point_var = emulated_neutral_point_var.clone();
        for (vk, &bit) in vks.iter().zip(bit_vec.iter()) {
            let point_var =
                self.binary_emulated_te_point_vars_select(bit, &emulated_neutral_point_var, &vk.0)?;
            expect_agg_point_var =
                self.emulated_te_ecc_add::<E>(&expect_agg_point_var, &point_var, d_ecc)?;
        }
        self.enforce_emulated_te_point_equal(&expect_agg_point_var, &agg_vk.0)
    }

    fn check_stake_table_digest<E: EmulationConfig<F>>(
        &mut self,
        vks: &[VerKeyTEVar<E>],
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
mod tests {
    use super::*;
    use ark_bls12_377::{g1::Config as Param377, Fq as Fq377};
    use ark_bn254::Fr as Fr254;
    use ark_ff::MontFp;
    use ark_std::{vec::Vec, UniformRand};
    use jf_primitives::rescue::sponge::RescueCRHF;
    use jf_relation::{
        errors::CircuitError,
        gadgets::{ecc::SWToTEConParam, SerializableEmulatedStruct},
        Circuit, PlonkCircuit, Variable,
    };

    #[test]
    fn test_vk_aggregate_te_circuit() -> Result<(), CircuitError> {
        let d_ecc : Fq377 = MontFp!("122268283598675559488486339158635529096981886914877139579534153582033676785385790730042363341236035746924960903179");
        test_vk_aggregate_te_circuit_helper::<Fq377, Fr254, Param377>(d_ecc)
    }

    // TODO: use Aggregate signature APIs to aggregate the keys outside the circuit
    fn test_vk_aggregate_te_circuit_helper<E, F, P>(d_ecc: E) -> Result<(), CircuitError>
    where
        E: EmulationConfig<F> + SWToTEConParam,
        F: RescueParameter,
        P: SWCurveConfig<BaseField = E>,
    {
        let mut rng = jf_utils::test_rng();
        let vk_points: Vec<Projective<P>> =
            (0..5).map(|_| Projective::<P>::rand(&mut rng)).collect();
        let bitvec = vec![false, true, false, true, false];
        let agg_vk_point =
            vk_points
                .iter()
                .zip(bitvec.iter())
                .fold(
                    Projective::<P>::zero(),
                    |acc, (x, &b)| {
                        if b {
                            acc + x
                        } else {
                            acc
                        }
                    },
                );
        let agg_vk_point: TEPoint<E> = agg_vk_point.into_affine().into();
        let vk_points: Vec<TEPoint<E>> = vk_points.iter().map(|p| p.into_affine().into()).collect();
        let stake_amts: Vec<F> = (0..5).map(|i| F::from((i + 1) as u32)).collect();
        let threshold = F::from(6u8);
        let digest = compute_stake_table_hash::<F, E>(&stake_amts[..], &vk_points[..]);

        let mut circuit = PlonkCircuit::<F>::new_ultra_plonk(20);
        // public input
        // TODO: make variables public?
        let agg_vk_var = VerKeyTEVar(circuit.create_emulated_te_point_variable(agg_vk_point)?);
        let threshold_var = circuit.create_variable(threshold)?;
        let digest_var = circuit.create_variable(digest)?;

        // add witness
        let vk_vars: Vec<VerKeyTEVar<E>> = vk_points
            .iter()
            .map(|&p| VerKeyTEVar(circuit.create_emulated_te_point_variable(p).unwrap()))
            .collect();
        let stake_amt_vars: Vec<Variable> = stake_amts
            .iter()
            .map(|&amt| circuit.create_variable(amt).unwrap())
            .collect();
        let bitvec_vars: Vec<BoolVar> = bitvec
            .iter()
            .map(|&b| circuit.create_boolean_variable(b).unwrap())
            .collect();
        // add circuit gadgets
        circuit.check_aggregate_vk::<E, P>(&vk_vars[..], &bitvec_vars[..], &agg_vk_var, d_ecc)?;
        circuit.check_stake_table_digest(&vk_vars[..], &stake_amt_vars[..], digest_var)?;
        circuit.check_threshold(&stake_amt_vars[..], &bitvec_vars[..], threshold_var)?;
        assert!(circuit.check_circuit_satisfiability(&[]).is_ok());

        // bad path: wrong aggregated vk
        let tmp_var = agg_vk_var.0 .0.to_vec()[0];
        let tmp = circuit.witness(tmp_var)?;
        *circuit.witness_mut(tmp_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(tmp_var) = tmp;

        // bad path: wrong digest
        let tmp = circuit.witness(digest_var)?;
        *circuit.witness_mut(digest_var) = F::zero();
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());
        *circuit.witness_mut(digest_var) = tmp;

        // bad path: bad threshold
        *circuit.witness_mut(threshold_var) = F::from(7u8);
        assert!(circuit.check_circuit_satisfiability(&[]).is_err());

        // check input parameter errors
        assert!(circuit
            .check_aggregate_vk::<E, P>(&vk_vars[..], &bitvec_vars[1..], &agg_vk_var, d_ecc)
            .is_err());
        assert!(circuit
            .check_stake_table_digest(&vk_vars[..], &stake_amt_vars[1..], digest_var)
            .is_err());
        assert!(circuit
            .check_threshold(&stake_amt_vars[..], &bitvec_vars[1..], threshold_var)
            .is_err());

        Ok(())
    }

    // TODO(binyi): make the API public
    fn compute_stake_table_hash<F: RescueParameter, E: EmulationConfig<F>>(
        stake_amts: &[F],
        vk_points: &[TEPoint<E>],
    ) -> F {
        let mut input_vec = vec![];
        for (&amt, point) in stake_amts.iter().zip(vk_points.iter()) {
            input_vec.extend(point.serialize_to_native_elements());
            input_vec.push(amt);
        }
        RescueCRHF::sponge_with_bit_padding(&input_vec[..], 1)[0]
    }
}
