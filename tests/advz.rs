use hotshot_primitives::vid::advz::Advz;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use sha2::Sha256;

type Pcs = UnivariateKzgPCS<Bls12_381>;
type G = <Bls12_381 as Pairing>::G1Affine;
type H = Sha256;

mod util;

#[test]
fn round_trip() {
    let mut rng = jf_utils::test_rng();
    let srs = Pcs::gen_srs_for_testing(&mut rng, 3).unwrap();

    println!(
            "modulus byte len: {}",
            (<<Pcs as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

    util::round_trip(
        |payload_chunk_size, num_storage_nodes| {
            Advz::<Pcs, G, H>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap()
        },
        &mut rng,
    );
}
