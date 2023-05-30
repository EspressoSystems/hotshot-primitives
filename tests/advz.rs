use hotshot_primitives::vid::advz::Advz;

use ark_bls12_381::Bls12_381;
use ark_ff::{Field, PrimeField};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use sha2::Sha256;

mod vid;

#[test]
fn round_trip() {
    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<Bls12_381>::gen_srs_for_testing(&mut rng, 3).unwrap();

    println!(
            "modulus byte len: {}",
            (<<UnivariateKzgPCS<Bls12_381> as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

    vid::round_trip(
        |payload_chunk_size, num_storage_nodes| {
            Advz::<Bls12_381, Sha256>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap()
        },
        &mut rng,
    );
}
