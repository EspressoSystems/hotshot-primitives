use hotshot_primitives::vid::{advz::Advz, VidScheme};

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ff::{Field, PrimeField};
use ark_std::{
    println,
    rand::{seq::SliceRandom, CryptoRng, RngCore},
    vec,
};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use jf_utils::test_rng;
use sha2::Sha256;

type Pcs = UnivariateKzgPCS<Bls12_381>;
type G = <Bls12_381 as Pairing>::G1Affine;
type H = Sha256;

#[test]
fn round_trip_advz() {
    let mut rng = test_rng();
    let srs = Pcs::gen_srs_for_testing(&mut rng, 3).unwrap();

    println!(
            "modulus byte len: {}",
            (<<Pcs as PolynomialCommitmentScheme>::Evaluation as Field>::BasePrimeField
                ::MODULUS_BIT_SIZE - 7)/8 + 1
        );

    round_trip(
        |payload_chunk_size, num_storage_nodes| {
            Advz::<Pcs, G, H>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap()
        },
        &mut rng,
    );
}

fn round_trip<V, R>(vid_factory: impl Fn(usize, usize) -> V, rng: &mut R)
where
    V: VidScheme,
    R: RngCore + CryptoRng,
{
    let vid_sizes = [(2, 3), (3, 9)];
    let byte_lens = [2, 16, 32, 47, 48, 49, 64, 100, 400];

    for (payload_chunk_size, num_storage_nodes) in vid_sizes {
        let vid = vid_factory(payload_chunk_size, num_storage_nodes);

        for len in byte_lens {
            println!(
                "m: {} n: {} byte_len: {}",
                payload_chunk_size, num_storage_nodes, len
            );

            let mut bytes_random = vec![0u8; len];
            rng.fill_bytes(&mut bytes_random);

            let (mut shares, common) = vid.dispersal_data(&bytes_random).unwrap();
            assert_eq!(shares.len(), num_storage_nodes);

            for share in shares.iter() {
                vid.verify_share(share, &common).unwrap().unwrap();
            }

            // sample a random subset of shares with size payload_chunk_size
            shares.shuffle(rng);

            // give minimum number of shares for recovery
            let bytes_recovered = vid
                .recover_payload(&shares[..payload_chunk_size], &common)
                .unwrap();
            assert_eq!(bytes_recovered, bytes_random);

            // give an intermediate number of shares for recovery
            let intermediate_num_shares = (payload_chunk_size + num_storage_nodes) / 2;
            let bytes_recovered = vid
                .recover_payload(&shares[..intermediate_num_shares], &common)
                .unwrap();
            assert_eq!(bytes_recovered, bytes_random);

            // give all shares for recovery
            let bytes_recovered = vid.recover_payload(&shares, &common).unwrap();
            assert_eq!(bytes_recovered, bytes_random);
        }
    }
}
