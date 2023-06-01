#![deny(warnings)]
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::Write;
use ark_std::rand::RngCore;
use criterion::{criterion_group, criterion_main, Criterion};
use digest::{Digest, DynDigest, OutputSizeUser};
use generic_array::ArrayLength;
use hotshot_primitives::vid::{advz::Advz, VidScheme};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use sha2::Sha256;

fn advz<E, H>(c: &mut Criterion, pairing_name: &str)
where
    E: Pairing,
    // TODO(Gus) clean up nasty trait bounds upstream
    H: Digest + DynDigest + Default + Clone + Write,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    const RATE: usize = 4; // ratio of num_storage_nodes : polynomial_degree
    const VID_SIZES_STEP: usize = 50;
    const VID_SIZES_COUNT: usize = 4;

    // (polynomial_degree, num_storage_nodes)
    let vid_sizes: Vec<(usize, usize)> = (1..=VID_SIZES_COUNT)
        .map(|x| (x * VID_SIZES_STEP, x * VID_SIZES_STEP * RATE))
        .collect();
    let supported_degree = vid_sizes.iter().max_by_key(|v| v.0).unwrap().0;

    // payload byte length
    let byte_lens = [10_000, 100_000, 1_000_000];

    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, supported_degree).unwrap();

    // separate bench for each vid_sizes and byte_lens
    for len in byte_lens {
        let mut bytes_random = vec![0u8; len];
        rng.fill_bytes(&mut bytes_random);

        for &(polynomial_degree, num_storage_nodes) in vid_sizes.iter() {
            let advz = Advz::<E, H>::new(polynomial_degree, num_storage_nodes, &srs).unwrap();

            c.bench_function(
                format!(
                    "advz_disperse_{}_{}_{}",
                    pairing_name, len, num_storage_nodes
                )
                .as_str(),
                |b| b.iter(|| advz.dispersal_data(&bytes_random).unwrap()),
            );
        }
    }
}

fn advz_main(c: &mut Criterion) {
    advz::<Bls12_381, Sha256>(c, "Bls381");
    advz::<Bn254, Sha256>(c, "Bn254");
}

criterion_group!(benches, advz_main);
criterion_main!(benches);
