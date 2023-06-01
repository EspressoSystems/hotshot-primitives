#![deny(warnings)]
use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_serialize::Write;
use ark_std::rand::RngCore;
use criterion::{criterion_group, criterion_main, Criterion};
use digest::{Digest, DynDigest, OutputSizeUser};
use generic_array::ArrayLength;
use hotshot_primitives::vid::{advz::Advz, VidScheme};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use sha2::Sha256;

fn advz<E, H>(c: &mut Criterion)
where
    E: Pairing,
    // TODO(Gus) clean up nasty trait bounds upstream
    H: Digest + DynDigest + Default + Clone + Write,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    // (payload_chunk_size, num_storage_nodes)
    let vid_sizes = [(20, 50), (40, 100), (60, 150), (80, 200), (100, 250)];

    // payload byte length
    let byte_lens = [1000];

    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<E>::gen_srs_for_testing(
        &mut rng,
        vid_sizes.iter().max_by_key(|v| v.0).unwrap().0,
    )
    .unwrap();

    // separate bench for each vid_sizes and byte_lens
    for (payload_chunk_size, num_storage_nodes) in vid_sizes {
        let advz = Advz::<E, H>::new(payload_chunk_size, num_storage_nodes, &srs).unwrap();

        for len in byte_lens {
            let mut bytes_random = vec![0u8; len];
            rng.fill_bytes(&mut bytes_random);

            println!("advz_disperse_{}_{}", payload_chunk_size, num_storage_nodes);

            c.bench_function(
                format!("advz_disperse_{}_{}", payload_chunk_size, num_storage_nodes).as_str(),
                |b| b.iter(|| advz.dispersal_data(&bytes_random).unwrap()),
            );
        }
    }
}

fn advz_main(c: &mut Criterion) {
    advz::<Bls12_381, Sha256>(c);
}

criterion_group!(benches, advz_main);
criterion_main!(benches);
