// #![deny(warnings)]
use ark_bls12_381::Bls12_381;
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_serialize::Write;
use ark_std::rand::RngCore;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use digest::{Digest, DynDigest, OutputSizeUser};
use generic_array::ArrayLength;
use hotshot_primitives::vid::{advz::Advz, VidScheme};
use jf_primitives::pcs::{prelude::UnivariateKzgPCS, PolynomialCommitmentScheme};
use sha2::Sha256;

const KB: usize = 1 << 10;

fn advz<E, H>(c: &mut Criterion, pairing_name: &str)
where
    E: Pairing,
    // TODO(Gus) clean up nasty trait bounds upstream
    H: Digest + DynDigest + Default + Clone + Write,
    <<H as OutputSizeUser>::OutputSize as ArrayLength<u8>>::ArrayType: Copy,
{
    // play with these items
    const RATE: usize = 4; // ratio of num_storage_nodes : polynomial_degree
    let poly_degrees = [60, 80, 100, 120, 140];
    let payload_byte_lens = [10 * KB, 100 * KB, 1000 * KB];

    // more items as af unction of the above
    let supported_degree = *poly_degrees.iter().max().unwrap();
    let mut rng = jf_utils::test_rng();
    let srs = UnivariateKzgPCS::<E>::gen_srs_for_testing(&mut rng, supported_degree).unwrap();

    for len in payload_byte_lens {
        let mut bytes_random = vec![0u8; len];
        rng.fill_bytes(&mut bytes_random);

        let mut grp = c.benchmark_group(format!("advz_disperse_{}_{}KB", pairing_name, len >> 10));
        grp.throughput(Throughput::Bytes(len as u64)); // TODO does this make sense?

        for &poly_degree in poly_degrees.iter() {
            let num_storage_nodes = poly_degree * RATE;
            let advz = Advz::<E, H>::new(poly_degree, num_storage_nodes, &srs).unwrap();
            grp.bench_with_input(
                BenchmarkId::from_parameter(num_storage_nodes),
                &num_storage_nodes,
                |b, _| {
                    b.iter(|| advz.dispersal_data(&bytes_random).unwrap());
                },
            );
        }
        grp.finish();
    }
}

fn advz_main(c: &mut Criterion) {
    advz::<Bls12_381, Sha256>(c, "Bls381");
    advz::<Bn254, Sha256>(c, "Bn254");
}

criterion_group!(benches, advz_main);
criterion_main!(benches);
