#[macro_use]
extern crate criterion;
use ark_bls12_381::Fr as Fr381;
use ark_bn254::Fr as Fr254;
use ark_std::rand::rngs::StdRng;
use criterion::Criterion;
use hotshot_primitives::vdf::{
    minroot::{MinRoot, MinRootElement},
    VDF,
};

fn minroot_bench(c: &mut Criterion) {
    let mut benchmark_group = c.benchmark_group("MinRoot");
    benchmark_group.sample_size(10);
    let pp = MinRoot::<Fr254>::setup::<StdRng>(1u64 << 16, None).unwrap();
    let input = MinRootElement::<Fr254>::default();
    benchmark_group.bench_function("MinRoot_BN254_2^16", |b| {
        b.iter(|| MinRoot::<Fr254>::eval(&pp, &input).unwrap())
    });

    let input = MinRootElement::<Fr381>::default();
    benchmark_group.bench_function("MinRoot_BLS381_2^16", |b| {
        b.iter(|| MinRoot::<Fr381>::eval(&pp, &input).unwrap())
    });
}

fn bench(c: &mut Criterion) {
    minroot_bench(c);
}

criterion_group!(benches, bench);

criterion_main!(benches);
