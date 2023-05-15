use hotshot_primitives::vid::VidScheme;

use ark_std::{
    println,
    rand::{seq::SliceRandom, CryptoRng, RngCore},
    vec,
};

pub fn round_trip<V, R>(vid_factory: impl Fn(usize, usize) -> V, rng: &mut R)
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