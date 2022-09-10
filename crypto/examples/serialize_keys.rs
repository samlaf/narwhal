use std::convert::TryFrom;

use bytes::{Bytes, BytesMut};
use rand::SeedableRng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use threshold_crypto::{
    serde_impl::SerdeSecret, Ciphertext, DecryptionShare, SecretKeySet, SecretKeyShare,
};

fn main() {
    // let mut rng = rand::thread_rng();
    let mut rng = rand::prelude::StdRng::seed_from_u64(0);
    let sk_set = SecretKeySet::random(1, &mut rng);

    let pk = sk_set.public_keys().public_key();

    let ciphertext = pk.encrypt(1u64.to_le_bytes());
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    println!("{}", serialized_ciphertext.len());

    let ciphertext = pk.encrypt(b"00001111");
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    println!("{}", serialized_ciphertext.len());

    let ciphertext = pk.encrypt("oklalalalalalalalalalalalala");
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    println!("{}", serialized_ciphertext.len());
}
