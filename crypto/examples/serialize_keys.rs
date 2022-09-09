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
    let mut tx = BytesMut::with_capacity(10);
    tx.resize(3, 0u8);
    let bytes = tx.split().freeze();
    let ciphertext = pk.encrypt(bytes);
    let serialized_ciphertext = bincode::serialize(&ciphertext).unwrap();
    let bytes = Bytes::from(serialized_ciphertext);
    let ciphertext: Ciphertext = bincode::deserialize(&bytes).unwrap();
    println!("{:?}", ciphertext);

    // let messages = ["ok", "no", "yes"];
    // let ciphertexts = messages.map(|msg| pk.encrypt(msg));
    // let serialized_ciphertexts =
    //     ciphertexts.map(|ct| Bytes::from(bincode::serialize(&ct).unwrap()));
    // let serialized_ciphertexts = serialized_ciphertexts.to_vec();
    // let deserialized_ciphertexts: Vec<Ciphertext> = serialized_ciphertexts
    //     .par_iter()
    //     .map(|serialized_ct| bincode::deserialize(serialized_ct).unwrap())
    //     .collect();
    // println!("{:?}", deserialized_ciphertexts);
}
