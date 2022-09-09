use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use threshold_crypto::{Ciphertext, DecryptionShare, SecretKeySet};

fn main() {
    // THRESHOLD
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::random(1, &mut rng);
    // for encrypting
    let pk = sk_set.public_keys().public_key();
    // for decrypting
    let sk_share = sk_set.secret_key_share(0);

    let messages: Vec<_> = (0..100).map(|i| i.to_string()).collect();

    // SEQUENTIAL
    let time0 = std::time::Instant::now();
    let ciphertexts: Vec<_> = messages.iter().map(|m| pk.encrypt(m)).collect();
    let time1 = std::time::Instant::now();
    let _dec_shares: Vec<_> = ciphertexts
        .iter()
        .map(|ct| sk_share.decrypt_share(ct))
        .collect();
    let time2 = std::time::Instant::now();
    println!("Benchmark for encrypt/decrypt 100 msgs");
    println!("sequential threshold encryption time: {:?}", time1 - time0);
    println!("sequential threshold decryption time: {:?}", time2 - time1);

    // PARALLEL
    let time0 = std::time::Instant::now();
    let ciphertexts: Vec<_> = messages.par_iter().map(|m| pk.encrypt(m)).collect();
    let time1 = std::time::Instant::now();
    let _dec_shares: Vec<_> = ciphertexts
        .par_iter()
        .map(|ct| sk_share.decrypt_share(ct))
        .collect();
    let time2 = std::time::Instant::now();
    println!("parallel threshold encryption time: {:?}", time1 - time0);
    println!("parallel threshold decryption time: {:?}", time2 - time1);
}
