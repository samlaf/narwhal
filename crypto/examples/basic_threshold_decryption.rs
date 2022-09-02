use threshold_crypto::{SecretKeySet, DecryptionShare};

fn main() {
    let mut rng = rand::thread_rng();
    let sk_set = SecretKeySet::random(1, &mut rng);
    let pk_set = sk_set.public_keys();
    let pk = pk_set.public_key();
    let msg = "hello";
    println!("msg: {}", msg);
    let ciphertext = pk.encrypt(msg);
    let decryption_shares: Vec<DecryptionShare> = (0..3)
        .map(|i| {
            let sk_share = sk_set.secret_key_share(i);
            sk_share
                .decrypt_share(&ciphertext)
                .expect("Failed to verify decryption share")
        })
        .collect();
    let ided_shares: Vec<(usize, &DecryptionShare)> = (0..3)
        .map(|i| {
            return (i, &decryption_shares[i]);
        })
        .collect();
    let decrypted_bytes = pk_set.decrypt(ided_shares, &ciphertext).unwrap();
    let decrypted_msg = String::from_utf8(decrypted_bytes).unwrap();
    println!("decrypted msg: {}", decrypted_msg);
}
