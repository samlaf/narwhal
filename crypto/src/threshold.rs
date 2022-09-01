extern crate rand;
extern crate threshold_crypto;

use threshold_crypto::{
    Ciphertext, DecryptionShare, PublicKey, PublicKeySet, PublicKeyShare, SecretKey, SecretKeySet,
    SecretKeyShare,
};

#[derive(Clone, Debug)]
struct Member {
    sk_share: SecretKeyShare,
    pk_share: PublicKeyShare,
}
impl Member {
    fn new(sk_share: SecretKeyShare, pk_share: PublicKeyShare) -> Self {
        return Member { sk_share, pk_share };
    }
}
struct Committee {
    members: Vec<Member>,
}
impl Committee {
    fn new(threshold: usize, n_members: usize) -> Self {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(1, &mut rng);
        let pk_set = sk_set.public_keys();
        let members = (0..n_members)
            .map(|i| {
                let sk_share = sk_set.secret_key_share(i);
                let pk_share = pk_set.public_key_share(i);
                Member::new(sk_share, pk_share)
            })
            .collect();
        Committee { members }
    }
}

#[test]
fn basic_threshold_decription_usage() {
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

#[test]
fn basic_secret_key_usage() {
    let sk0 = SecretKey::random();
    let sk1 = SecretKey::random();

    let pk0 = sk0.public_key();

    let msg0 = b"Real news";
    let msg1 = b"Fake news";

    assert!(pk0.verify(&sk0.sign(msg0), msg0));
    assert!(!pk0.verify(&sk1.sign(msg0), msg0)); // Wrong key.
    assert!(!pk0.verify(&sk0.sign(msg1), msg0)); // Wrong message.
}
