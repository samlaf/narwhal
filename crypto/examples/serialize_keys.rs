use rand::SeedableRng;
use threshold_crypto::{serde_impl::SerdeSecret, DecryptionShare, SecretKeySet, SecretKeyShare};

fn main() {
    // let mut rng = rand::thread_rng();
    let mut rng = rand::prelude::StdRng::seed_from_u64(0);
    let sk_set = SecretKeySet::random(1, &mut rng);
    let sk_key = SerdeSecret(sk_set.secret_key_share(0));
    let sk_key_serialized = serde_json::to_string(&sk_key).unwrap();
    println!("{:#?}", sk_key_serialized);
    let sk_key_deserialized: SerdeSecret<SecretKeyShare> =
        serde_json::from_str(&sk_key_serialized).unwrap();
    let pk_key_share = sk_key_deserialized.public_key_share();
    println!("{:?}", pk_key_share);
}
